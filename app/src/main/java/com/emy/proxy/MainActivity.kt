package com.emy.proxy

import android.content.Context
import android.net.VpnService
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var backend: GoBackend
    private lateinit var etConfig: EditText
    private lateinit var tvStatus: TextView
    private lateinit var tvIp: TextView
    private lateinit var btnConnect: MaterialButton
    private var connected = false

    private val tunnel = object : Tunnel {
        override fun getName() = "emy"
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread { showState(newState == Tunnel.State.UP) }
        }
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) setTunnel(true)
            else toast("Izin VPN ditolak")
        }

    private val pickFile =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let {
                contentResolver.openInputStream(it)?.bufferedReader()?.use { r ->
                    etConfig.setText(r.readText())
                }
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        backend = GoBackend(applicationContext)

        etConfig = findViewById(R.id.etConfig)
        tvStatus = findViewById(R.id.tvStatus)
        tvIp = findViewById(R.id.tvIp)
        btnConnect = findViewById(R.id.btnConnect)

        val prefs = getSharedPreferences("emy", Context.MODE_PRIVATE)
        etConfig.setText(prefs.getString("cfg", ""))

        findViewById<MaterialButton>(R.id.btnImport).setOnClickListener {
            pickFile.launch(arrayOf("*/*"))
        }
        btnConnect.setOnClickListener {
            if (connected) {
                setTunnel(false)
            } else {
                val text = etConfig.text.toString().trim()
                if (text.isEmpty()) {
                    toast("Config masih kosong")
                    return@setOnClickListener
                }
                prefs.edit().putString("cfg", text).apply()
                val intent = VpnService.prepare(this)
                if (intent != null) vpnPermission.launch(intent) else setTunnel(true)
            }
        }

        try {
            showState(backend.getState(tunnel) == Tunnel.State.UP)
        } catch (_: Exception) {
        }
        refreshIp(0)
    }

    private fun setTunnel(up: Boolean) {
        val text = etConfig.text.toString()
        tvStatus.text = if (up) "Menghubungkan..." else "Memutuskan..."
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val cfg = if (up) Config.parse(ByteArrayInputStream(text.toByteArray())) else null
                    backend.setState(
                        tunnel,
                        if (up) Tunnel.State.UP else Tunnel.State.DOWN,
                        cfg
                    )
                }
                showState(up)
                refreshIp(1500)
            } catch (e: Exception) {
                showState(false)
                toast("Gagal: ${e.message}")
            }
        }
    }

    private fun showState(up: Boolean) {
        connected = up
        tvStatus.text = if (up) "Terhubung" else "Terputus"
        tvStatus.setTextColor(if (up) 0xFF4ADE80.toInt() else 0xFFFF6B6B.toInt())
        btnConnect.text = if (up) "DISCONNECT" else "CONNECT"
    }

    private fun refreshIp(waitMs: Long) {
        lifecycleScope.launch {
            delay(waitMs)
            val ip = withContext(Dispatchers.IO) {
                try {
                    val c = URL("https://api.ipify.org").openConnection() as HttpURLConnection
                    c.connectTimeout = 6000
                    c.readTimeout = 6000
                    c.inputStream.bufferedReader().use { it.readText() }
                } catch (_: Exception) {
                    "-"
                }
            }
            tvIp.text = "IP: $ip"
        }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
}
