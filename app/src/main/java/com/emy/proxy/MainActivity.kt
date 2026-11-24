package com.emy.proxy

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var backend: GoBackend
    private lateinit var etConfig: EditText
    private lateinit var tvStatus: TextView
    private lateinit var tvIp: TextView
    private lateinit var btnConnect: MaterialButton
    private lateinit var toggle: MaterialButtonToggleGroup
    private val prefs by lazy { getSharedPreferences("emy", Context.MODE_PRIVATE) }

    private var mode = 0          // 0 = WireGuard, 1 = V2Ray/Xray (yang dipilih di UI)
    private var activeMode = 0    // mode yang sedang jalan
    private var connected = false
    private var afterPermission: (() -> Unit)? = null

    private val tunnel = object : Tunnel {
        override fun getName() = "emy"
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread { if (activeMode == 0) showState(newState == Tunnel.State.UP, 0) }
        }
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) afterPermission?.invoke() else toast("Izin VPN ditolak")
            afterPermission = null
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
        toggle = findViewById(R.id.toggleMode)

        mode = prefs.getInt("mode", 0)
        etConfig.setText(prefs.getString(key(mode), ""))
        etConfig.hint = hintFor(mode)
        toggle.check(if (mode == 1) R.id.btnModeXray else R.id.btnModeWg)
        toggle.addOnButtonCheckedListener { _, id, checked ->
            if (checked) switchMode(if (id == R.id.btnModeXray) 1 else 0)
        }

        findViewById<MaterialButton>(R.id.btnImport).setOnClickListener {
            pickFile.launch(arrayOf("*/*"))
        }
        findViewById<MaterialButton>(R.id.btnPaste).setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val t = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()
            if (t.isNullOrBlank()) toast("Clipboard kosong") else etConfig.setText(t)
        }
        btnConnect.setOnClickListener { if (connected) disconnect() else connect() }

        EmyVpnService.listener = { up, err ->
            if (activeMode == 1) {
                showState(up, 1)
                if (err != null) toast("Gagal: $err")
                if (up) refreshIp(1500)
            }
        }

        if (EmyVpnService.running) {
            showState(true, 1)
        } else {
            try {
                showState(backend.getState(tunnel) == Tunnel.State.UP, 0)
            } catch (_: Exception) {
            }
        }
        refreshIp(0)
    }

    override fun onDestroy() {
        EmyVpnService.listener = null
        super.onDestroy()
    }

    private fun key(m: Int) = if (m == 1) "cfg_xray" else "cfg_wg"
    private fun hintFor(m: Int) =
        if (m == 1) "Paste link vless:// vmess:// trojan:// atau ss://"
        else "Paste config WireGuard (.conf) di sini"

    private fun saveCurrent() {
        prefs.edit().putString(key(mode), etConfig.text.toString().trim()).apply()
    }

    private fun switchMode(m: Int) {
        if (m == mode) return
        saveCurrent()
        mode = m
        prefs.edit().putInt("mode", m).apply()
        etConfig.setText(prefs.getString(key(m), ""))
        etConfig.hint = hintFor(m)
    }

    private fun connect() {
        val text = etConfig.text.toString().trim()
        if (text.isEmpty()) {
            toast("Config masih kosong")
            return
        }
        saveCurrent()
        if (mode == 0) {
            runWithPermission { setWireGuard(true) }
        } else {
            tvStatus.text = "Menghubungkan..."
            lifecycleScope.launch {
                val cfg = try {
                    withContext(Dispatchers.IO) { XrayConfig.fromLink(text) }
                } catch (e: Exception) {
                    showState(false, 1)
                    toast("Link tidak valid: ${e.message}")
                    return@launch
                }
                runWithPermission {
                    activeMode = 1
                    startService(
                        Intent(this@MainActivity, EmyVpnService::class.java)
                            .setAction(EmyVpnService.ACTION_START)
                            .putExtra(EmyVpnService.EXTRA_CONFIG, cfg)
                    )
                }
            }
        }
    }

    private fun runWithPermission(action: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            afterPermission = action
            vpnPermission.launch(intent)
        } else {
            action()
        }
    }

    private fun disconnect() {
        if (activeMode == 1) {
            startService(
                Intent(this, EmyVpnService::class.java).setAction(EmyVpnService.ACTION_STOP)
            )
            showState(false, 1)
            refreshIp(1000)
        } else {
            setWireGuard(false)
        }
    }

    private fun setWireGuard(up: Boolean) {
        val text = etConfig.text.toString()
        if (up) activeMode = 0
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
                showState(up, 0)
                refreshIp(1500)
            } catch (e: Exception) {
                showState(false, 0)
                toast("Gagal: ${e.message}")
            }
        }
    }

    private fun showState(up: Boolean, m: Int) {
        connected = up
        if (up) activeMode = m
        tvStatus.text = if (up) "Terhubung" else "Terputus"
        tvStatus.setTextColor(if (up) 0xFF4ADE80.toInt() else 0xFFFF6B6B.toInt())
        btnConnect.text = if (up) "DISCONNECT" else "CONNECT"
    }

    private fun refreshIp(waitMs: Long) {
        lifecycleScope.launch {
            delay(waitMs)
            val viaSocks = connected && activeMode == 1
            val ip = withContext(Dispatchers.IO) {
                try {
                    val url = URL("https://api.ipify.org")
                    val c = (if (viaSocks)
                        url.openConnection(
                            Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", XrayConfig.SOCKS_PORT))
                        ) else url.openConnection()) as HttpURLConnection
                    c.connectTimeout = 8000
                    c.readTimeout = 8000
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
