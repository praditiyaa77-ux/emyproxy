package com.emy.proxy

import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray

class EmyVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.emy.proxy.START"
        const val ACTION_STOP = "com.emy.proxy.STOP"
        const val EXTRA_CONFIG = "config"

        @Volatile
        var running = false
        var listener: ((Boolean, String?) -> Unit)? = null
    }

    private var pfd: ParcelFileDescriptor? = null
    private var controller: CoreController? = null
    private val main = Handler(Looper.getMainLooper())

    private val callback = object : CoreCallbackHandler {
        override fun startup(): Long = 0
        override fun shutdown(): Long = 0
        override fun onEmitStatus(p0: Long, p1: String?): Long = 0
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCore(null)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val cfg = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                Thread { startCore(cfg) }.start()
            }
        }
        return START_NOT_STICKY
    }

    private fun startCore(config: String) {
        try {
            stopCore(null)
            val p = Builder()
                .setSession("Emy Proxy")
                .setMtu(1500)
                .addAddress("172.19.0.1", 30)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addDisallowedApplication(packageName) // koneksi Xray sendiri tidak masuk ke tunnel (anti loop)
                .establish() ?: throw IllegalStateException("VPN tidak bisa dibuat")
            pfd = p
            Libv2ray.initCoreEnv(filesDir.absolutePath, "")
            val c = Libv2ray.newCoreController(callback)
            c.startLoop(config, p.fd)
            controller = c
            running = true
            post(true, null)
        } catch (e: Throwable) {
            stopCore(e.message ?: e.toString())
        }
    }

    @Synchronized
    private fun stopCore(error: String?) {
        try { controller?.stopLoop() } catch (_: Throwable) {}
        controller = null
        try { pfd?.close() } catch (_: Throwable) {}
        pfd = null
        val was = running
        running = false
        if (was || error != null) post(false, error)
    }

    private fun post(up: Boolean, err: String?) {
        main.post { listener?.invoke(up, err) }
    }

    override fun onRevoke() {
        stopCore(null)
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCore(null)
        super.onDestroy()
    }
}
