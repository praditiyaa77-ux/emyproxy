package com.emy.proxy

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress

/** Mengubah link share (vless/vmess/trojan/ss) menjadi config Xray lengkap dengan inbound TUN. */
object XrayConfig {
    const val SOCKS_PORT = 10808

    fun fromLink(input: String): String {
        val link = input.lines().map { it.trim() }.firstOrNull { it.isNotEmpty() }
            ?: throw IllegalArgumentException("Link kosong")
        val outbound = when {
            link.startsWith("vless://") -> vless(link)
            link.startsWith("vmess://") -> vmess(link)
            link.startsWith("trojan://") -> trojan(link)
            link.startsWith("ss://") -> shadowsocks(link)
            else -> throw IllegalArgumentException("Link tidak dikenali. Pakai vless://, vmess://, trojan:// atau ss://")
        }
        outbound.put("tag", "proxy")

        val tun = JSONObject()
            .put("tag", "tun-in")
            .put("protocol", "tun")
            .put("settings", JSONObject().put("name", "xray0").put("MTU", 1500))
            .put(
                "sniffing",
                JSONObject().put("enabled", true)
                    .put("destOverride", JSONArray(listOf("http", "tls", "quic")))
            )
        val socks = JSONObject()
            .put("tag", "socks-in")
            .put("listen", "127.0.0.1")
            .put("port", SOCKS_PORT)
            .put("protocol", "socks")
            .put("settings", JSONObject().put("auth", "noauth").put("udp", true))

        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(tun).put(socks))
            .put(
                "outbounds", JSONArray()
                    .put(outbound)
                    .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
                    .put(JSONObject().put("tag", "block").put("protocol", "blackhole"))
            )
            .put("routing", JSONObject().put("domainStrategy", "AsIs"))
            .toString()
    }

    // Resolve domain server di sini (sebelum VPN aktif) supaya Xray tidak perlu DNS untuk server-nya.
    private fun resolve(host: String): String {
        val all = InetAddress.getAllByName(host)
        return (all.firstOrNull { it is Inet4Address } ?: all.first()).hostAddress ?: host
    }

    private fun b64(s: String): ByteArray {
        var t = s.trim().replace('-', '+').replace('_', '/')
        while (t.length % 4 != 0) t += "="
        return Base64.decode(t, Base64.DEFAULT)
    }

    private fun vless(link: String): JSONObject {
        val u = Uri.parse(link)
        val host = (u.host ?: throw IllegalArgumentException("Host kosong")).trim('[', ']')
        val port = if (u.port > 0) u.port else 443
        val id = u.userInfo ?: throw IllegalArgumentException("UUID kosong")
        val q = { k: String -> u.getQueryParameter(k) }
        val user = JSONObject().put("id", id).put("encryption", q("encryption") ?: "none")
        q("flow")?.takeIf { it.isNotEmpty() }?.let { user.put("flow", it) }
        val vnext = JSONObject().put("address", resolve(host)).put("port", port)
            .put("users", JSONArray().put(user))
        return JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
            .put("streamSettings", stream(q("type") ?: "tcp", q("security") ?: "none", host, q))
    }

    private fun vmess(link: String): JSONObject {
        val j = JSONObject(String(b64(link.removePrefix("vmess://"))))
        val host = j.optString("add").trim('[', ']')
        if (host.isEmpty()) throw IllegalArgumentException("Host kosong")
        val port = j.optString("port").toIntOrNull() ?: 443
        val user = JSONObject().put("id", j.getString("id"))
            .put("alterId", j.optString("aid", "0").toIntOrNull() ?: 0)
            .put("security", j.optString("scy").ifEmpty { "auto" })
        val vnext = JSONObject().put("address", resolve(host)).put("port", port)
            .put("users", JSONArray().put(user))
        val m = mapOf(
            "sni" to j.optString("sni"),
            "host" to j.optString("host"),
            "path" to j.optString("path"),
            "alpn" to j.optString("alpn"),
            "fp" to j.optString("fp"),
            "serviceName" to j.optString("path")
        )
        val sec = if (j.optString("tls") == "tls") "tls" else "none"
        return JSONObject().put("protocol", "vmess")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
            .put("streamSettings", stream(j.optString("net", "tcp"), sec, host) { m[it] })
    }

    private fun trojan(link: String): JSONObject {
        val u = Uri.parse(link)
        val host = (u.host ?: throw IllegalArgumentException("Host kosong")).trim('[', ']')
        val port = if (u.port > 0) u.port else 443
        val q = { k: String -> u.getQueryParameter(k) }
        val server = JSONObject().put("address", resolve(host)).put("port", port)
            .put("password", Uri.decode(u.userInfo ?: ""))
        return JSONObject().put("protocol", "trojan")
            .put("settings", JSONObject().put("servers", JSONArray().put(server)))
            .put("streamSettings", stream(q("type") ?: "tcp", q("security") ?: "tls", host, q))
    }

    private fun shadowsocks(link: String): JSONObject {
        val body = link.removePrefix("ss://").substringBefore("#").substringBefore("?")
        val userInfo: String
        val hostPort: String
        if (body.contains("@")) {
            val raw = body.substringBeforeLast("@")
            userInfo = decodeSsUser(raw)
            hostPort = body.substringAfterLast("@")
        } else {
            val dec = String(b64(body))
            userInfo = dec.substringBeforeLast("@")
            hostPort = dec.substringAfterLast("@")
        }
        val method = userInfo.substringBefore(":")
        val password = userInfo.substringAfter(":")
        val host = hostPort.substringBeforeLast(":").trim('[', ']')
        val port = hostPort.substringAfterLast(":").toIntOrNull() ?: throw IllegalArgumentException("Port salah")
        val server = JSONObject().put("address", resolve(host)).put("port", port)
            .put("method", method).put("password", password)
        return JSONObject().put("protocol", "shadowsocks")
            .put("settings", JSONObject().put("servers", JSONArray().put(server)))
    }

    private fun decodeSsUser(raw: String): String {
        val plain = Uri.decode(raw)
        if (plain.contains(":")) return plain
        return String(b64(raw))
    }

    private fun stream(net: String, sec: String, host: String, q: (String) -> String?): JSONObject {
        val network = when (net) {
            "ws", "grpc", "httpupgrade", "xhttp" -> net
            "splithttp" -> "xhttp"
            else -> "tcp"
        }
        val s = JSONObject().put("network", network)
        val hostHdr = q("host")?.takeIf { it.isNotEmpty() } ?: host
        val path = q("path")?.takeIf { it.isNotEmpty() } ?: "/"
        when (network) {
            "ws" -> s.put(
                "wsSettings",
                JSONObject().put("path", path).put("headers", JSONObject().put("Host", hostHdr))
            )
            "grpc" -> s.put("grpcSettings", JSONObject().put("serviceName", q("serviceName") ?: ""))
            "httpupgrade" -> s.put(
                "httpupgradeSettings", JSONObject().put("path", path).put("host", hostHdr)
            )
            "xhttp" -> s.put(
                "xhttpSettings",
                JSONObject().put("path", path).put("host", hostHdr).put("mode", q("mode") ?: "auto")
            )
        }
        val sni = q("sni")?.takeIf { it.isNotEmpty() } ?: hostHdr
        val fp = q("fp")?.takeIf { it.isNotEmpty() } ?: "chrome"
        when (sec) {
            "tls" -> {
                s.put("security", "tls")
                val t = JSONObject().put("serverName", sni).put("fingerprint", fp)
                q("alpn")?.takeIf { it.isNotEmpty() }?.let { t.put("alpn", JSONArray(it.split(","))) }
                s.put("tlsSettings", t)
            }
            "reality" -> {
                s.put("security", "reality")
                s.put(
                    "realitySettings",
                    JSONObject().put("serverName", sni).put("fingerprint", fp)
                        .put("publicKey", q("pbk") ?: "").put("shortId", q("sid") ?: "")
                        .put("spiderX", q("spx") ?: "")
                )
            }
            else -> s.put("security", "none")
        }
        return s
    }
}
