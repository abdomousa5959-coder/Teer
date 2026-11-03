package com.tulipeni.nexusultra

import android.app.Activity
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var web: WebView

    @Suppress("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.settings.javaScriptCanOpenWindowsAutomatically = false
        web.webViewClient = WebViewClient()
        web.addJavascriptInterface(Bridge(), "Nexus")
        setContentView(web)
        web.loadUrl("file:///android_asset/index.html")
    }

    inner class Bridge {
        @JavascriptInterface
        fun scan(raw: String) {
            thread(name = "nexus-scan") {
                val payload = try {
                    scanTarget(raw)
                } catch (e: Exception) {
                    JSONObject()
                        .put("ok", false)
                        .put("error", e.message ?: "تعذر تنفيذ الفحص")
                }
                runOnUiThread {
                    web.evaluateJavascript(
                        "window.receiveScan(${JSONObject.quote(payload.toString())})",
                        null
                    )
                }
            }
        }
    }

    private fun scanTarget(raw: String): JSONObject {
        val url = URL(raw.trim())
        require(url.protocol.equals("https", true)) { "يسمح بفحص HTTPS فقط." }
        require(url.userInfo == null) { "لا تضع بيانات دخول داخل الرابط." }
        require(url.port == -1 || url.port == 443) { "الإصدار الحالي يفحص المنفذ 443 فقط." }
        require(url.host.isNotBlank()) { "اسم النطاق غير صالح." }

        val host = IDN.toASCII(url.host)
        require(host.length <= 253 && host.contains(".")) { "أدخل اسم نطاق عام صالح." }
        require(!host.equals("localhost", true) && !host.endsWith(".localhost", true)) {
            "النطاق المحلي غير مسموح."
        }

        val ips = InetAddress.getAllByName(host)
        require(ips.isNotEmpty() && ips.none { isNonPublic(it) }) {
            "تم رفض النطاق لأنه يحل إلى عنوان محلي أو خاص."
        }

        val conn = (URL("https://$host${url.file}").openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10000
            readTimeout = 12000
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("User-Agent", "TulipeniNexusX-Ultra/2.0")
            setRequestProperty("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
            setRequestProperty("Connection", "close")
        }

        try {
            conn.connect()
            val status = conn.responseCode
            val responseHeaders = conn.headerFields
            val headerMap = JSONObject()
            val findings = JSONArray()
            var risk = 0

            val expected = listOf(
                "Strict-Transport-Security" to "HSTS",
                "Content-Security-Policy" to "CSP",
                "X-Content-Type-Options" to "MIME sniffing protection",
                "X-Frame-Options" to "Clickjacking protection",
                "Referrer-Policy" to "Referrer privacy",
                "Permissions-Policy" to "Browser feature restrictions"
            )

            for ((header, label) in expected) {
                val value = conn.getHeaderField(header)
                headerMap.put(header, value ?: JSONObject.NULL)
                if (value.isNullOrBlank()) {
                    val severity = if (header == "Content-Security-Policy" ||
                        header == "Strict-Transport-Security") "MEDIUM" else "LOW"
                    risk += if (severity == "MEDIUM") 10 else 5
                    findings.put(finding(severity, "Missing $header", "$label header was not observed."))
                }
            }

            val cookies = JSONArray()
            responseHeaders.entries
                .filter { it.key?.equals("Set-Cookie", true) == true }
                .flatMap { it.value ?: emptyList() }
                .forEachIndexed { index, cookie ->
                    val lower = cookie.lowercase()
                    val secure = lower.contains("; secure") || lower.endsWith(";secure")
                    val httpOnly = lower.contains("httponly")
                    val sameSite = lower.contains("samesite=")
                    cookies.put(JSONObject()
                        .put("index", index + 1)
                        .put("secure", secure)
                        .put("httpOnly", httpOnly)
                        .put("sameSite", sameSite)
                        .put("preview", cookie.take(220)))
                    if (!secure || !httpOnly || !sameSite) {
                        risk += 5
                        findings.put(finding(
                            "LOW",
                            "Cookie attribute review",
                            "Cookie ${index + 1}: Secure=$secure, HttpOnly=$httpOnly, SameSite=$sameSite"
                        ))
                    }
                }

            val certs = conn.serverCertificates
            val cert = certs.firstOrNull() as? X509Certificate
            val tls = JSONObject()
                .put("protocol", conn.sslSession?.protocol ?: "TLS session established")
                .put("cipherSuite", conn.cipherSuite ?: "Unavailable")
                .put("subject", cert?.subjectX500Principal?.name ?: "Unavailable")
                .put("issuer", cert?.issuerX500Principal?.name ?: "Unavailable")
                .put("notBefore", cert?.notBefore?.toString() ?: "Unavailable")
                .put("notAfter", cert?.notAfter?.toString() ?: "Unavailable")

            if (status in 300..399) {
                findings.put(finding(
                    "INFO", "Redirect not followed",
                    "Server returned HTTP $status. Redirects are intentionally not followed."
                ))
            }
            if (status >= 500) {
                risk += 10
                findings.put(finding("INFO", "Server error response", "HTTP status: $status"))
            }

            val score = (100 - risk.coerceAtMost(100)).coerceAtLeast(0)
            val dns = JSONArray()
            ips.forEach { dns.put(it.hostAddress) }

            return JSONObject()
                .put("ok", true)
                .put("target", "https://$host${url.file}")
                .put("timestamp", System.currentTimeMillis())
                .put("status", status)
                .put("contentType", conn.contentType ?: "Unavailable")
                .put("serverHeader", conn.getHeaderField("Server") ?: "Not disclosed")
                .put("dns", dns)
                .put("tls", tls)
                .put("headers", headerMap)
                .put("cookies", cookies)
                .put("findings", findings)
                .put("score", score)
                .put("scoreDisclaimer", "مؤشر أولي لوجود إعدادات محددة، وليس حكماً بأن الموقع آمن أو مخترق.")
                .put("scopeNote", "فحص سلبي محدود لعنوان HTTPS واحد؛ لا يجري استغلالاً أو تخمين مسارات.")
        } finally {
            conn.disconnect()
        }
    }

    private fun finding(severity: String, title: String, detail: String) =
        JSONObject().put("severity", severity).put("title", title).put("detail", detail)

    private fun isNonPublic(ip: InetAddress): Boolean {
        val address = ip.address
        val ipv4 = address.size == 4
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress ||
            ip.isSiteLocalAddress || ip.isMulticastAddress) return true
        if (!ipv4) {
            val first = address[0].toInt() and 0xff
            return (first and 0xfe) == 0xfc
        }
        val a = address[0].toInt() and 0xff
        val b = address[1].toInt() and 0xff
        return a == 0 || a == 10 || a == 127 || a == 169 && b == 254 ||
            a == 172 && b in 16..31 || a == 192 && b == 168 ||
            a >= 224 || a == 100 && b in 64..127
    }
}
