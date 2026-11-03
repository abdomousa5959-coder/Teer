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
import java.util.Date
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var web: WebView

    @Suppress("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = false
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
                val payload = try { scanTarget(raw) } catch (e: Exception) {
                    JSONObject().put("ok", false).put("error", e.message ?: "تعذر تنفيذ الفحص")
                }
                runOnUiThread {
                    web.evaluateJavascript("window.receiveScan(${JSONObject.quote(payload.toString())})", null)
                }
            }
        }
    }

    private fun scanTarget(raw: String): JSONObject {
        val input = URL(raw.trim())
        require(input.protocol.equals("https", true)) { "يسمح بفحص HTTPS فقط." }
        require(input.userInfo == null) { "لا تضع بيانات دخول داخل الرابط." }
        require(input.port == -1 || input.port == 443) { "الفحص متاح على المنفذ 443 فقط." }
        require(input.host.isNotBlank()) { "اسم النطاق غير صالح." }
        val host = IDN.toASCII(input.host.trimEnd('.')).lowercase()
        require(host.length <= 253 && host.contains(".") && !host.startsWith("-")) { "أدخل اسم نطاق عام صالح." }
        require(!host.equals("localhost", true) && !host.endsWith(".localhost", true)) { "النطاق المحلي غير مسموح." }

        val addresses = InetAddress.getAllByName(host)
        require(addresses.isNotEmpty() && addresses.none { isNonPublic(it) }) {
            "تم رفض النطاق لأنه يحل إلى عنوان محلي أو خاص."
        }

        val target = URL("https", host, 443, input.file.ifBlank { "/" })
        val conn = (target.openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10000
            readTimeout = 12000
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("User-Agent", "NexusXUltra/3.0 (passive-security-audit)")
            setRequestProperty("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7")
            setRequestProperty("Connection", "close")
        }

        try {
            conn.connect()
            val status = conn.responseCode
            val contentType = conn.contentType ?: ""
            val isRedirect = status in 300..399
            val isHtml = contentType.contains("text/html", true) || contentType.contains("application/xhtml", true)
            val findings = JSONArray()
            var deductions = 0

            fun add(severity: String, title: String, detail: String, points: Int = 0) {
                findings.put(finding(severity, title, detail, points))
                deductions += points
            }

            val headers = JSONObject()
            val headerNames = listOf(
                "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
                "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
                "Cross-Origin-Embedder-Policy", "X-Permitted-Cross-Domain-Policies"
            )
            headerNames.forEach { name -> headers.put(name, conn.getHeaderField(name) ?: JSONObject.NULL) }

            val hsts = conn.getHeaderField("Strict-Transport-Security")
            if (hsts.isNullOrBlank()) {
                add("MEDIUM", "HSTS غير موجود", "لم يتم رصد Strict-Transport-Security في هذه الاستجابة.", 12)
            } else {
                val maxAge = Regex("max-age\\s*=\\s*(\\d+)", RegexOption.IGNORE_CASE).find(hsts)?.groupValues?.get(1)?.toLongOrNull()
                if (maxAge == null || maxAge < 31536000L) add("LOW", "إعداد HSTS يحتاج مراجعة", "يفضل max-age لا يقل عن سنة مع مراجعة includeSubDomains.", 4)
            }

            if (isHtml && !isRedirect) {
                val csp = conn.getHeaderField("Content-Security-Policy")
                if (csp.isNullOrBlank()) add("MEDIUM", "CSP غير موجود", "صفحة HTML لا ترسل Content-Security-Policy.", 10)
                else {
                    if (csp.contains("'unsafe-inline'", true)) add("MEDIUM", "CSP يسمح unsafe-inline", "وجود unsafe-inline يقلل حماية CSP من بعض هجمات XSS؛ راجع الحاجة إليه.", 6)
                    if (csp.contains("'unsafe-eval'", true)) add("MEDIUM", "CSP يسمح unsafe-eval", "وجود unsafe-eval يسمح بتقييم نصوص JavaScript ديناميكياً.", 6)
                    if (csp.contains("default-src *", true)) add("MEDIUM", "CSP واسع جداً", "default-src * سياسة واسعة وقد تسمح بمصادر غير موثوقة.", 6)
                }
                if (conn.getHeaderField("X-Content-Type-Options")?.equals("nosniff", true) != true)
                    add("LOW", "X-Content-Type-Options غير مضبوط", "يفضل إرسال القيمة nosniff.", 4)
                if (conn.getHeaderField("X-Frame-Options").isNullOrBlank() && !csp.orEmpty().contains("frame-ancestors", true))
                    add("LOW", "حماية التأطير غير مرصودة", "لم يتم رصد X-Frame-Options أو CSP frame-ancestors؛ قد يزيد ذلك خطر clickjacking.", 4)
                if (conn.getHeaderField("Referrer-Policy").isNullOrBlank())
                    add("LOW", "Referrer-Policy غير موجود", "سياسة الإحالة غير محددة صراحةً.", 3)
                if (conn.getHeaderField("Permissions-Policy").isNullOrBlank())
                    add("INFO", "Permissions-Policy غير موجود", "لم يتم رصد سياسة لتقييد واجهات المتصفح.", 0)
                if (conn.getHeaderField("Cross-Origin-Opener-Policy").isNullOrBlank())
                    add("INFO", "COOP غير موجود", "لم يتم رصد Cross-Origin-Opener-Policy.", 0)
                if (conn.getHeaderField("Cross-Origin-Resource-Policy").isNullOrBlank())
                    add("INFO", "CORP غير موجود", "لم يتم رصد Cross-Origin-Resource-Policy.", 0)
            }

            val cookies = JSONArray()
            val cookieLines = conn.headerFields.entries
                .filter { it.key?.equals("Set-Cookie", true) == true }
                .flatMap { it.value ?: emptyList() }
            cookieLines.forEachIndexed { index, line ->
                val parts = line.split(";").map { it.trim() }
                val name = parts.firstOrNull()?.substringBefore("=")?.take(80) ?: "cookie-${index + 1}"
                val attrs = parts.drop(1)
                val secure = attrs.any { it.equals("Secure", true) }
                val httpOnly = attrs.any { it.equals("HttpOnly", true) }
                val sameSite = attrs.any { it.startsWith("SameSite=", true) }
                val httpOnlyExpected = !name.startsWith("__Host-", true) && !name.startsWith("__Secure-", true) &&
                    !name.contains("csrf", true) && !name.contains("xsrf", true)
                cookies.put(JSONObject().put("index", index + 1).put("name", name)
                    .put("secure", secure).put("httpOnly", httpOnly).put("sameSite", sameSite))
                if (!secure) add("MEDIUM", "Cookie بدون Secure", "$name قد يُرسل عبر اتصال غير مشفر في سياقات أخرى؛ أضف Secure.", 6)
                if (!httpOnly && httpOnlyExpected) add("LOW", "Cookie بدون HttpOnly", "$name متاح لجافاسكريبت؛ استخدم HttpOnly إذا لم يحتج إليه التطبيق.", 3)
                if (!sameSite) add("LOW", "Cookie بدون SameSite", "$name لا يحدد سياسة SameSite صراحةً؛ راجع احتياج cross-site.", 3)
                val sameSiteValue = attrs.firstOrNull { it.startsWith("SameSite=", true) }?.substringAfter("=")
                if (sameSiteValue.equals("None", true) && !secure)
                    add("HIGH", "SameSite=None بدون Secure", "$name يستخدم SameSite=None دون Secure.", 10)
            }

            val redirect = conn.getHeaderField("Location")
            var redirectInfo = JSONObject.NULL
            if (isRedirect && !redirect.isNullOrBlank()) {
                val resolved = URL(target, redirect)
                val sameHost = resolved.host.equals(host, true)
                redirectInfo = JSONObject().put("location", resolved.toString())
                    .put("sameHost", sameHost).put("https", resolved.protocol.equals("https", true))
                if (!resolved.protocol.equals("https", true))
                    add("HIGH", "تحويل إلى HTTP", "وجهة التحويل تستخدم اتصالاً غير مشفر؛ لا تتبعها تلقائياً.", 12)
                else if (!sameHost)
                    add("INFO", "تحويل إلى نطاق آخر", "التحويل يذهب إلى ${resolved.host}. تحقق من ملكية الوجهة قبل فحصها.", 0)
            } else if (isRedirect) {
                add("INFO", "استجابة تحويل", "HTTP $status بدون Location ظاهر؛ لم يتم اتباع التحويل.", 0)
            }

            val cert = try { conn.serverCertificates.firstOrNull() as? java.security.cert.X509Certificate }
                catch (_: SSLPeerUnverifiedException) { null }
            val now = Date()
            val tls = JSONObject()
                .put("cipherSuite", conn.cipherSuite ?: "Unavailable")
                .put("subject", cert?.subjectX500Principal?.name ?: "Unavailable")
                .put("issuer", cert?.issuerX500Principal?.name ?: "Unavailable")
                .put("notBefore", cert?.notBefore?.toString() ?: "Unavailable")
                .put("notAfter", cert?.notAfter?.toString() ?: "Unavailable")
            if (cert != null) {
                val daysLeft = TimeUnit.MILLISECONDS.toDays(cert.notAfter.time - now.time)
                tls.put("daysUntilExpiry", daysLeft)
                when {
                    now.before(cert.notBefore) -> add("HIGH", "الشهادة لم تصبح صالحة بعد", "تاريخ بداية صلاحية الشهادة في المستقبل.", 15)
                    now.after(cert.notAfter) -> add("HIGH", "شهادة TLS منتهية", "انتهت صلاحية شهادة الخادم.", 20)
                    daysLeft <= 30 -> add("MEDIUM", "شهادة TLS قاربت على الانتهاء", "متبقي $daysLeft يوم تقريباً على انتهاء الشهادة.", 8)
                }
            }
            val cipher = conn.cipherSuite.orEmpty()
            if (Regex("(_NULL_|_EXPORT_|RC4|3DES|DES_CBC|MD5)", RegexOption.IGNORE_CASE).containsMatchIn(cipher))
                add("HIGH", "مجموعة تشفير قديمة أو ضعيفة", "مجموعة التشفير المعلنة تستحق مراجعة فورية: $cipher", 15)

            val server = conn.getHeaderField("Server")
            if (!server.isNullOrBlank() && Regex("/\\d").containsMatchIn(server))
                add("INFO", "كشف إصدار الخادم", "ترويسة Server تكشف معلومات إصدار: $server", 0)

            val dns = JSONArray()
            addresses.forEach { dns.put(it.hostAddress) }
            val score = (100 - deductions.coerceAtMost(100)).coerceAtLeast(0)
            val counts = JSONObject()
            listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").forEach { sev ->
                var count = 0
                for (i in 0 until findings.length()) if (findings.getJSONObject(i).optString("severity") == sev) count++
                counts.put(sev.lowercase(), count)
            }

            return JSONObject()
                .put("ok", true).put("engineVersion", "3.0")
                .put("target", target.toString()).put("timestamp", System.currentTimeMillis())
                .put("status", status).put("contentType", contentType.ifBlank { "Unavailable" })
                .put("serverHeader", server ?: "Not disclosed").put("dns", dns)
                .put("tls", tls).put("headers", headers).put("cookies", cookies)
                .put("redirect", redirectInfo).put("findings", findings)
                .put("severityCounts", counts).put("score", score)
                .put("scoreDisclaimer", "درجة تقديرية لإعدادات تم رصدها فقط؛ ليست احتمال اختراق ولا تثبت خلو الموقع من الثغرات.")
                .put("scopeNote", "فحص سلبي محدود لاستجابة HTTPS واحدة. لا يجري استغلالاً أو brute force أو تخمين مسارات أو اختباراً شاملاً للتطبيق.")
        } finally {
            conn.disconnect()
        }
    }

    private fun finding(severity: String, title: String, detail: String, deduction: Int) =
        JSONObject().put("severity", severity).put("title", title).put("detail", detail).put("deduction", deduction)

    private fun isNonPublic(ip: InetAddress): Boolean {
        val a = ip.address
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress ||
            ip.isSiteLocalAddress || ip.isMulticastAddress) return true
        if (a.size != 4) {
            val first = a[0].toInt() and 0xff
            return (first and 0xfe) == 0xfc
        }
        val x = a[0].toInt() and 0xff
        val y = a[1].toInt() and 0xff
        return x == 0 || x == 10 || x == 127 || x == 169 && y == 254 ||
            x == 172 && y in 16..31 || x == 192 && y == 168 ||
            x >= 224 || x == 100 && y in 64..127
    }
}
