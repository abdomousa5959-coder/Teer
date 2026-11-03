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
            setRequestProperty("User-Agent", "NexusXUltra/4.0 (passive-security-audit)")
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

            val headerNames = listOf(
                "Strict-Transport-Security", "Content-Security-Policy", "Content-Type",
                "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
                "Permissions-Policy", "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy",
                "X-Permitted-Cross-Domain-Policies", "Cache-Control"
            )
            val headers = JSONObject()
            headerNames.forEach { name -> headers.put(name, conn.getHeaderField(name) ?: JSONObject.NULL) }

            val hsts = conn.getHeaderField("Strict-Transport-Security")
            if (hsts.isNullOrBlank()) {
                add("MEDIUM", "HSTS غير موجود", "لم يتم رصد Strict-Transport-Security في هذه الاستجابة.", 10)
            } else {
                val maxAge = Regex("max-age\\s*=\\s*(\\d+)", RegexOption.IGNORE_CASE).find(hsts)?.groupValues?.get(1)?.toLongOrNull()
                if (maxAge == null || maxAge < 31536000L) add("LOW", "إعداد HSTS يحتاج مراجعة", "تحقق من max-age لا يقل عن سنة، ومن ملاءمة includeSubDomains وpreload.", 3)
                if (hsts.contains("preload", true) && !hsts.contains("includeSubDomains", true))
                    add("INFO", "HSTS preload يحتاج مراجعة", "وجود preload دون includeSubDomains قد لا يحقق شروط الإدراج المعتادة.", 0)
            }

            val csp = conn.getHeaderField("Content-Security-Policy")
            if (isHtml && !isRedirect) {
                if (csp.isNullOrBlank()) add("MEDIUM", "CSP غير موجود", "صفحة HTML لا ترسل Content-Security-Policy.", 9)
                else {
                    val directives = csp.split(";").map { it.trim() }.filter { it.isNotBlank() }
                        .associate { it.substringBefore(" ").lowercase() to it.substringAfter(" ", "").trim() }
                    if (csp.contains("'unsafe-inline'", true)) add("MEDIUM", "CSP يسمح unsafe-inline", "يسمح بتنفيذ inline scripts/styles بحسب التوجيه المتأثر؛ راجع استخدام nonce أو hash.", 5)
                    if (csp.contains("'unsafe-eval'", true)) add("MEDIUM", "CSP يسمح unsafe-eval", "يسمح بتقييم JavaScript ديناميكياً في التوجيه المتأثر.", 5)
                    if (csp.contains("default-src *", true) || csp.contains("script-src *", true))
                        add("HIGH", "مصادر CSP واسعة جداً", "استخدام wildcard في default-src أو script-src يوسع الثقة في مصادر المحتوى.", 8)
                    if (!directives.containsKey("object-src")) add("LOW", "CSP لا يحدد object-src", "يفضل object-src 'none' لمنع تحميل إضافات قديمة.", 2)
                    if (!directives.containsKey("base-uri")) add("LOW", "CSP لا يحدد base-uri", "يفضل تقييد base-uri لتقليل مخاطر إساءة استخدام عنصر base.", 2)
                    if (!directives.containsKey("frame-ancestors") && conn.getHeaderField("X-Frame-Options").isNullOrBlank())
                        add("LOW", "سياسة منع التأطير غير مرصودة", "لم يتم رصد frame-ancestors أو X-Frame-Options.", 3)
                }
                if (conn.getHeaderField("X-Content-Type-Options")?.equals("nosniff", true) != true)
                    add("LOW", "X-Content-Type-Options غير مضبوط", "يفضل إرسال القيمة nosniff.", 3)
                if (conn.getHeaderField("Referrer-Policy").isNullOrBlank())
                    add("LOW", "Referrer-Policy غير موجود", "سياسة الإحالة غير محددة صراحةً.", 2)
                if (conn.getHeaderField("Permissions-Policy").isNullOrBlank())
                    add("INFO", "Permissions-Policy غير موجود", "راجع تقييد واجهات المتصفح غير المستخدمة.", 0)
                if (conn.getHeaderField("Cross-Origin-Opener-Policy").isNullOrBlank())
                    add("INFO", "COOP غير موجود", "قد يكون مناسباً حسب نموذج العزل والتكاملات الخارجية.", 0)
                if (conn.getHeaderField("Cross-Origin-Resource-Policy").isNullOrBlank())
                    add("INFO", "CORP غير موجود", "قد يكون مناسباً حسب كيفية مشاركة الموارد عبر المواقع.", 0)
                if (conn.getHeaderField("Cross-Origin-Embedder-Policy").isNullOrBlank())
                    add("INFO", "COEP غير موجود", "مطلوب فقط لبعض سيناريوهات cross-origin isolation.", 0)
            }

            // Read a bounded HTML sample only; never download an unbounded response body.
            val pageAnalysis = JSONObject()
            if (isHtml && !isRedirect) {
                val stream = if (status >= 400) conn.errorStream else conn.inputStream
                val body = stream?.use { readBounded(it, 512 * 1024) } ?: ""
                val lower = body.lowercase()
                val insecureRefs = Regex("""(?:src|href)\s*=\s*["']http://[^"']+["']""", RegexOption.IGNORE_CASE).findAll(body).count()
                val scripts = Regex("""<script\b[^>]*>""", RegexOption.IGNORE_CASE).findAll(body).toList()
                val externalScriptsWithoutSri = scripts.count {
                    val tag = it.value
                    Regex("""\bsrc\s*=""", RegexOption.IGNORE_CASE).containsMatchIn(tag) &&
                        !Regex("""\bintegrity\s*=""", RegexOption.IGNORE_CASE).containsMatchIn(tag)
                }
                val passwordForms = Regex("""<form\b[^>]*>.*?</form>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                    .findAll(body).filter { Regex("""type\s*=\s*["']?password""", RegexOption.IGNORE_CASE).containsMatchIn(it.value) }.toList()
                val insecurePasswordForms = passwordForms.count { form ->
                    val action = Regex("""action\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE).find(form.value)?.groupValues?.get(1)
                    action?.startsWith("http://", true) == true
                }
                val inlineScripts = Regex("""<script\b(?![^>]*\bsrc\s*=)[^>]*>""", RegexOption.IGNORE_CASE).findAll(body).count()
                pageAnalysis.put("sampleBytes", body.toByteArray(Charsets.UTF_8).size)
                    .put("truncated", body.toByteArray(Charsets.UTF_8).size >= 512 * 1024)
                    .put("htmlScriptTags", scripts.size)
                    .put("externalScriptsWithoutSri", externalScriptsWithoutSri)
                    .put("inlineScriptBlocks", inlineScripts)
                    .put("passwordForms", passwordForms.size)
                    .put("insecurePasswordForms", insecurePasswordForms)
                    .put("httpResourceReferences", insecureRefs)
                if (insecureRefs > 0) add("MEDIUM", "موارد HTTP داخل صفحة HTTPS", "تم رصد $insecureRefs مرجعاً يستخدم HTTP داخل عينة HTML؛ تحقق من mixed content.", 5)
                if (insecurePasswordForms > 0) add("HIGH", "نموذج كلمة مرور يرسل إلى HTTP", "تم رصد نموذج كلمة مرور يحدد action عبر HTTP؛ راجع مسار الإرسال فوراً.", 12)
                if (externalScriptsWithoutSri > 0) add("INFO", "سكريبتات خارجية دون SRI", "تم رصد $externalScriptsWithoutSri وسماً لسكريبت خارجي دون integrity؛ SRI مفيد للملفات الثابتة المستضافة خارجياً.", 0)
                if (inlineScripts > 0 && csp.isNullOrBlank()) add("INFO", "كتل JavaScript داخلية", "تم رصد $inlineScripts كتلة script داخل الصفحة مع غياب CSP؛ هذه ملاحظة سياقية وليست إثبات XSS.", 0)
                pageAnalysis.put("analysisNote", "تحليل ساكن لعينة HTML محدودة؛ لا ينفذ JavaScript ولا يثبت قابلية الاستغلال.")
            } else {
                pageAnalysis.put("analysisNote", "لم يتم تحليل HTML لأن الاستجابة ليست صفحة HTML مباشرة.")
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
                val sameSiteValue = attrs.firstOrNull { it.startsWith("SameSite=", true) }?.substringAfter("=")
                val sameSite = sameSiteValue != null
                val prefixHost = name.startsWith("__Host-", true)
                val prefixSecure = name.startsWith("__Secure-", true)
                cookies.put(JSONObject().put("index", index + 1).put("name", name)
                    .put("secure", secure).put("httpOnly", httpOnly).put("sameSite", sameSiteValue ?: "Unspecified"))
                if (!secure) add("MEDIUM", "Cookie بدون Secure", "$name لا يفرض Secure؛ راجع ما إذا كان يجب حصره في HTTPS.", 4)
                if (!httpOnly && !name.contains("csrf", true) && !name.contains("xsrf", true))
                    add("LOW", "Cookie بدون HttpOnly", "$name يمكن الوصول إليه من JavaScript؛ أضف HttpOnly إن لم يكن مطلوباً للواجهة.", 2)
                if (!sameSite) add("LOW", "Cookie بدون SameSite", "$name لا يحدد SameSite صراحةً؛ راجع سياسة CSRF وتدفقات cross-site.", 2)
                if (sameSiteValue.equals("None", true) && !secure)
                    add("HIGH", "SameSite=None بدون Secure", "$name يستخدم SameSite=None دون Secure.", 8)
                if (prefixHost && (!secure || !attrs.any { it.equals("Path=/", true) } || attrs.any { it.startsWith("Domain=", true) }))
                    add("MEDIUM", "بادئة __Host- غير مطابقة للشروط", "$name يتطلب Secure وPath=/ وعدم وجود Domain.", 5)
                if (prefixSecure && !secure)
                    add("HIGH", "بادئة __Secure- بدون Secure", "$name يستخدم بادئة __Secure- دون خاصية Secure.", 8)
            }

            val redirect = conn.getHeaderField("Location")
            var redirectInfo: Any = JSONObject.NULL
            if (isRedirect && !redirect.isNullOrBlank()) {
                val resolved = URL(target, redirect)
                val safeLocation = resolved.protocol.equals("https", true)
                val sameHost = resolved.host.equals(host, true)
                redirectInfo = JSONObject().put("location", resolved.toString())
                    .put("sameHost", sameHost).put("https", safeLocation)
                if (!safeLocation) add("HIGH", "تحويل إلى HTTP", "وجهة التحويل تستخدم اتصالاً غير مشفر؛ لم يتم اتباعها.", 10)
                else if (!sameHost) add("INFO", "تحويل إلى نطاق آخر", "التحويل يذهب إلى ${resolved.host}. تحقق من ملكية الوجهة قبل فحصها.", 0)
            } else if (isRedirect) add("INFO", "استجابة تحويل", "HTTP $status بدون Location ظاهر؛ لم يتم اتباع التحويل.", 0)

            val cert = try { conn.serverCertificates.firstOrNull() as? java.security.cert.X509Certificate }
                catch (_: SSLPeerUnverifiedException) { null }
            val chain = try { conn.serverCertificates.size } catch (_: Exception) { 0 }
            val tls = JSONObject().put("cipherSuite", conn.cipherSuite ?: "Unavailable")
                .put("subject", cert?.subjectX500Principal?.name ?: "Unavailable")
                .put("issuer", cert?.issuerX500Principal?.name ?: "Unavailable")
                .put("notBefore", cert?.notBefore?.toString() ?: "Unavailable")
                .put("notAfter", cert?.notAfter?.toString() ?: "Unavailable")
                .put("certificateChainLength", chain)
            if (cert != null) {
                val daysLeft = TimeUnit.MILLISECONDS.toDays(cert.notAfter.time - Date().time)
                val sans = JSONArray()
                cert.subjectAlternativeNames?.forEach { entry -> if (entry.size > 1) sans.put(entry[1].toString()) }
                tls.put("daysUntilExpiry", daysLeft).put("subjectAlternativeNames", sans)
                    .put("publicKeyAlgorithm", cert.publicKey.algorithm)
                    .put("signatureAlgorithm", cert.sigAlgName)
                    .put("serialNumber", cert.serialNumber.toString(16))
                val key = cert.publicKey
                val keyBits = when (key) {
                    is java.security.interfaces.RSAKey -> key.modulus.bitLength()
                    is java.security.interfaces.ECKey -> key.params.order.bitLength()
                    else -> 0
                }
                tls.put("publicKeyBits", keyBits)
                when {
                    Date().before(cert.notBefore) -> add("HIGH", "الشهادة لم تصبح صالحة بعد", "تاريخ بداية صلاحية الشهادة في المستقبل.", 12)
                    Date().after(cert.notAfter) -> add("HIGH", "شهادة TLS منتهية", "انتهت صلاحية شهادة الخادم.", 18)
                    daysLeft <= 30 -> add("MEDIUM", "شهادة TLS قاربت على الانتهاء", "متبقي $daysLeft يوم تقريباً على انتهاء الشهادة.", 6)
                }
                if (key.algorithm.equals("RSA", true) && keyBits in 1..2047)
                    add("HIGH", "مفتاح RSA قصير", "طول المفتاح $keyBits بت؛ يوصى عادةً بـ 2048 بت على الأقل.", 10)
                if (cert.sigAlgName.contains("SHA1", true) || cert.sigAlgName.contains("MD5", true))
                    add("HIGH", "خوارزمية توقيع شهادة قديمة", "خوارزمية التوقيع: ${cert.sigAlgName}", 10)
                val sanMatch = cert.subjectAlternativeNames?.any { entry ->
                    entry.size > 1 && entry[1] is String && hostnameMatches(host, entry[1].toString())
                } ?: false
                if (!sanMatch) add("INFO", "تعذر تأكيد SAN للنطاق", "لم يعثر المحلل على تطابق واضح في SAN؛ تحقق من تفاصيل الشهادة يدوياً. لا يعني ذلك تجاوز تحقق TLS الذي نفذه النظام.", 0)
            }
            val cipher = conn.cipherSuite.orEmpty()
            if (Regex("(_NULL_|_EXPORT_|RC4|3DES|DES_CBC|MD5)", RegexOption.IGNORE_CASE).containsMatchIn(cipher))
                add("HIGH", "مجموعة تشفير قديمة أو ضعيفة", "مجموعة التشفير المعلنة تستحق مراجعة: $cipher", 12)

            val server = conn.getHeaderField("Server")
            if (!server.isNullOrBlank() && Regex("/\\d").containsMatchIn(server))
                add("INFO", "كشف إصدار الخادم", "ترويسة Server تكشف معلومات إصدار: $server", 0)

            val dns = JSONArray()
            addresses.forEach { dns.put(it.hostAddress) }
            val counts = JSONObject()
            listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").forEach { sev ->
                counts.put(sev.lowercase(), (0 until findings.length()).count { findings.getJSONObject(it).optString("severity") == sev })
            }
            val score = (100 - deductions.coerceAtMost(100)).coerceAtLeast(0)
            return JSONObject().put("ok", true).put("engineVersion", "4.0")
                .put("target", target.toString()).put("timestamp", System.currentTimeMillis())
                .put("status", status).put("contentType", contentType.ifBlank { "Unavailable" })
                .put("serverHeader", server ?: "Not disclosed").put("dns", dns)
                .put("tls", tls).put("headers", headers).put("pageAnalysis", pageAnalysis)
                .put("cookies", cookies).put("redirect", redirectInfo)
                .put("findings", findings).put("severityCounts", counts).put("score", score)
                .put("scoreDisclaimer", "درجة إرشادية للفحوص المنفذة فقط، وليست نسبة أمان أو احتمال اختراق.")
                .put("scopeNote", "فحص سلبي لاستجابة HTTPS واحدة وعينة HTML محدودة حتى 512KB. لا ينفذ JavaScript أو استغلالاً أو brute force أو تخمين مسارات أو فحصاً شاملاً للتطبيق.")
        } finally {
            conn.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Int): String {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (total < maxBytes) {
            val count = input.read(buffer, 0, minOf(buffer.size, maxBytes - total))
            if (count <= 0) break
            out.write(buffer, 0, count)
            total += count
        }
        return out.toString("UTF-8")
    }

    private fun hostnameMatches(host: String, pattern: String): Boolean {
        val p = pattern.lowercase().trimEnd('.')
        if (!p.startsWith("*.")) return host.equals(p, true)
        val suffix = p.substring(1)
        return host.endsWith(suffix, true) && host.count { it == '.' } == p.count { it == '.' }
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
