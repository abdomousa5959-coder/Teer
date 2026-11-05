package com.dexrat.lab

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.zip.ZipFile

private val Neon = Color(0xFF39F5A5)
private val Cyan = Color(0xFF50D9F5)
private val Bg = Color(0xFF050A0D)
private val Panel = Color(0xFF0B151A)
private val Muted = Color(0xFF91A7AC)

data class ApkReport(
    val name:String, val sha:String, val entries:Int, val dex:List<String>,
    val libs:List<String>, val urls:List<String>, val packageName:String,
    val version:String, val permissions:List<String>, val activities:List<String>,
    val services:List<String>, val receivers:List<String>, val providers:List<String>,
    val indicators:List<String>, val certSha256:String, val score:Int,
    val warnings:List<String>
) {
    fun asText():String = buildString {
        appendLine("DEXRAT V2 ULTRA — STATIC APK REPORT")
        appendLine("File: $name"); appendLine("Package: $packageName"); appendLine("Version: $version")
        appendLine("SHA-256: $sha"); appendLine("Risk score: $score/100")
        appendLine("Signing certificate SHA-256: $certSha256")
        appendLine("\nPermissions:"); permissions.forEach { appendLine(" • $it") }
        appendLine("\nDEX files:"); dex.forEach { appendLine(" • $it") }
        appendLine("\nNative libraries:"); libs.forEach { appendLine(" • $it") }
        appendLine("\nURLs:"); urls.forEach { appendLine(" • $it") }
        appendLine("\nSuspicious indicators:"); indicators.forEach { appendLine(" • $it") }
        appendLine("\nActivities:"); activities.forEach { appendLine(" • $it") }
        appendLine("\nServices:"); services.forEach { appendLine(" • $it") }
        appendLine("\nReceivers:"); receivers.forEach { appendLine(" • $it") }
        appendLine("\nProviders:"); providers.forEach { appendLine(" • $it") }
        appendLine("\nNotes:"); warnings.forEach { appendLine(" • $it") }
        appendLine("\nDEXRAT performs static inspection only. Findings are indicators, not proof of malware.")
    }
}

class MainActivity : ComponentActivity() {
    private var picked:((Uri)->Unit)?=null
    private val picker=registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if(uri!=null) {
            runCatching { contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            picked?.invoke(uri)
        }
    }
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { DexratApp({ cb -> picked=cb; picker.launch(arrayOf("application/vnd.android.package-archive","application/octet-stream")) },{ scan(it) }) }
    }

    @Suppress("DEPRECATION")
    private suspend fun scan(uri:Uri):ApkReport=withContext(Dispatchers.IO) {
        val file=cacheDir.resolve("dexrat-${System.nanoTime()}.apk")
        contentResolver.openInputStream(uri).use { input -> requireNotNull(input) { "تعذر فتح الملف المختار" }.copyTo(file.outputStream()) }
        try {
            val sha=MessageDigest.getInstance("SHA-256").digest(file.readBytes()).hex()
            val entries=mutableListOf<String>(); val dex=mutableListOf<String>(); val libs=mutableListOf<String>()
            val urls=linkedSetOf<String>(); val indicators=linkedSetOf<String>()
            val urlRegex=Regex("https?://[A-Za-z0-9._~:/?#\\[\\]@!\\?#\\[\\]@!$&'()*+,;=%-]{5,}",RegexOption.IGNORE_CASE)
            val signatures=listOf(
                "DexClassLoader" to "Dynamic code loading (DexClassLoader)",
                "PathClassLoader" to "Custom class loading (PathClassLoader)",
                "Runtime.getRuntime" to "Runtime command execution reference",
                "ProcessBuilder" to "ProcessBuilder command execution reference",
                "AccessibilityService" to "Accessibility service reference",
                "DeviceAdminReceiver" to "Device administrator reference",
                "getDeviceId" to "Device identifier access reference",
                "getImei" to "IMEI access reference",
                "REQUEST_INSTALL_PACKAGES" to "Request to install other packages",
                "SYSTEM_ALERT_WINDOW" to "Overlay permission reference",
                "RECEIVE_BOOT_COMPLETED" to "Auto-start after device boot permission",
                "VpnService" to "VPN service reference",
                "WebView.setJavaScriptEnabled" to "WebView JavaScript enabled reference",
                "TrustManager" to "Custom TLS trust manager reference",
                "X509TrustManager" to "Custom certificate trust manager reference",
                "Cipher.getInstance" to "Cryptography API reference",
                "su -c" to "Root command string reference"
            )
            ZipFile(file).use { zip ->
                val it=zip.entries()
                while(it.hasMoreElements()) {
                    val e=it.nextElement(); entries.add(e.name)
                    if(Regex("classes(\\d*)\\.dex").matches(e.name)) dex.add(e.name)
                    if(e.name.startsWith("lib/") && e.name.endsWith(".so")) libs.add(e.name)
                    if(!e.isDirectory && e.size in 1..8_388_608 &&
                        (e.name.endsWith(".dex") || e.name.startsWith("assets/") || e.name.endsWith(".xml") || e.name.endsWith(".json"))) {
                        runCatching {
                            val content=zip.getInputStream(e).use { stream -> stream.readBytes().toString(Charsets.ISO_8859_1) }
                            urlRegex.findAll(content).forEach { m -> urls.add(m.value.trimEnd('.',',',')',']',';')) }
                            signatures.forEach { (needle,label) -> if(content.contains(needle,true)) indicators.add(label) }
                            if(content.contains("usesCleartextTraffic=\"true\"",true)) indicators.add("Manifest string suggests cleartext traffic is enabled")
                            if(content.contains("android:debuggable=\"true\"",true)) indicators.add("Manifest string suggests debuggable build")
                        }
                    }
                }
            }
            val flags=PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or PackageManager.GET_SIGNING_CERTIFICATES
            val info=packageManager.getPackageArchiveInfo(file.absolutePath,flags)
            val perms=info?.requestedPermissions?.toList().orEmpty()
            val activities=info?.activities?.map { it.name + if(it.exported) "  [EXPORTED]" else "" }.orEmpty()
            val services=info?.services?.map { it.name + if(it.exported) "  [EXPORTED]" else "" }.orEmpty()
            val receivers=info?.receivers?.map { it.name + if(it.exported) "  [EXPORTED]" else "" }.orEmpty()
            val providers=info?.providers?.map { it.name + if(it.exported) "  [EXPORTED]" else "" }.orEmpty()
            val cert=runCatching {
                (if (Build.VERSION.SDK_INT >= 28) info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() else null)?.let {
                    MessageDigest.getInstance("SHA-256").digest(it).hex()
                } ?: "Unavailable"
            }.getOrDefault("Unavailable")
            val riskPerms=listOf("READ_SMS","RECEIVE_SMS","SEND_SMS","READ_CALL_LOG","RECORD_AUDIO","CAMERA","READ_CONTACTS","ACCESS_FINE_LOCATION","REQUEST_INSTALL_PACKAGES","SYSTEM_ALERT_WINDOW","BIND_ACCESSIBILITY_SERVICE","RECEIVE_BOOT_COMPLETED")
            val risky=perms.filter { p -> riskPerms.any { p.endsWith(it) } }
            val warnings=mutableListOf<String>()
            if(info==null) warnings.add("Android PackageManager could not decode package metadata; manifest details may be incomplete.")
            if(dex.isEmpty()) warnings.add("No classes.dex found in the archive.")
            if(cert=="Unavailable") warnings.add("Signing certificate fingerprint could not be read from this APK.")
            warnings.add("Static string matches can be false positives; verify each item in context.")
            warnings.add("No code was executed, no network requests were sent, and the APK was not installed.")
            val score=(risky.size*5 + indicators.size*4 + (if(libs.isNotEmpty()) 3 else 0) + (if(urls.size>15) 5 else 0)).coerceIn(0,100)
            ApkReport(uri.lastPathSegment ?: "selected.apk",sha,entries.size,dex,libs,urls.toList().take(150),
                info?.packageName ?: "Unknown",info?.versionName ?: "Unknown",perms,activities,
                services,receivers,providers,indicators.toList(),cert,score,warnings)
        } finally { file.delete() }
    }
}
private fun ByteArray.hex()=joinToString("") { "%02x".format(it) }

@Composable
fun DexratApp(onPick:((Uri)->Unit)->Unit,scan:suspend (Uri)->ApkReport) {
    var tab by remember { mutableIntStateOf(0) }; var report by remember { mutableStateOf<ApkReport?>(null) }
    var busy by remember { mutableStateOf(false) }; var error by remember { mutableStateOf("") }
    val scope=rememberCoroutineScope(); val context= LocalContext.current
    MaterialTheme(colorScheme=darkColorScheme(primary=Neon,secondary=Cyan,background=Bg,surface=Panel)) {
        Box(Modifier.fillMaxSize().background(Bg)) {
            MatrixBackdrop()
            Column(Modifier.fillMaxSize().padding(14.dp)) {
                Row(verticalAlignment=Alignment.CenterVertically) {
                    DexratLogo(50.dp); Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text("DEXRAT",color=Color.White,fontSize=25.sp,fontWeight=FontWeight.Black,letterSpacing=2.sp)
                        Text("V2 • ULTRA APK INTELLIGENCE",color=Neon,fontSize=9.sp,letterSpacing=1.5.sp)
                    }
                    Text("OFFLINE",color=Neon,fontSize=9.sp,modifier=Modifier.border(1.dp,Neon,CircleShape).padding(7.dp))
                }
                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement=Arrangement.spacedBy(5.dp)) {
                    listOf("Home","Scan","Report","Guide").forEachIndexed { i,label ->
                        Box(Modifier.weight(1f).background(if(tab==i) Color(0x3339F5A5) else Panel,RoundedCornerShape(9.dp))
                            .border(1.dp,if(tab==i) Neon else Color(0xFF20343A),RoundedCornerShape(9.dp))
                            .clickable { tab=i }.padding(vertical=12.dp),contentAlignment=Alignment.Center) {
                            Text(label,color=if(tab==i) Neon else Muted,fontSize=11.sp,fontWeight=FontWeight.Bold)
                        }
                    }
                }
                Spacer(Modifier.height(13.dp))
                when(tab) {
                    0 -> Column(Modifier.weight(1f).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(11.dp)) {
                        CardBlock("SYSTEM ONLINE") {
                            Text("APK STATIC INTELLIGENCE",color=Color.White,fontSize=18.sp,fontWeight=FontWeight.Black)
                            Text("فحص محلي داخل الهاتف • بدون رفع ملفات • لا يتم تشغيل APK",color=Muted,fontSize=11.sp)
                            Spacer(Modifier.height(10.dp)); Text("DEX ENGINE  •  MANIFEST  •  SIGNATURE  •  INDICATORS",color=Neon,fontSize=9.sp)
                        }
                        CardBlock("WHAT DEXRAT CAN DO") {
                            listOf("SHA-256 file fingerprint","DEX & native library inventory","Package, version & requested permissions","Activities / services / receivers / providers","URL extraction from readable archive content","Suspicious API and behavior string indicators","Signing certificate SHA-256 fingerprint","Heuristic risk score and shareable report").forEach { Bullet(it) }
                        }
                        CardBlock("QUICK START") {
                            Text("ابدأ من Scan ثم اختر ملف APK من مدير الملفات. بعد انتهاء الفحص افتح Report لمراجعة النتائج أو مشاركتها.",color=Muted,fontSize=12.sp)
                            Spacer(Modifier.height(10.dp))
                            Button(onClick={tab=1},modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.buttonColors(containerColor=Neon)) { Text("START SCANNING",color=Bg,fontWeight=FontWeight.Black) }
                        }
                        CardBlock("IMPORTANT") { Text("DEXRAT أداة تحليل ثابت دفاعية. الدرجة تقديرية وليست حكماً بأن التطبيق خبيث. لا يوجد تحليل ديناميكي أو فك كامل لـ Smali في هذا الإصدار.",color=Muted,fontSize=11.sp) }
                    }
                    1 -> Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                        CardBlock("APK INSPECTOR") {
                            Text("اختر APK تملكه أو لديك تصريح بتحليله. التطبيق لن يثبّت الملف ولن يشغّله.",color=Muted,fontSize=12.sp)
                            Spacer(Modifier.height(12.dp))
                            Button(enabled=!busy,onClick={
                                error=""; onPick { uri -> scope.launch {
                                    busy=true
                                    try { report=scan(uri); tab=2 }
                                    catch(t:Throwable) { error=t.message ?: "حدث خطأ أثناء الفحص" }
                                    finally { busy=false }
                                } }
                            },modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.buttonColors(containerColor=Neon)) {
                                Text(if(busy) "ANALYZING…" else "SELECT APK FILE",color=Bg,fontWeight=FontWeight.Black)
                            }
                            if(busy) { Spacer(Modifier.height(12.dp)); LinearProgressIndicator(Modifier.fillMaxWidth(),color=Neon) }
                            if(error.isNotEmpty()) Text(error,color=Color(0xFFFF7777),fontSize=11.sp)
                        }
                        CardBlock("SCAN PIPELINE") {
                            listOf("1  Read selected APK locally","2  Calculate SHA-256","3  Enumerate ZIP / DEX / SO files","4  Read package metadata & permissions","5  Extract readable URLs and indicators","6  Estimate risk and build report").forEach { Bullet(it) }
                        }
                    }
                    2 -> {
                        val r=report
                        if(r==null) Column(Modifier.weight(1f)) { CardBlock("NO REPORT") { Text("اعمل Scan الأول عشان يظهر التقرير.",color=Muted) } }
                        else LazyColumn(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(9.dp)) {
                            item { CardBlock("RISK OVERVIEW") {
                                Text("${r.score}/100",color=if(r.score>=50) Color(0xFFFF7777) else Neon,fontSize=34.sp,fontWeight=FontWeight.Black)
                                Text("Heuristic indicator score • not a malware verdict",color=Muted,fontSize=10.sp)
                                LinearProgressIndicator(progress={r.score/100f},modifier=Modifier.fillMaxWidth(),color=if(r.score>=50) Color(0xFFFF7777) else Neon)
                            } }
                            item { CardBlock("FILE & SIGNATURE") { Info("File",r.name); Info("Package",r.packageName); Info("Version",r.version); Info("ZIP entries",r.entries.toString()); Info("APK SHA-256",r.sha); Info("Certificate SHA-256",r.certSha256) } }
                            item { CardBlock("REQUESTED PERMISSIONS (${r.permissions.size})") { if(r.permissions.isEmpty()) Empty("No permission metadata"); r.permissions.forEach { Text(it,color=if(listOf("SMS","CAMERA","RECORD_AUDIO","LOCATION","CONTACTS","INSTALL_PACKAGES","SYSTEM_ALERT_WINDOW").any { k -> it.contains(k,true) }) Color(0xFFFFD166) else Color.White,fontSize=10.sp) } } }
                            item { CardBlock("SUSPICIOUS INDICATORS (${r.indicators.size})") { if(r.indicators.isEmpty()) Empty("No known string indicators found"); r.indicators.forEach { Bullet(it) } } }
                            item { CardBlock("DEX FILES (${r.dex.size})") { if(r.dex.isEmpty()) Empty("No DEX files found"); r.dex.forEach { Text(it,color=Cyan,fontSize=10.sp) } } }
                            item { CardBlock("NATIVE LIBRARIES (${r.libs.size})") { if(r.libs.isEmpty()) Empty("No native libraries found"); r.libs.forEach { Text(it,color=Cyan,fontSize=10.sp) } } }
                            item { CardBlock("URL STRINGS (${r.urls.size})") { if(r.urls.isEmpty()) Empty("No URLs found"); r.urls.forEach { Text(it,color=Color.White,fontSize=10.sp) } } }
                            item { CardBlock("ACTIVITIES") { if(r.activities.isEmpty()) Empty("None decoded"); r.activities.forEach { Bullet(it) } } }
                            item { CardBlock("SERVICES") { if(r.services.isEmpty()) Empty("None decoded"); r.services.forEach { Bullet(it) } } }
                            item { CardBlock("RECEIVERS") { if(r.receivers.isEmpty()) Empty("None decoded"); r.receivers.forEach { Bullet(it) } } }
                            item { CardBlock("PROVIDERS") { if(r.providers.isEmpty()) Empty("None decoded"); r.providers.forEach { Bullet(it) } } }
                            item { CardBlock("ANALYSIS NOTES") { r.warnings.forEach { Bullet(it) }; Spacer(Modifier.height(8.dp)); Button(onClick={
                                val send=Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_SUBJECT,"DEXRAT APK report").putExtra(Intent.EXTRA_TEXT,r.asText())
                                context.startActivity(Intent.createChooser(send,"Share DEXRAT report"))
                            },modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.buttonColors(containerColor=Neon)) { Text("SHARE FULL REPORT",color=Bg,fontWeight=FontWeight.Bold) } } }
                        }
                    }
                    else -> Column(Modifier.weight(1f).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)) {
                        CardBlock("HOW TO USE DEXRAT") {
                            listOf(
                                "1. افتح تبويب Scan.",
                                "2. اضغط SELECT APK FILE.",
                                "3. من مدير الملفات اختر ملف ينتهي بـ .apk.",
                                "4. انتظر انتهاء الفحص؛ لا تغلق التطبيق أثناء المعالجة.",
                                "5. افتح Report لمشاهدة النتيجة بالتفصيل.",
                                "6. اضغط SHARE FULL REPORT لإرسال التقرير أو حفظه في تطبيق آخر."
                            ).forEach { Bullet(it) }
                        }
                        CardBlock("UNDERSTANDING THE REPORT") {
                            listOf(
                                "SHA-256: بصمة الملف لمقارنة النسخ والتحقق من تطابقها.",
                                "Permissions: الصلاحيات التي يطلبها التطبيق، وليست دليلاً وحدها على إساءة الاستخدام.",
                                "Exported components: مكونات معلّمة بأنها متاحة للتطبيقات الأخرى وفق بيانات الحزمة.",
                                "URLs: عناوين عُثر عليها كنصوص قابلة للقراءة؛ لا يتم الاتصال بها.",
                                "Indicators: أسماء APIs أو نصوص قد تستحق مراجعة يدوية؛ قد تظهر نتائج كاذبة.",
                                "Risk score: مؤشر تقريبي مبني على عدد بعض الصلاحيات والمؤشرات، وليس نسبة احتمال إصابة."
                            ).forEach { Bullet(it) }
                        }
                        CardBlock("LIMITATIONS & SAFETY") {
                            listOf(
                                "الفحص Static فقط؛ لا يشغّل APK ولا يراقب سلوكه أثناء التشغيل.",
                                "لا يفك DEX إلى Smali ولا يفحص كل تدفق التنفيذ.",
                                "بعض ملفات XML تكون بصيغة Android binary وقد لا تُقرأ كنص.",
                                "لا يثبت أن التطبيق آمن أو خبيث بشكل قاطع.",
                                "حلّل فقط التطبيقات التي تملكها أو لديك إذن صريح بفحصها."
                            ).forEach { Bullet(it) }
                        }
                        CardBlock("TROUBLESHOOTING") {
                            listOf(
                                "لو الملف غير ظاهر: اختر All files أو APK من مدير الملفات.",
                                "لو ظهر خطأ قراءة: أعد اختيار الملف وتأكد أنه APK سليم وليس ZIP تالفاً.",
                                "لو البيانات ناقصة: قد يكون Android غير قادر على قراءة Manifest الخاص بالملف.",
                                "لو التطبيق كبير: انتظر؛ تتم القراءة محلياً وقد يستغرق ذلك وقتاً."
                            ).forEach { Bullet(it) }
                        }
                    }
                }
                Spacer(Modifier.height(6.dp))
                Text("DEXRAT V2 ULTRA • DEFENSIVE STATIC ANALYSIS",color=Muted,fontSize=8.sp,modifier=Modifier.align(Alignment.CenterHorizontally))
            }
        }
    }
}

@Composable private fun Bullet(s:String) { Row(Modifier.padding(bottom=5.dp),verticalAlignment=Alignment.Top) { Text("›",color=Neon,fontSize=15.sp,fontWeight=FontWeight.Bold); Spacer(Modifier.width(7.dp)); Text(s,color=Color(0xFFD4E1E2),fontSize=11.sp) } }
@Composable private fun Empty(s:String) { Text(s,color=Muted,fontSize=10.sp) }
@Composable fun CardBlock(title:String,content:@Composable ColumnScope.()->Unit) {
    Column(Modifier.fillMaxWidth().background(Panel.copy(alpha=.97f),RoundedCornerShape(15.dp)).border(1.dp,Color(0xFF1D4540),RoundedCornerShape(15.dp)).padding(13.dp)) {
        Text(title,color=Neon,fontSize=10.sp,fontWeight=FontWeight.Bold,letterSpacing=1.sp); Spacer(Modifier.height(9.dp)); content()
    }
}
@Composable fun Info(k:String,v:String) { Text(k.uppercase(),color=Muted,fontSize=8.sp); Text(v,color=Color.White,fontSize=10.sp,modifier=Modifier.padding(bottom=7.dp)) }
@Composable fun DexratLogo(size:androidx.compose.ui.unit.Dp) {
    Canvas(Modifier.size(size)) {
        val w=this.size.width; val h=this.size.height
        val p=Path().apply { moveTo(w*.5f,h*.04f); lineTo(w*.92f,h*.27f); lineTo(w*.92f,h*.73f); lineTo(w*.5f,h*.96f); lineTo(w*.08f,h*.73f); lineTo(w*.08f,h*.27f); close() }
        drawPath(p,brush=Brush.linearGradient(listOf(Color(0xFF123E35),Color(0xFF0A1720))))
        drawPath(p,color=Neon,style=androidx.compose.ui.graphics.drawscope.Stroke(width=w*.045f))
        drawLine(Neon,Offset(w*.3f,h*.28f),Offset(w*.3f,h*.72f),w*.07f,cap=StrokeCap.Round)
        drawLine(Neon,Offset(w*.3f,h*.28f),Offset(w*.7f,h*.28f),w*.07f,cap=StrokeCap.Round)
        drawLine(Neon,Offset(w*.3f,h*.5f),Offset(w*.62f,h*.5f),w*.07f,cap=StrokeCap.Round)
        drawLine(Neon,Offset(w*.3f,h*.72f),Offset(w*.7f,h*.72f),w*.07f,cap=StrokeCap.Round)
    }
}
@Composable fun MatrixBackdrop() {
    val tr=rememberInfiniteTransition(label="matrix")
    val offset by tr.animateFloat(0f,1f,infiniteRepeatable(tween(8000,easing=LinearEasing)),label="offset")
    val pulse by tr.animateFloat(.08f,.3f,infiniteRepeatable(tween(1800),RepeatMode.Reverse),label="pulse")
    Canvas(Modifier.fillMaxSize()) {
        val gap=34.dp.toPx()
        for(x in 0..(size.width/gap).toInt()) drawLine(Color(0xFF12352F).copy(alpha=.2f),Offset(x*gap,0f),Offset(x*gap,size.height),1f)
        for(y in 0..(size.height/gap).toInt()) drawLine(Color(0xFF12352F).copy(alpha=.15f),Offset(0f,y*gap),Offset(size.width,y*gap),1f)
        for(i in 0..25) drawCircle(Neon.copy(alpha=pulse),if(i%4==0) 2f else 1f,Offset((i*83f)%size.width,(i*127f+offset*size.height)%size.height))
        drawRect(Brush.verticalGradient(listOf(Color(0xCC050A0D),Color(0x99050A0D),Color(0xEE050A0D))))
    }
}
