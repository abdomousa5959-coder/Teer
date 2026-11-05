package com.dexrat.lab

import android.net.Uri
import android.os.Bundle
import android.content.pm.PackageManager
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
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

data class ApkReport(val name:String,val sha:String,val entries:Int,val dex:List<String>,val libs:List<String>,val urls:List<String>,val packageName:String,val version:String)

class MainActivity : ComponentActivity() {
 private var picked:((Uri)->Unit)?=null
 private val picker=registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
  if(uri!=null) { contentResolver.takePersistableUriPermission(uri,android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION); picked?.invoke(uri) }
 }
 override fun onCreate(savedInstanceState:Bundle?) { super.onCreate(savedInstanceState); setContent { DexratApp({ cb -> picked=cb; picker.launch(arrayOf("application/vnd.android.package-archive","application/octet-stream")) },{ scan(it) }) } }
 private suspend fun scan(uri:Uri):ApkReport=withContext(Dispatchers.IO) {
  val file=cacheDir.resolve("dexrat.apk")
  contentResolver.openInputStream(uri).use { input -> requireNotNull(input).copyTo(file.outputStream()) }
  try {
   val sha=MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
   val entries=mutableListOf<String>(); val dex=mutableListOf<String>(); val libs=mutableListOf<String>(); val urls=linkedSetOf<String>()
   ZipFile(file).use { zip ->
    val it=zip.entries()
    while(it.hasMoreElements()) {
     val e=it.nextElement(); entries.add(e.name)
     if(Regex("classes(\\d*)\\.dex").matches(e.name)) dex.add(e.name)
     if(e.name.startsWith("lib/") && e.name.endsWith(".so")) libs.add(e.name)
     if(!e.isDirectory && e.size in 1..4194304 && (e.name.endsWith(".dex") || e.name.startsWith("assets/") || e.name.endsWith(".xml"))) {
      runCatching {
       val bytes=zip.getInputStream(e).use { it.readBytes() }
       Regex("https?://[^\\s]{5,}").findAll(String(bytes,Charsets.ISO_8859_1)).forEach { m -> urls.add(m.value.trimEnd('.',',',')',']',';')) }
      }
     }
    }
   }
   val info=packageManager.getPackageArchiveInfo(file.absolutePath,PackageManager.GET_PERMISSIONS)
   ApkReport(uri.lastPathSegment ?: "selected.apk",sha,entries.size,dex,libs,urls.toList().take(80),info?.packageName ?: "Unknown",info?.versionName ?: "Unknown")
  } finally { file.delete() }
 }
}

@Composable
fun DexratApp(onPick:((Uri)->Unit)->Unit,scan:suspend (Uri)->ApkReport) {
 var tab by remember { mutableIntStateOf(0) }; var report by remember { mutableStateOf<ApkReport?>(null) }
 var busy by remember { mutableStateOf(false) }; var error by remember { mutableStateOf("") }
 val scope=rememberCoroutineScope()
 MaterialTheme(colorScheme=darkColorScheme(primary=Neon,secondary=Cyan,background=Bg,surface=Panel)) {
  Box(Modifier.fillMaxSize().background(Bg)) {
   MatrixBackdrop()
   Column(Modifier.fillMaxSize().padding(16.dp)) {
    Row(verticalAlignment=Alignment.CenterVertically) {
     DexratLogo(52.dp); Spacer(Modifier.width(12.dp))
     Column(Modifier.weight(1f)) { Text("DEXRAT",color=Color.White,fontSize=25.sp,fontWeight=FontWeight.Black,letterSpacing=2.sp); Text("REVERSE ENGINEERING LAB",color=Neon,fontSize=9.sp,letterSpacing=2.sp) }
     Text("LOCAL",color=Neon,fontSize=10.sp,modifier=Modifier.border(1.dp,Neon,CircleShape).padding(8.dp))
    }
    Spacer(Modifier.height(20.dp))
    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
     listOf("Overview","Analyze","Report").forEachIndexed { i,label ->
      Box(Modifier.weight(1f).background(if(tab==i) Color(0x3339F5A5) else Panel,RoundedCornerShape(10.dp)).border(1.dp,if(tab==i) Neon else Color(0xFF20343A),RoundedCornerShape(10.dp)).clickable { tab=i }.padding(12.dp),contentAlignment=Alignment.Center) { Text(label,color=if(tab==i) Neon else Muted,fontSize=12.sp,fontWeight=FontWeight.Bold) }
     }
    }
    Spacer(Modifier.height(16.dp))
    when(tab) {
     0 -> {
      CardBlock("LAB STATUS") { Text("STATIC APK INSPECTION READY",color=Color.White,fontWeight=FontWeight.Bold,fontSize=17.sp); Text("Local analysis • No APK upload • Offline processing",color=Muted,fontSize=11.sp); Spacer(Modifier.height(12.dp)); Text("ENGINE ONLINE   •   MODE OFFLINE   •   V1.0",color=Neon,fontSize=10.sp) }
      Spacer(Modifier.height(12.dp))
      CardBlock("QUICK START") { Text("افحص ملفات APK التي تملكها أو لديك تصريح بتحليلها.",color=Muted,fontSize=12.sp); Spacer(Modifier.height(10.dp)); Button(onClick={tab=1},modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.buttonColors(containerColor=Neon)) { Text("START APK ANALYSIS",color=Bg,fontWeight=FontWeight.Black) } }
     }
     1 -> CardBlock("APK INSPECTOR") {
      Text("اختر ملف APK. الفحص ثابت ولا يشغّل التطبيق.",color=Muted,fontSize=12.sp); Spacer(Modifier.height(12.dp))
      Button(enabled=!busy,onClick={error="";onPick { uri -> scope.launch { busy=true; try { report=scan(uri); tab=2 } catch(t:Throwable) { error=t.message ?: "Scan failed" } finally { busy=false } } } },modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.buttonColors(containerColor=Neon)) { Text(if(busy) "ANALYZING…" else "CHOOSE APK",color=Bg,fontWeight=FontWeight.Bold) }
      if(busy) { Spacer(Modifier.height(10.dp)); LinearProgressIndicator(Modifier.fillMaxWidth(),color=Neon) }
      if(error.isNotEmpty()) Text(error,color=Color.Red,fontSize=11.sp)
     }
     else -> {
      val r=report
      if(r==null) CardBlock("NO REPORT") { Text("No scan yet",color=Muted) } else LazyColumn(verticalArrangement=Arrangement.spacedBy(10.dp)) {
       item { CardBlock("FILE SUMMARY") { Info("File",r.name); Info("Package",r.packageName); Info("Version",r.version); Info("ZIP entries",r.entries.toString()); Info("SHA-256",r.sha) } }
       item { CardBlock("DEX FILES ("+r.dex.size+")") { if(r.dex.isEmpty()) Text("None found",color=Muted); r.dex.forEach { Text(it,color=Cyan,fontSize=11.sp) } } }
       item { CardBlock("NATIVE LIBRARIES ("+r.libs.size+")") { if(r.libs.isEmpty()) Text("None found",color=Muted); r.libs.take(60).forEach { Text(it,color=Cyan,fontSize=11.sp) } } }
       item { CardBlock("URL STRINGS ("+r.urls.size+")") { if(r.urls.isEmpty()) Text("None found",color=Muted); r.urls.forEach { Text(it,color=Color.White,fontSize=10.sp) } } }
      }
     }
    }
    Spacer(Modifier.weight(1f))
    Text("DEXRAT • STATIC ANALYSIS • V1.0.0",color=Muted,fontSize=9.sp,modifier=Modifier.align(Alignment.CenterHorizontally))
   }
  }
 }
}

@Composable fun CardBlock(title:String,content:@Composable ColumnScope.()->Unit) {
 Column(Modifier.fillMaxWidth().background(Panel.copy(alpha=.95f),RoundedCornerShape(16.dp)).border(1.dp,Color(0xFF1D4540),RoundedCornerShape(16.dp)).padding(15.dp)) { Text(title,color=Neon,fontSize=11.sp,fontWeight=FontWeight.Bold,letterSpacing=1.2.sp); Spacer(Modifier.height(10.dp)); content() }
}
@Composable fun Info(k:String,v:String) { Text(k.uppercase(),color=Muted,fontSize=9.sp); Text(v,color=Color.White,fontSize=11.sp,modifier=Modifier.padding(bottom=8.dp)) }
@Composable fun DexratLogo(size:androidx.compose.ui.unit.Dp) {
 Canvas(Modifier.size(size)) {
  val w=this.size.width; val h=this.size.height
  val p=Path().apply { moveTo(w*.5f,h*.04f); lineTo(w*.92f,h*.27f); lineTo(w*.92f,h*.73f); lineTo(w*.5f,h*.96f); lineTo(w*.08f,h*.73f); lineTo(w*.08f,h*.27f); close() }
  drawPath(p,brush=Brush.linearGradient(listOf(Color(0xFF123E35),Color(0xFF0A1720)))); drawPath(p,color=Neon,style=androidx.compose.ui.graphics.drawscope.Stroke(width=w*.045f))
  drawLine(Neon,Offset(w*.3f,h*.28f),Offset(w*.3f,h*.72f),w*.07f,cap=StrokeCap.Round); drawLine(Neon,Offset(w*.3f,h*.28f),Offset(w*.7f,h*.28f),w*.07f,cap=StrokeCap.Round); drawLine(Neon,Offset(w*.3f,h*.5f),Offset(w*.62f,h*.5f),w*.07f,cap=StrokeCap.Round); drawLine(Neon,Offset(w*.3f,h*.72f),Offset(w*.7f,h*.72f),w*.07f,cap=StrokeCap.Round)
 }
}
@Composable fun MatrixBackdrop() {
 val tr=rememberInfiniteTransition(label="matrix"); val offset by tr.animateFloat(0f,1f,infiniteRepeatable(tween(8000,easing=LinearEasing)),label="offset"); val pulse by tr.animateFloat(.08f,.3f,infiniteRepeatable(tween(1800),RepeatMode.Reverse),label="pulse")
 Canvas(Modifier.fillMaxSize()) {
  val gap=34.dp.toPx()
  for(x in 0..(size.width/gap).toInt()) drawLine(Color(0xFF12352F).copy(alpha=.2f),Offset(x*gap,0f),Offset(x*gap,size.height),1f)
  for(y in 0..(size.height/gap).toInt()) drawLine(Color(0xFF12352F).copy(alpha=.15f),Offset(0f,y*gap),Offset(size.width,y*gap),1f)
  for(i in 0..25) drawCircle(Neon.copy(alpha=pulse),if(i%4==0) 2f else 1f,Offset((i*83f)%size.width,(i*127f+offset*size.height)%size.height))
  drawRect(Brush.verticalGradient(listOf(Color(0xCC050A0D),Color(0x99050A0D),Color(0xEE050A0D))))
 }
}
