package com.tulipeni.nexusultra.scanner
import java.net.IDN
import java.net.URL
object TargetScope {
 fun normalizeHttps(raw:String):URL {
  val input=URL(raw.trim())
  require(input.protocol.equals("https",true)) { "يسمح بفحص HTTPS فقط." }
  require(input.userInfo==null) { "لا تضع بيانات دخول داخل الرابط." }
  require(input.port==-1 || input.port==443) { "الفحص متاح على المنفذ 443 فقط." }
  val host=IDN.toASCII(input.host.trimEnd('.')).lowercase()
  require(host.length<=253 && host.contains(".") && !host.startsWith("-")) { "اسم النطاق غير صالح." }
  require(host!="localhost" && !host.endsWith(".localhost")) { "النطاق المحلي غير مسموح." }
  return URL("https",host,443,input.file.ifBlank { "/" })
 }
 fun isSameOrigin(candidate:URL,origin:URL)=candidate.protocol.equals("https",true) && candidate.host.equals(origin.host,true) && (candidate.port==-1 || candidate.port==443) && candidate.userInfo==null && candidate.query==null
}