package com.tulipeni.nexusultra.scanner
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection
/** HEAD/OPTIONS only: no payloads, credentials, form submissions, path guessing or state changes. */
object SafeActiveChecks {
 fun run(target:URL,connectTimeout:Int,readTimeout:Int):JSONObject {
  val results=JSONArray()
  listOf("HEAD","OPTIONS").forEach { method ->
   val result=JSONObject().put("method",method)
   var connection:HttpsURLConnection?=null
   try {
    connection=(target.openConnection() as HttpsURLConnection).apply {
     requestMethod=method; this.connectTimeout=connectTimeout; this.readTimeout=readTimeout
     instanceFollowRedirects=false; useCaches=false
     setRequestProperty("User-Agent","NexusXUltra/6.0 (authorized-safe-check)")
     setRequestProperty("Connection","close")
    }
    val status=connection.responseCode
    result.put("status",status).put("allow",connection.getHeaderField("Allow") ?: JSONObject.NULL)
     .put("corsOrigin",connection.getHeaderField("Access-Control-Allow-Origin") ?: JSONObject.NULL)
     .put("corsMethods",connection.getHeaderField("Access-Control-Allow-Methods") ?: JSONObject.NULL)
     .put("corsCredentials",connection.getHeaderField("Access-Control-Allow-Credentials") ?: JSONObject.NULL)
     .put("note","طلب محدود دون إرسال بيانات أو تغيير حالة الخادم.")
   } catch(e:Exception) { result.put("error",e.message ?: "تعذر تنفيذ الطلب") }
   finally { connection?.disconnect() }
   results.put(result)
  }
  return JSONObject().put("enabled",true).put("checks",results).put("disclaimer","مؤشرات إعدادات فقط ولا تثبت قابلية الاستغلال.")
 }
}