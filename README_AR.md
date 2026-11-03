# NEXUS X ULTRA — Android Passive Web Security Audit

## الإصدار 4.2
- واجهة Android بطابع Terminal أسود/أخضر مع تصدير JSON.
- فحص HTTPS فقط على المنفذ 443، مع موافقة صريحة، ورفض عناوين IP المحلية والخاصة.
- تحليل TLS: الشهادة، SAN، سلسلة الشهادات، الصلاحية، نوع/طول المفتاح، التوقيع ومجموعة التشفير.
- مراجعة HSTS وCSP وتوجيهات object-src/base-uri/form-action/frame-ancestors وX-Frame-Options.
- تحليل COOP/CORP/COEP وCORS، مع رصد CORS wildcard مع credentials.
- تحليل Cookies دون حفظ قيمها: Secure وHttpOnly وSameSite وبادئات __Host-/__Secure-.
- تحليل عينة استجابة محدودة حتى 512KB: أخطاء SQL/PHP، Stack traces، أنماط كشف PHP، XML DOCTYPE/External Entity declarations.
- فحص HTML ساكن: mixed content، نماذج كلمات المرور عبر HTTP أو GET، سكريبتات خارجية دون SRI، روابط target=_blank دون noopener، iframe دون sandbox، ومراجع Source Map.
- تحليل Location دون اتباع التحويل تلقائياً، وكشف بعض معلومات الخادم.
- تصنيف النتائج وتصدير JSON.

## حدود الدقة
هذا محرك مراجعة سلبية وليس ماسح استغلال. لا ينفذ SQL injection أو XXE payloads، ولا يجرب كلمات مرور، ولا يخمن مسارات أو يفحص منافذ، ولا ينفذ JavaScript. عدم ظهور مؤشر لا يثبت غياب الثغرة. رسائل SQL/PHP وXML declarations مؤشرات تحتاج تحققاً يدوياً، كما أن فحص استجابة واحدة لا يغطي الموقع كله. استخدمه فقط على نطاقات تملكها أو لديك تصريح صريح بفحصها.

## البناء
افتح GitHub Actions ونزّل artifact باسم `nexus-x-ultra-debug-apk` بعد نجاح البناء.
