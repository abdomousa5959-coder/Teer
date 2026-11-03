# NEXUS X ULTRA — Android Passive Web Security Audit

## الإصدار 4.0
- واجهة سوداء وخضراء بطابع Terminal.
- فحص HTTPS سلبي لعنوان واحد في كل تشغيل، مع موافقة المستخدم.
- تحليل ترويسات HSTS وCSP وتوجيهات CSP الأساسية، X-Content-Type-Options، X-Frame-Options/frame-ancestors، Referrer-Policy، Permissions-Policy وCOOP/CORP/COEP.
- مراجعة Cookies لخصائص Secure وHttpOnly وSameSite وبادئات __Host-/__Secure- دون حفظ قيم الكوكي.
- تحليل شهادة TLS: SAN، الجهة المصدرة، الصلاحية، طول المفتاح، خوارزمية التوقيع، سلسلة الشهادات ومجموعة التشفير.
- تحليل ساكن لعينة HTML محدودة حتى 512KB لرصد مراجع HTTP، نماذج كلمات المرور التي ترسل إلى HTTP، والسكريبتات الخارجية دون SRI.
- تحليل DNS وHTTP status ووجهة التحويل دون اتباعها تلقائياً.
- تصدير تقرير JSON.

## البناء
يعمل GitHub Actions عند الدفع إلى main. افتح Actions ونزّل artifact باسم `nexus-x-ultra-debug-apk`.

## حدود ودقة النتائج
هذه أداة تدقيق سلبي لإعدادات HTTP/TLS وعينة HTML واحدة. لا تنفذ JavaScript ولا تثبت قابلية الاستغلال، ولا تجري استغلالاً أو brute force أو تخمين مسارات أو فحص منافذ أو تدقيقاً شاملاً للتطبيق. تحليل HTML محدود بعينة 512KB، وغياب ترويسة لا يعني وحده وجود ثغرة. لا يمكن ضمان اكتشاف جميع الثغرات بواسطة هذا النوع من الفحص. يجب مراجعة النتائج يدوياً ضمن نطاق تملك تصريحاً بفحصه.
