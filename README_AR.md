# TULIPENI NEXUS X ULTRA — Android Project

## محتويات النسخة
- تطبيق Android أصلي Kotlin مع واجهة HTML5 محلية.
- فحص HTTPS لموقع واحد في كل تشغيل.
- فحص ترويسات HSTS وCSP وX-Content-Type-Options وX-Frame-Options وReferrer-Policy وPermissions-Policy.
- قراءة خصائص Set-Cookie الظاهرة في الاستجابة.
- معلومات جلسة TLS والشهادة عند إتاحتها من Android.
- عرض DNS وHTTP status ودرجة مؤشر أولية.
- تصدير تقرير JSON.
- رفض عناوين IP المحلية والخاصة، ورفض HTTP والمنافذ غير القياسية، وعدم اتباع التحويلات.
- تأكيد من المستخدم بأنه يملك الهدف أو لديه تصريح.

## بناء APK محلياً
1. فك ضغط ZIP.
2. افتح المجلد في Android Studio حديث.
3. استخدم JDK 17، ثم Gradle Sync.
4. اختر Build > Build Bundle(s) / APK(s) > Build APK(s).
5. الناتج: `app/build/outputs/apk/debug/app-debug.apk`.

## بناء APK عبر GitHub Actions
1. ارفع محتويات المشروع إلى مستودع GitHub.
2. افتح تبويب Actions.
3. شغّل `Build Android APK` عبر Run workflow.
4. نزّل artifact باسم `nexus-x-ultra-debug-apk`.

## حدود فنية وأمنية
- هذه حزمة مصدر قابلة للبناء، وليست APK مُجمّعاً أو موقّعاً هنا.
- الفحص تدقيق إعدادات محدود وليس ماسح ثغرات شامل أو اختبار اختراق.
- الدرجة مؤشر مبسط لوجود ستة ترويسات وبعض خصائص الكوكيز؛ لا تعني أن الموقع آمن أو مخترق.
- فحص DNS قبل الاتصال ليس ضماناً كاملاً ضد DNS rebinding؛ استخدمه فقط مع نطاقات تملكها أو لديك تصريح بها.
- لا يُتبع أي Redirect تلقائياً؛ افحص الوجهة يدوياً بعد التحقق من نطاقها وتصريحها.
- لا يحتوي التطبيق على استغلال ثغرات أو brute force أو تخمين مسارات أو مسح شبكات.
