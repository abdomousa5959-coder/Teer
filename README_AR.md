# NEXUS X ULTRA — Android Passive Web Security Audit

## الإصدار 4.1
- إصلاح خطأ JavaScript كان يمنع واجهة الفحص من إرسال واستقبال النتائج.
- إضافة مهلة اتصال ورسائل خطأ واضحة في الواجهة.
- تدقيق سلبي لإعدادات HTTPS/TLS وHSTS وCSP وCookies وCross-Origin.
- تحليل محدود لعينة الاستجابة لرصد مؤشرات أخطاء SQL وPHP وStack traces.
- تحليل مستندات XML لرصد DOCTYPE وexternal entity declarations.
- رصد مراجع HTTP ونماذج كلمات المرور التي ترسل إلى HTTP والسكريبتات الخارجية دون SRI.
- تحليل شهادة TLS وSAN وصلاحيتها ومفتاحها وخوارزمية التوقيع.
- تصدير تقرير JSON.

## حدود مهمة
لا يرسل البرنامج SQL injection أو XXE payloads، ولا يستغل ثغرات ولا يجرب كلمات مرور ولا يخمن مسارات. رصد رسائل أخطاء SQL لا يثبت SQL injection، ووجود XML DOCTYPE/ENTITY لا يثبت XXE؛ يتطلب ذلك مراجعة التطبيق الذي يعالج XML. لا يستطيع فحص صفحة واحدة اكتشاف كل ثغرات PHP أو SQL أو التطبيق. يجب إجراء أي اختبار أعمق فقط على أنظمة تملكها أو لديك تصريح صريح بفحصها.

## البناء
افتح GitHub Actions ونزّل artifact باسم `nexus-x-ultra-debug-apk` بعد نجاح البناء.
