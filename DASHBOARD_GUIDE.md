# 🚀 SecOps Orchestrator - Dashboard Guide

## نظرة عامة
داش بورد احترافي وديناميكي متكامل مع محركات فحص الثغرات. يوفر واجهة موحدة لإدارة عمليات:
- **Subdomain Enumeration** - فحص النطاقات الفرعية
- **Path Discovery** - اكتشاف المسارات والثغرات

---

## ✨ المميزات الجديدة

### 🎯 ربط حقيقي مع APIs
- اتصال كامل مع محركات الفحص الخلفية
- مراقبة حالة الفحوصات في الوقت الفعلي (Real-time polling)
- عرض النتائج الحقيقية من قواعد البيانات

### 📊 إحصائيات ديناميكية
- عداد إجمالي الفحوصات
- عداد الفحوصات النشطة
- إجمالي النطاقات المكتشفة
- رسم بياني للنشاط خلال آخر 7 أيام

### 💾 تصدير النتائج
- تحميل النتائج بصيغة JSON
- زر Export لكل قسم
- حفظ تلقائي للنتائج

### 🔍 بحث وتصفية
- بحث فوري في النتائج
- تصفية ديناميكية للجداول
- واجهة سريعة الاستجابة

### 🎨 واجهة محسنة
- تصميم احترافي ونظيف
- رسائل تنبيه واضحة
- مؤشرات تحميل متقدمة
- Animations سلسة

---

## 🏃 طريقة التشغيل

### الخطوة 1: تشغيل Subdomain Scanner API
```powershell
cd model
python web_server.py --port 5000
```

الخادم سيعمل على: `http://localhost:5000`

### الخطوة 2: تشغيل Path Discovery API
```powershell
cd path_discovery\model
python web_server.py --port 5001
```

الخادم سيعمل على: `http://localhost:5001`

### الخطوة 3: فتح الداش بورد
افتح أي من الرابطين:
- `http://localhost:5000` - من خادم Subdomain Scanner
- `http://localhost:5001` - من خادم Path Discovery
- أو افتح الملف مباشرة: `web/web_interface.html`

**ملاحظة**: يُفضل فتح Dashboard من أحد الخوادم لتجنب مشاكل CORS.

---

## 📡 API Endpoints المتاحة

### Subdomain Scanner (`http://localhost:5000/api`)

#### POST `/api/scan`
بدء فحص جديد للنطاقات الفرعية
```json
{
  "domain": "example.com",
  "tools": ["subfinder", "amass", "assetfinder"],
  "parallel": true,
  "validate_dns": true
}
```

#### GET `/api/scan/{job_id}`
الحصول على حالة الفحص

#### GET `/api/scan/{job_id}/results`
الحصول على نتائج الفحص المكتمل

#### GET `/api/stats`
إحصائيات النظام

#### GET `/api/jobs`
قائمة جميع الفحوصات

#### GET `/api/results`
قائمة ملفات النتائج المحفوظة

### Path Discovery (`http://localhost:5001/api`)
نفس APIs أعلاه لكن للـ path discovery مع:
- `url` بدلاً من `domain`
- tools: `["ffuf", "dirsearch", "arjun", "paramspider"]`

---

## 🎯 كيفية الاستخدام

### 1. فحص النطاقات الفرعية
1. انتقل إلى تبويب **Subdomain Scanner**
2. أدخل النطاق المستهدف (مثل: `example.com`)
3. اختر الأدوات المطلوبة:
   - ✅ Subfinder (سريع وموثوق)
   - ✅ Amass (شامل ودقيق)
   - ✅ Assetfinder (بديل خفيف)
   - Sublist3r (قد يكون بطيء)
4. اضغط **Start Subdomain Scan**
5. انتظر حتى اكتمال الفحص (سيتم التحديث تلقائياً)
6. النتائج ستظهر في جدول تفاعلي مع:
   - أسماء النطاقات الفرعية
   - مستوى الأولوية (High/Medium/Low)
   - عناوين IP
   - الحالة (Active/Inactive)

#### مميزات إضافية:
- 🔍 **بحث**: استخدم صندوق البحث للتصفية
- 💾 **تصدير**: احفظ النتائج بصيغة JSON
- 🗑️ **مسح**: امسح النتائج الحالية

### 2. اكتشاف المسارات
1. انتقل إلى تبويب **Path Discovery**
2. أدخل URL الهدف (مثل: `https://example.com`)
3. اختر أدوات الاكتشاف:
   - ✅ FFUF (سريع للغاية)
   - ✅ Dirsearch (متوازن)
   - Arjun (لاكتشاف Parameters)
   - ✅ ParamSpider (للـ URLs المخفية)
4. اضغط **Launch Path Discovery**
5. النتائج ستظهر مع:
   - المسار المكتشف
   - Status Code
   - HTTP Method
   - الأداة المستخدمة

### 3. لوحة التحكم الرئيسية
- **Total Scans Today**: إجمالي الفحوصات اليوم
- **High Severity**: الفحوصات النشطة حالياً
- **Subdomains Found**: إجمالي النطاقات المكتشفة
- **Activity Trend**: رسم بياني يوضح النشاط الأسبوعي

---

## 🔧 الإعدادات

### تخصيص منافذ الشبكة
يمكنك تغيير المنافذ عند التشغيل:
```powershell
python web_server.py --port 8080 --host 127.0.0.1
```

### تفعيل Debug Mode
```powershell
python web_server.py --debug
```

---

## 🛠️ حل المشاكل الشائعة

### مشكلة: CORS Error
**الحل**: استخدم الداش بورد من خلال أحد الخوادم (`http://localhost:5000`) وليس بفتح الملف مباشرة.

### مشكلة: لا توجد نتائج
**الأسباب المحتملة**:
1. الخادم غير مشغل - تأكد من تشغيل API servers
2. الأدوات غير مثبتة - راجع `QUICKSTART.md`
3. مشكلة في الشبكة - تحقق من الاتصال بالإنترنت

### مشكلة: الفحص عالق
- انتظر حتى 10 دقائق (timeout)
- تحقق من logs الخادم في Terminal
- حاول مرة أخرى مع أدوات أقل

### مشكلة: Dashboard Stats فارغة
- تأكد من أن كلا الخادمين يعملان
- قم بإجراء فحص واحد على الأقل
- انتقل لتبويب Dashboard وسينعش تلقائياً

---

## 📁 هيكل الملفات

```
vuln_Scanner/
├── model/                    # Subdomain Scanner
│   ├── web_server.py        # API Server (Port 5000)
│   ├── orchestrator.py      # التنسيق بين الأدوات
│   ├── results/             # ملفات النتائج
│   └── config.json          # الإعدادات
│
├── path_discovery/          # Path Discovery
│   └── model/
│       ├── web_server.py    # API Server (Port 5001)
│       ├── orchestrator.py
│       └── results/
│
└── web/                     # Dashboard Files
    ├── web_interface.html   # الواجهة الرئيسية
    ├── main.css            # التصميم
    └── main.js             # المنطق والربط مع APIs
```

---

## 🔐 ملاحظات أمنية

⚠️ **تحذير هام**: 
- استخدم فقط على نطاقات تملكها أو لديك تصريح باختبارها
- لا تستخدم على نطاقات الإنتاج مباشرة
- احفظ النتائج بشكل آمن (تحتوي على معلومات حساسة)
- لا تشارك النتائج مع أطراف غير موثوقة

---

## 🎨 التخصيص

### تغيير الألوان
عدل متغيرات CSS في `web/main.css`:
```css
:root {
  --primary: #4f46e5;      /* اللون الأساسي */
  --secondary: #ec4899;    /* اللون الثانوي */
  --bg-dark: #0f172a;      /* خلفية Sidebar */
}
```

### إضافة أدوات جديدة
1. أضف الأداة في `config.json`
2. أضف checkbox في HTML
3. سيتم اكتشافها تلقائياً

---

## 📈 تحسينات مستقبلية

- [ ] إضافة WebSocket للتحديثات الفورية
- [ ] دعم تصدير PDF/HTML
- [ ] مقارنة بين نتائج الفحوصات المختلفة
- [ ] نظام إشعارات متقدم
- [ ] Dark Mode
- [ ] Multi-language support

---

## 📞 الدعم

إذا واجهت أي مشكلة:
1. راجع ملف `TROUBLESHOOTING_AR.md`
2. تحقق من logs الخوادم
3. تأكد من تثبيت جميع المتطلبات

---

## 📝 Changelog

### v2.0.0 (2026-02-13)
- ✅ ربط كامل مع Backend APIs
- ✅ إحصائيات ديناميكية في الوقت الفعلي
- ✅ تصدير النتائج
- ✅ بحث وتصفية
- ✅ تحسينات UI/UX شاملة
- ✅ Notifications system
- ✅ Auto-refresh dashboard
- ✅ Responsive design improvements

---

**تم التطوير بواسطة**: SecOps Pro Team  
**الإصدار**: 2.4.0 Professional Edition  
**التاريخ**: فبراير 2026

---

🎉 **استمتع بالفحص!**
