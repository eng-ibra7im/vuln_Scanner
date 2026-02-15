# حل مشكلة عدم وجود نتائج من الأدوات

## المشكلة ❌
الأدوات Subfinder, Amass, Assetfinder غير مثبتة على النظام

## الحلول المتاحة ✅

### 1️⃣ **الحل الأفضل: تثبيت الأدوات الحقيقية**

#### المتطلبات الأساسية:
1. تثبيت **Go Language** أولاً:
   - تحميل من: https://golang.org/dl/
   - اختر: `go1.22.windows-amd64.msi` (أو أحدث نسخة)
   - قم بالتثبيت واتبع الخطوات

2. أعد تشغيل PowerShell بعد تثبيت Go

3. تأكد من تثبيت Go:
```powershell
go version
```

#### تشغيل سكريبت التثبيت:
```powershell
# افتح PowerShell كمسؤول (Run as Administrator)
cd D:\vuln_Scanner

# شغل سكريبت التثبيت
.\install_tools.ps1

# بعد الانتهاء، أعد تشغيل PowerShell
# أو شغل هذا الأمر:
$env:PATH += ";$env:USERPROFILE\go\bin"

# تأكد من التثبيت:
subfinder -version
amass version
assetfinder -h
```

#### تشغيل النظام:
```powershell
cd model
python web_server.py
```
افتح المتصفح: http://localhost:5000

---

### 2️⃣ **الحل السريع: استخدام API Mode** ⚡

النظام الآن يستخدم APIs مجانية تلقائياً إذا لم تكن الأدوات مثبتة!

#### مصادر البيانات المستخدمة:
- ✅ **crt.sh** - Certificate Transparency Logs
- ✅ **HackerTarget** - Host Search API
- ✅ **ThreatCrowd** - Threat Intelligence
- ✅ **DNS Brute Force** - Common subdomains

#### التشغيل:
```powershell
cd model

# الطريقة 1: عبر الواجهة
python web_server.py
# افتح: http://localhost:5000

# الطريقة 2: مباشرة عبر Terminal
python api_finder.py example.com
```

#### مميزات API Mode:
- ✅ لا يحتاج تثبيت أي أدوات
- ✅ يعمل مباشرة
- ✅ سريع (10-30 ثانية)
- ⚠️ نتائج أقل من الأدوات الكاملة

---

### 3️⃣ **الحل المؤقت: بيانات تجريبية** 🧪

#### اختبار سريع للنظام:
```powershell
cd model
python cli.py --demo
```

سيُنشئ بيانات تجريبية لاختبار التقارير والواجهة.

---

## التحقق من الإعدادات ⚙️

### ملف config.json:
```json
{
  "use_api_fallback": true,  // ✅ تفعيل API Mode
  "tools": {
    "subfinder": {
      "enabled": true  // سيستخدم API إذا لم يكن مثبت
    }
  }
}
```

---

## اختبار الحل 🧪

### اختبار API Mode:
```powershell
cd model

# اختبر مع نطاق حقيقي
python api_finder.py google.com

# يجب أن ترى:
# 🔍 Searching for subdomains of google.com...
#   [1/4] Checking crt.sh...
#   [2/4] Checking HackerTarget...
#   ...
# ✓ Found 50+ unique subdomains
```

### اختبار عبر الواجهة:
```powershell
cd model
python web_server.py
```

1. افتح: http://localhost:5000
2. أدخل نطاق: `google.com`
3. اختر الأدوات المطلوبة
4. اضغط Start Scan
5. انتظر النتائج (30-60 ثانية)

---

## استكشاف الأخطاء 🔧

### خطأ: "Tool not found"
```
✅ الحل: النظام يستخدم API Mode تلقائياً
✅ أو: شغل install_tools.ps1 لتثبيت الأدوات
```

### خطأ: "No results"
```
✅ تحقق من الاتصال بالإنترنت
✅ جرب نطاق مشهور: google.com, facebook.com
✅ تأكد من: "use_api_fallback": true في config.json
```

### خطأ: "Go not found"
```
✅ ثبت Go من: https://golang.org/dl/
✅ أعد تشغيل PowerShell
✅ تأكد: go version
```

---

## المقارنة بين الحلول 📊

| الميزة | الأدوات الحقيقية | API Mode |
|--------|------------------|----------|
| التثبيت | يحتاج Go + tools | لا يحتاج شيء ✅ |
| السرعة | سريع جداً ⚡ | متوسط ⏱️ |
| عدد النتائج | كثيرة جداً 🚀 | جيدة ✅ |
| الدقة | عالية جداً ⭐⭐⭐ | جيدة ⭐⭐ |
| الإنترنت | اختياري | مطلوب 🌐 |

---

## الخلاصة 🎯

**الحل السريع اليوم:**
```powershell
cd model
python web_server.py
```
النظام سيعمل بـ API Mode تلقائياً!

**للحصول على أفضل نتائج:**
1. ثبت Go Language
2. شغل `install_tools.ps1`
3. أعد تشغيل PowerShell
4. شغل النظام مرة أخرى

---

## الدعم 💬

إذا واجهت أي مشكلة:
1. تأكد من `use_api_fallback: true` في config.json
2. جرب: `python api_finder.py google.com`
3. تحقق من logs في Terminal
