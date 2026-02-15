# 🚀 تشغيل الداش بورد الموحد - SecOps Orchestrator

## نظرة عامة

الداش بورد الموحد يجمع جميع أدوات الأمان في واجهة واحدة شاملة.

## ✅ المودلات المتاحة

عند تشغيل الداش بورد، يتم تفعيل جميع المودلات التالية تلقائياً:

1. **🔍 Subdomain Enumeration** - كشف النطاقات الفرعية
   - Subfinder
   - Amass
   - Assetfinder
   - Sublist3r
   - FFUF

2. **⚡ XSS Detection** - كشف ثغرات XSS
   - توليد خطط الاختبار التلقائية
   - تنفيذ الهجمات والتحليل
   - تقارير مفصلة

3. **🛣️ Path Discovery** - اكتشاف المسارات
   - اكتشاف المسارات المخفية
   - فحص API endpoints
   - تحليل الهيكل

4. **💉 SQL Injection** - كشف ثغرات SQL Injection
   - فحص تلقائي
   - تحليل نقاط الضعف

## 🎯 طرق التشغيل

### الطريقة 1: استخدام PowerShell Script (موصى به)

```powershell
.\start_dashboard.ps1
```

### الطريقة 2: استخدام Python مباشرة

```powershell
python run_dashboard.py
```

### الطريقة 3: تشغيل من مجلد model

```powershell
cd model
python dashboard.py
```

## 📱 الوصول للداش بورد

بعد التشغيل، افتح المتصفح على:

```
http://localhost:5001
```

## 🔧 المميزات

### 1. واجهة موحدة
- جميع الأدوات في مكان واحد
- تبديل سهل بين المودلات المختلفة
- عرض موحد للنتائج

### 2. API متكامل
جميع المودلات متاحة عبر REST API:

```
GET  /api/stats          - إحصائيات النظام
GET  /api/tools          - الأدوات المتاحة
POST /api/scan           - بدء فحص نطاقات فرعية
POST /api/xss/generate-plan - توليد خطة XSS
POST /api/xss/execute-plan  - تنفيذ خطة XSS
POST /api/path/scan      - فحص المسارات
GET  /api/jobs           - قائمة المهام
```

### 3. تشغيل متوازي
- تنفيذ عدة عمليات فحص في نفس الوقت
- متابعة تقدم كل مهمة على حدة
- نتائج فورية

### 4. حفظ النتائج
جميع النتائج يتم حفظها تلقائياً في:
- `results/` - نتائج فحص النطاقات الفرعية
- `xss_results/` - نتائج فحص XSS
- `sqli_results/` - نتائج SQL Injection

## 🛑 إيقاف الداش بورد

### من نفس النافذة:
اضغط `Ctrl + C`

### من نافذة أخرى:
```powershell
.\stop_dashboard.ps1
```

أو:
```powershell
Get-Process python | Stop-Process -Force
```

## 📊 أمثلة الاستخدام

### 1. فحص نطاق فرعي

```bash
# من خلال curl
curl -X POST http://localhost:5001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "tools": ["subfinder", "amass"]}'
```

### 2. اختبار XSS

```bash
# توليد خطة
curl -X POST http://localhost:5001/api/xss/generate-plan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com/search?q=test"}'

# تنفيذ الخطة
curl -X POST http://localhost:5001/api/xss/execute-plan \
  -H "Content-Type: application/json" \
  -d '{"plan_file": "plan_xxx.json"}'
```

### 3. فحص المسارات

```bash
curl -X POST http://localhost:5001/api/path/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com"}'
```

## 🔍 التحقق من الحالة

### التحقق من أن الخادم يعمل:

```powershell
netstat -ano | Select-String "5001"
```

### فحص المودلات النشطة:

```powershell
curl http://localhost:5001/api/tools
```

### عرض الإحصائيات:

```powershell
curl http://localhost:5001/api/stats
```

## ⚙️ الإعدادات

### تغيير البورت

```powershell
python run_dashboard.py --port 8080
```

### تفعيل وضع Debug

```powershell
python run_dashboard.py --debug
```

### تغيير العنوان

```powershell
python run_dashboard.py --host 127.0.0.1 --port 8080
```

## 🐛 استكشاف الأخطاء

### المشكلة: البورت مشغول
```powershell
# إيقاف العمليات القديمة
Get-Process python | Stop-Process -Force
Start-Sleep -Seconds 2
# إعادة التشغيل
.\start_dashboard.ps1
```

### المشكلة: مودل غير متاح
تحقق من الرسائل عند بدء التشغيل:
- ✅ Active = يعمل
- ⚠️ Unavailable = غير متاح (سيستمر الداش بورد بدونه)

### المشكلة: أخطاء UTF-8
يتم تعيين الترميز تلقائياً في السكريبت.

## 📝 ملاحظات

1. **التشغيل للمرة الأولى**: قد يستغرق بضع ثوان لتحميل جميع المودلات

2. **استخدام الذاكرة**: المودلات تستهلك ذاكرة حسب الاستخدام

3. **الأداء**: يمكن تشغيل عدة فحوصات معاً دون مشاكل

4. **الأمان**: الداش بورد مصمم للاستخدام المحلي (localhost)

## 🎓 المزيد من المعلومات

- [DASHBOARD_GUIDE.md](DASHBOARD_GUIDE.md) - دليل مفصل
- [API_EXAMPLES.md](API_EXAMPLES.md) - أمثلة API
- [ARCHITECTURE.md](ARCHITECTURE.md) - معمارية النظام

## 📞 الدعم

إذا واجهت مشاكل:
1. تحقق من ملف [TROUBLESHOOTING_AR.md](TROUBLESHOOTING_AR.md)
2. راجع سجلات الأخطاء في Terminal
3. تأكد من تثبيت جميع المتطلبات

---

**تم التطوير بواسطة:** SecOps Team  
**الإصدار:** 2.0  
**التاريخ:** فبراير 2026
