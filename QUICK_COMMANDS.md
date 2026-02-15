# 🎯 أوامر سريعة - Quick Commands Reference

## تشغيل الداش بورد | Start Dashboard

```powershell
# الطريقة الموصى بها | Recommended
.\start_dashboard.ps1

# مباشرة | Direct
python run_dashboard.py

# بخيارات مخصصة | With options
python run_dashboard.py --port 8080 --debug
```

## إيقاف الداش بورد | Stop Dashboard

```powershell
# سكريبت الإيقاف | Stop script
.\stop_dashboard.ps1

# يدوياً | Manual
Get-Process python | Stop-Process -Force
```

## التحقق من الحالة | Check Status

```powershell
# فحص البورت | Check port
netstat -ano | Select-String "5001"

# حالة النظام | System status
curl http://localhost:5001/api/stats

# الأدوات المتاحة | Available tools
curl http://localhost:5001/api/tools

# المهام النشطة | Active jobs
curl http://localhost:5001/api/jobs
```

## أمثلة API | API Examples

### 1. فحص نطاق فرعي | Subdomain Scan

```powershell
# بدء الفحص | Start scan
$body = @{
    domain = "example.com"
    tools = @("subfinder", "amass")
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5001/api/scan" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

### 2. اختبار XSS | XSS Test

```powershell
# توليد خطة | Generate plan
$body = @{
    target_url = "http://testphp.vulnweb.com/search.php?test=query"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "http://localhost:5001/api/xss/generate-plan" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body

# تنفيذ الخطة | Execute plan
$planFile = ($response.Content | ConvertFrom-Json).plan_file

$execBody = @{
    plan_file = $planFile
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5001/api/xss/execute-plan" `
    -Method POST `
    -ContentType "application/json" `
    -Body $execBody
```

### 3. فحص المسارات | Path Discovery

```powershell
$body = @{
    target_url = "http://example.com"
    wordlist = "common.txt"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5001/api/path/scan" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

### 4. متابعة مهمة | Track Job

```powershell
# استبدل JOB_ID بمعرف المهمة | Replace JOB_ID with job ID
$jobId = "abc-123"

# حالة المهمة | Job status
curl "http://localhost:5001/api/scan/$jobId"

# النتائج | Results
curl "http://localhost:5001/api/scan/$jobId/results"
```

## روابط سريعة | Quick Links

| الصفحة | الرابط | الوصف |
|--------|--------|-------|
| الرئيسية | http://localhost:5001 | الواجهة الرئيسية |
| API Stats | http://localhost:5001/api/stats | إحصائيات |
| Tools | http://localhost:5001/api/tools | الأدوات |
| Jobs | http://localhost:5001/api/jobs | المهام |
| Reports | http://localhost:5001/api/reports | التقارير |

## استكشاف الأخطاء | Troubleshooting

### البورت مشغول | Port in use
```powershell
Get-Process python | Stop-Process -Force
Start-Sleep -Seconds 2
.\start_dashboard.ps1
```

### مسح النتائج القديمة | Clear old results
```powershell
Remove-Item results\*.json
Remove-Item xss_results\*.json
```

### إعادة تثبيت المتطلبات | Reinstall dependencies
```powershell
cd model
pip install -r requirements.txt
pip install -r requirements_api.txt
```

## متغيرات البيئة | Environment Variables

```powershell
# تعيين الترميز | Set encoding
$env:PYTHONIOENCODING = "utf-8"

# تعيين البورت | Set port
$env:DASHBOARD_PORT = "5001"

# تفعيل Debug | Enable debug
$env:FLASK_DEBUG = "1"
```

## الاختصارات المفيدة | Useful Shortcuts

```powershell
# فتح الداش بورد في المتصفح | Open in browser
Start-Process "http://localhost:5001"

# عرض السجلات | View logs
cd model
Get-Content dashboard.log -Tail 20 -Wait

# فحص سريع | Quick scan
curl -X POST http://localhost:5001/api/scan `
    -H "Content-Type: application/json" `
    -d '{"domain":"example.com","tools":["subfinder"]}'
```

## الملفات المهمة | Important Files

| الملف | الوصف |
|-------|-------|
| `run_dashboard.py` | مشغل الداش بورد الرئيسي |
| `start_dashboard.ps1` | سكريبت تشغيل PowerShell |
| `stop_dashboard.ps1` | سكريبت إيقاف |
| `model/dashboard.py` | كود الداش بورد الرئيسي |
| `model/config.json` | إعدادات المودلات |
| `model/xss_config.json` | إعدادات XSS |
| `web/web_interface.html` | الواجهة الويب |

## نصائح | Tips

1. **استخدم السكريبت دائماً** - `start_dashboard.ps1` يعد البيئة تلقائياً
2. **تابع السجلات** - راقب رسائل Terminal لمعرفة الحالة
3. **النسخ الاحتياطي** - احفظ نتائجك المهمة من مجلد `results/`
4. **الأداء** - أغلق المهام القديمة لتحرير الذاكرة
5. **الأمان** - لا تعرض الداش بورد للإنترنت مباشرة

---

**نسخة سريعة** | **Quick Reference** v2.0
