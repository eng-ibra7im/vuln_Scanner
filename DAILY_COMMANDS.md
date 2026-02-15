# 🎯 الأوامر اليومية - Daily Commands

## تشغيل سريع | Quick Start

```powershell
# شغل الداش بورد
.\start_dashboard.ps1
```

افتح المتصفح: http://localhost:5001

## إيقاف | Stop

```powershell
# اضغط في نافذة الداش بورد
Ctrl + C

# أو من نافذة أخرى
.\stop_dashboard.ps1
```

## فحص الحالة | Check Status

```powershell
# هل الداش بورد يعمل؟
netstat -ano | Select-String "5001"

# معلومات النظام
curl http://localhost:5001/api/stats

# الأدوات المتاحة
curl http://localhost:5001/api/tools
```

## أمثلة سريعة | Quick Examples

### 1. فحص نطاق | Scan Domain

```powershell
# PowerShell
$body = @{domain="example.com"; tools=@("subfinder")} | ConvertTo-Json
Invoke-WebRequest -Uri "http://localhost:5001/api/scan" -Method POST -ContentType "application/json" -Body $body
```

### 2. اختبار XSS | Test XSS

```powershell
# توليد خطة
$body = @{target_url="http://testphp.vulnweb.com/search.php?test=query"} | ConvertTo-Json
Invoke-WebRequest -Uri "http://localhost:5001/api/xss/generate-plan" -Method POST -ContentType "application/json" -Body $body
```

## روابط مهمة | Important Links

- 📖 [الدليل الكامل](DASHBOARD_START_AR.md)
- 🚀 [Quick Start](UNIFIED_DASHBOARD.md)
- ⚡ [جميع الأوامر](QUICK_COMMANDS.md)

---

**نسخة مختصرة للاستخدام اليومي**
