# Script to install subdomain enumeration tools on Windows
# Run as Administrator

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Installing Subdomain Tools" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Check if Go is installed
Write-Host "[1/5] Checking Go installation..." -ForegroundColor Yellow
try {
    $goVersion = go version
    Write-Host "✓ Go is installed: $goVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Go is not installed!" -ForegroundColor Red
    Write-Host "Please install Go from: https://golang.org/dl/" -ForegroundColor Yellow
    Write-Host "After installing Go, run this script again.`n"
    exit 1
}

# Set Go environment
$env:GO111MODULE = "on"
$goPath = $env:GOPATH
if (-not $goPath) {
    $goPath = "$env:USERPROFILE\go"
}
$goBin = "$goPath\bin"

Write-Host "`nGo bin path: $goBin`n" -ForegroundColor Cyan

# Install Subfinder
Write-Host "[2/5] Installing Subfinder..." -ForegroundColor Yellow
try {
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    if (Test-Path "$goBin\subfinder.exe") {
        Write-Host "✓ Subfinder installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Subfinder installation failed" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error installing Subfinder: $_" -ForegroundColor Red
}

# Install Amass
Write-Host "`n[3/5] Installing Amass..." -ForegroundColor Yellow
try {
    go install -v github.com/owasp-amass/amass/v4/...@master
    if (Test-Path "$goBin\amass.exe") {
        Write-Host "✓ Amass installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Amass installation failed" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error installing Amass: $_" -ForegroundColor Red
}

# Install Assetfinder
Write-Host "`n[4/5] Installing Assetfinder..." -ForegroundColor Yellow
try {
    go install -v github.com/tomnomnom/assetfinder@latest
    if (Test-Path "$goBin\assetfinder.exe") {
        Write-Host "✓ Assetfinder installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Assetfinder installation failed" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error installing Assetfinder: $_" -ForegroundColor Red
}

# Check PATH
Write-Host "`n[5/5] Checking PATH configuration..." -ForegroundColor Yellow
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$goBin*") {
    Write-Host "⚠ Adding Go bin to PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$goBin", "User")
    Write-Host "✓ PATH updated. Please restart your terminal." -ForegroundColor Green
    Write-Host "  Or run: `$env:PATH += `";$goBin`"" -ForegroundColor Cyan
} else {
    Write-Host "✓ Go bin is already in PATH" -ForegroundColor Green
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$tools = @(
    @{Name="subfinder"; Path="$goBin\subfinder.exe"},
    @{Name="amass"; Path="$goBin\amass.exe"},
    @{Name="assetfinder"; Path="$goBin\assetfinder.exe"}
)

foreach ($tool in $tools) {
    if (Test-Path $tool.Path) {
        Write-Host "✓ $($tool.Name)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($tool.Name)" -ForegroundColor Red
    }
}

Write-Host "`n📌 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Restart your PowerShell terminal" -ForegroundColor White
Write-Host "2. Or run: `$env:PATH += `";$goBin`"" -ForegroundColor White
Write-Host "3. Test with: subfinder -version" -ForegroundColor White
Write-Host "4. Run your scans from: cd model; python web_server.py`n" -ForegroundColor White
