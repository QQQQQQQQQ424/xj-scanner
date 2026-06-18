# ==============================================
# 黑盒漏洞巡检扫描器 - 工具下载脚本 (Windows PowerShell)
# 用法: 右键 -> 使用 PowerShell 运行
#      或在终端: powershell -ExecutionPolicy Bypass -File download_tools.ps1
# ==============================================

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$NmapDir    = Join-Path $ScriptDir "nmap"
$NucleiDir  = Join-Path $ScriptDir "nuclei"
$TemplatesDir = Join-Path $ScriptDir "nuclei-templates"

Write-Host "========================================="  -ForegroundColor Cyan
Write-Host " BlackBox Scanner - 工具下载 (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# ---------- 1. Nmap ----------
Write-Host "[1/3] Nmap..." -ForegroundColor Yellow

$nmap_exe = Join-Path $NmapDir "nmap.exe"
if (Test-Path $nmap_exe) {
    Write-Host "  已存在: $nmap_exe"
} else {
    # 检查系统是否已安装 nmap
    $system_nmap = (Get-Command nmap -ErrorAction SilentlyContinue).Source
    if ($system_nmap) {
        New-Item -ItemType Directory -Force -Path $NmapDir | Out-Null
        Copy-Item $system_nmap $nmap_exe
        Write-Host "  -> 已从系统路径复制: $system_nmap"
    } else {
        Write-Host "  系统未安装 nmap，请手动安装:"
        Write-Host "    https://nmap.org/download.html"
        Write-Host "    下载 Windows 安装包，安装后将 nmap.exe 复制到: $NmapDir"
    }
}

# ---------- 2. Nuclei ----------
Write-Host "[2/3] Nuclei..." -ForegroundColor Yellow

$nuclei_exe = Join-Path $NucleiDir "nuclei.exe"
if (Test-Path $nuclei_exe) {
    Write-Host "  已存在: $nuclei_exe"
} else {
    $nuclei_version = "3.3.9"
    $nuclei_url = "https://github.com/projectdiscovery/nuclei/releases/download/v${nuclei_version}/nuclei_${nuclei_version}_windows_amd64.zip"
    $nuclei_zip = Join-Path $ScriptDir "nuclei.zip"

    Write-Host "  下载 $nuclei_url ..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nuclei_url -OutFile $nuclei_zip -UseBasicParsing
        New-Item -ItemType Directory -Force -Path $NucleiDir | Out-Null
        Expand-Archive -Path $nuclei_zip -DestinationPath $NucleiDir -Force
        Remove-Item $nuclei_zip -Force
        Write-Host "  -> 下载完成: $nuclei_exe"
    } catch {
        Write-Host "  [WARN] 下载失败，请手动下载并放到: $NucleiDir"
        Write-Host "         下载地址: $nuclei_url"
    }
}

# ---------- 3. Nuclei Templates ----------
Write-Host "[3/3] Nuclei 官方模板库..." -ForegroundColor Yellow

if (Test-Path (Join-Path $TemplatesDir ".git")) {
    Write-Host "  模板库已存在，尝试更新..."
    Push-Location $TemplatesDir
    git pull --depth=1 2>$null
    Pop-Location
} else {
    Write-Host "  git clone https://github.com/projectdiscovery/nuclei-templates.git ..."
    try {
        git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git $TemplatesDir 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw
        }
    } catch {
        Write-Host "  [WARN] 模板下载失败，扫描时将仅使用自定义插件"
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " 工具准备完成！" -ForegroundColor Green
Write-Host " nmap:          $nmap_exe"
Write-Host " nuclei:        $nuclei_exe"
Write-Host " templates:     $TemplatesDir"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "按任意键退出..." 
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
