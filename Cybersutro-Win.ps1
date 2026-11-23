#Requires -Version 5.1
<#
.SYNOPSIS
    Cybersutro win - Herramienta de soporte tecnico para Windows.
.DESCRIPTION
    Lanzador principal. Se auto-eleva como administrador, carga el nucleo y los
    modulos, y abre la interfaz grafica (WPF) o el menu de consola.
.PARAMETER Console
    Abre el menu de consola en lugar de la interfaz grafica.
.PARAMETER QuickRepair
    Ejecuta la reparacion rapida sin menus y genera el informe.
.PARAMETER NoElevate
    No intenta elevar privilegios (algunas acciones fallaran).
.EXAMPLE
    .\Cybersutro-Win.ps1
.EXAMPLE
    .\Cybersutro-Win.ps1 -Console
#>
[CmdletBinding()]
param(
    [switch]$Console,
    [switch]$QuickRepair,
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }

# --- Ejecutable de PowerShell actual (powershell.exe 5.1 o pwsh 7) -----------
$psExe = (Get-Process -Id $PID).Path
if (-not $psExe) { $psExe = 'powershell.exe' }

function Get-RelaunchArgs {
    param([switch]$Sta)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($Sta) { $a += '-STA' }
    $a += @('-File', ('"{0}"' -f $PSCommandPath))
    if ($Console) { $a += '-Console' }
    if ($QuickRepair) { $a += '-QuickRepair' }
    if ($NoElevate) { $a += '-NoElevate' }
    return $a
}

# --- Auto-elevacion ----------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoElevate) {
    Write-Host 'Solicitando permisos de administrador...' -ForegroundColor Yellow
    try {
        Start-Process -FilePath $psExe -ArgumentList (Get-RelaunchArgs -Sta) -Verb RunAs | Out-Null
    }
    catch {
        Write-Host 'Elevacion cancelada. Ejecute de nuevo y acepte el aviso de UAC, o use -NoElevate.' -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
    return
}

# --- La GUI WPF necesita un hilo STA -----------------------------------------
$wantGui = -not $Console -and -not $QuickRepair
if ($wantGui -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process -FilePath $psExe -ArgumentList (Get-RelaunchArgs -Sta) | Out-Null
    return
}

# --- Archivos descargados de Internet: quitar marca de zona -------------------
try { Get-ChildItem -Path $root -Recurse -Include *.ps1, *.psm1 | Unblock-File -ErrorAction SilentlyContinue } catch { }

# --- Carga del nucleo y modulos ----------------------------------------------
try {
    Import-Module (Join-Path $root 'core\CSW.Core.psm1') -Global -Force -DisableNameChecking
    Initialize-CSWCore -RootPath $root
    $failed = @()
    foreach ($m in (Get-ChildItem -Path (Join-Path $root 'modules') -Filter *.psm1 | Sort-Object Name)) {
        try { Import-Module $m.FullName -Global -Force -DisableNameChecking }
        catch { $failed += "$($m.BaseName): $($_.Exception.Message)" }
    }
    foreach ($f in $failed) { Write-CSWLog "No se pudo cargar el modulo $f" -Level Error }
    Write-CSWLog ("Cybersutro win iniciado. {0} modulos cargados. Log: {1}" -f @(Get-CSWModule).Count, $global:CSW.LogFile) -Level Info
}
catch {
    Write-Host "Error critico al cargar Cybersutro win: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'ENTER para salir'
    return
}
$ErrorActionPreference = 'Continue'

# --- Arranque ----------------------------------------------------------------
if ($QuickRepair) {
    $report = Invoke-CSWQuickRepair
    if ($report) { Start-Process $report }
    return
}

if ($Console) {
    . (Join-Path $root 'ui\CSW.Console.ps1')
    Start-CSWConsole
    return
}

try {
    . (Join-Path $root 'ui\CSW.Gui.ps1')
    Start-CSWGui -RootPath $root
}
catch {
    Write-Host "No se pudo abrir la interfaz grafica: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Abriendo modo consola...' -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    . (Join-Path $root 'ui\CSW.Console.ps1')
    Start-CSWConsole
}
