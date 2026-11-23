#Requires -Version 5.1
<#
    Cybersutro win - Modulo de Reparacion (Repair)
    SFC, DISM, CHKDSK, Windows Update, puntos de restauracion, arranque (solo lectura),
    caches de iconos, Microsoft Store, indice de busqueda, hora y reinicio pendiente.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------
function Get-CSWRepairSysDir {
    # En un proceso de 32 bits sobre Windows de 64 bits, System32 se redirige: usar Sysnative
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $nat = Join-Path $env:windir 'Sysnative'
        if (Test-Path -LiteralPath $nat) { return $nat }
    }
    return (Join-Path $env:windir 'System32')
}

function Get-CSWRepairSysExe {
    param([Parameter(Mandatory)][string]$Name)
    $p = Join-Path (Get-CSWRepairSysDir) $Name
    if (Test-Path -LiteralPath $p) { return $p }
    return $Name
}

function ConvertTo-CSWRepairBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ([string]$Value -match '^\s*(1|true|\$true|s|si|y|yes|on)\s*$')
}

function ConvertTo-CSWRepairDrive {
    param([string]$Drive)
    if (-not $Drive) { $Drive = $env:SystemDrive }
    $d = $Drive.Trim().TrimEnd('\').TrimEnd(':')
    if ($d -notmatch '^[A-Za-z]$') { return $null }
    return ($d.ToUpper() + ':')
}

function Test-CSWRepairElevation {
    # Devuelve $null si hay permisos; si no, registra el error y devuelve el resultado a retornar
    param([string]$What)
    if (Test-CSWAdmin) { return $null }
    return (New-CSWAdminRequiredResult $What)
}

function Invoke-CSWRepairExternalCapture {
    <# Ejecuta con Invoke-CSWExternal (salida en vivo al log) y devuelve tambien el texto capturado. #>
    param([Parameter(Mandatory)][string]$FilePath, [string]$Arguments = '', [switch]$Unicode, [int]$TimeoutSeconds = 0)
    $s = Get-CSWState
    $from = $s.LogLines.Count
    $code = Invoke-CSWExternal -FilePath $FilePath -Arguments $Arguments -Unicode:$Unicode -TimeoutSeconds $TimeoutSeconds
    $lines = New-Object System.Collections.Generic.List[string]
    $to = $s.LogLines.Count
    for ($i = $from; $i -lt $to; $i++) {
        try { $lines.Add([string]$s.LogLines[$i].Message) } catch { }
    }
    return [pscustomobject]@{ ExitCode = $code; Lines = $lines.ToArray(); Text = ($lines -join "`n") }
}

function Get-CSWRepairHex {
    param([int]$Code)
    return ('0x{0}' -f $Code.ToString('X8'))
}

function Get-CSWRepairDismErrorText {
    param([int]$Code)
    switch ($Code) {
        0           { return 'Correcto' }
        3010        { return 'Correcto; requiere reinicio' }
        87          { return 'Parametro no valido (version de DISM incompatible)' }
        740         { return 'Se requieren permisos de administrador' }
        1726        { return 'Fallo de RPC: otro proceso de mantenimiento esta en curso; reinicie y repita' }
        -2146498529 { return 'No se encontraron los archivos de origen (0x800F081F): use una ISO de la misma version como Source' }
        -2146498298 { return 'No se pudieron descargar los archivos de origen (0x800F0906): revise Internet o Windows Update' }
        -2146498297 { return 'Una directiva impide descargar el origen (0x800F0907)' }
        -2146498554 { return 'El almacen de componentes no se puede reparar (0x800F0806)' }
        -2146498530 { return 'Version de origen no coincide (0x800F081E)' }
        default     { return ('Codigo {0}' -f (Get-CSWRepairHex $Code)) }
    }
}

function Get-CSWRepairDismHealth {
    param([string]$Text)
    if ($Text -match 'not repairable|no se puede reparar|no es reparable') { return 'NotRepairable' }
    if ($Text -match 'is repairable|se puede reparar|es reparable') { return 'Repairable' }
    if ($Text -match 'No component store corruption detected|No se detectaron da.os|No se detect') { return 'Healthy' }
    return 'Unknown'
}

function Get-CSWRepairFreeBytes {
    param([string]$Drive = $env:SystemDrive)
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction Stop
        if ($ld) { return [int64]$ld.FreeSpace }
    }
    catch { }
    return [int64]-1
}

function Get-CSWRepairCbsSrLines {
    <# Extrae lineas [SR] relevantes de CBS.log posteriores a $Since (lee solo el final del archivo). #>
    param([datetime]$Since, [int]$Max = 80)
    $path = Join-Path $env:windir 'Logs\CBS\CBS.log'
    $result = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $path)) { return , $result.ToArray() }
    $content = ''
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        try {
            $maxBytes = 24MB
            if ($fs.Length -gt $maxBytes) { [void]$fs.Seek(-$maxBytes, [System.IO.SeekOrigin]::End) }
            $rd = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::Default)
            $content = $rd.ReadToEnd()
            $rd.Dispose()
        }
        finally { $fs.Dispose() }
    }
    catch {
        Write-CSWLog "No se pudo leer CBS.log: $($_.Exception.Message)" -Level Warn
        return , $result.ToArray()
    }
    $limit = $Since.AddMinutes(-1)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($l in ($content -split "`r?`n")) {
        if ($l.IndexOf('[SR]') -lt 0) { continue }
        if ($l.Length -ge 19) {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParseExact($l.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
                if ($dt -lt $limit) { continue }
            }
        }
        if ($l -match 'Cannot repair|Repairing corrupted|Repaired file|corrupt|Verify complete|Repair complete|could not|Could not') {
            $result.Add($l.Trim())
        }
    }
    if ($result.Count -gt $Max) {
        $tail = $result.GetRange($result.Count - $Max, $Max)
        return , $tail.ToArray()
    }
    return , $result.ToArray()
}

function Stop-CSWRepairService {
    <# Detiene un servicio con tiempo limite. Devuelve Missing / Stopped / Running. #>
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 45)
    $sc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $sc) { return 'Missing' }
    if ($sc.Status -eq 'Stopped') { return 'Stopped' }
    try {
        foreach ($dep in @($sc.DependentServices)) {
            if ($dep.Status -ne 'Stopped') {
                Write-CSWLog "Deteniendo servicio dependiente $($dep.Name)..." -Level Info
                try { $dep.Stop() } catch { }
                try { $dep.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20)) } catch { }
            }
        }
    }
    catch { }
    try { $sc.Stop() } catch { Write-CSWLog "Aviso al detener ${Name}: $($_.Exception.Message)" -Level Warn }
    try { $sc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSec)); return 'Stopped' } catch { }
    # Ultimo recurso: si el servicio corre en su propio proceso, finalizarlo
    try {
        $w = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
        if ($w -and $w.ProcessId -gt 0) {
            $shared = @(Get-CimInstance Win32_Service -Filter ("ProcessId={0}" -f $w.ProcessId) -ErrorAction Stop)
            if ($shared.Count -eq 1) {
                Write-CSWLog "Forzando cierre del proceso de $Name (PID $($w.ProcessId))..." -Level Warn
                Stop-Process -Id $w.ProcessId -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
        }
    }
    catch { }
    $sc.Refresh()
    if ($sc.Status -eq 'Stopped') { return 'Stopped' }
    return 'Running'
}

function Start-CSWRepairService {
    <# Inicia un servicio. Devuelve Missing / Disabled / Running / Failed. #>
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 30)
    $sc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $sc) { return 'Missing' }
    if ($sc.Status -eq 'Running') { return 'Running' }
    try { if ([string]$sc.StartType -eq 'Disabled') { return 'Disabled' } } catch { }
    try {
        $sc.Start()
        $sc.WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSec))
        return 'Running'
    }
    catch {
        Write-CSWLog "No se pudo iniciar ${Name}: $($_.Exception.Message)" -Level Warn
        return 'Failed'
    }
}

function Get-CSWRepairServiceStartType {
    param([string]$Name)
    try {
        $w = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
        if ($w) { return [string]$w.StartMode }
    }
    catch { }
    return ''
}

function Import-CSWRepairAppx {
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) { return $true }
    try { Import-Module Appx -ErrorAction Stop; return $true } catch { }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        try { Import-Module Appx -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue; return $true } catch { }
    }
    return $false
}

function Get-CSWRepairFirmwareType {
    # GetFirmwareType (Windows 8+): 1 = BIOS, 2 = UEFI
    try {
        if (-not ('CybersutroWin.FirmwareInfo' -as [type])) {
            Add-Type -Namespace 'CybersutroWin' -Name 'FirmwareInfo' -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetFirmwareType(ref uint firmwareType);
'@ -ErrorAction Stop
        }
        [uint32]$ft = 0
        if ([CybersutroWin.FirmwareInfo]::GetFirmwareType([ref]$ft)) {
            switch ($ft) { 1 { return 'BIOS heredada (Legacy)' } 2 { return 'UEFI' } }
        }
    }
    catch { }
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType
        if ($v -eq 2) { return 'UEFI' }
        if ($v -eq 1) { return 'BIOS heredada (Legacy)' }
    }
    catch { }
    return 'Desconocido'
}

# ---------------------------------------------------------------------------
# SFC
# ---------------------------------------------------------------------------
function Repair-CSWRepairSfc {
    param([object]$IncludeCbsLog = $true)
    $deny = Test-CSWRepairElevation 'SFC'
    if ($deny) { return $deny }

    try {
        $ti = Get-Service -Name TrustedInstaller -ErrorAction Stop
        if ([string]$ti.StartType -eq 'Disabled') {
            Write-CSWLog 'El servicio Instalador de modulos (TrustedInstaller) esta deshabilitado; SFC no podra reparar. Se configura en Manual.' -Level Warn
            Set-Service -Name TrustedInstaller -StartupType Manual -ErrorAction SilentlyContinue
        }
    }
    catch { }

    Write-CSWLog 'Comprobando archivos protegidos del sistema con SFC /scannow (10-30 minutos)...' -Level Step
    $start = Get-Date
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'sfc.exe') -Arguments '/scannow' -Unicode
    $t = $r.Text

    $state = 'Unknown'
    if ($t -match 'system repair pending|reparaci.n del sistema pendiente|reparaci.n pendiente') { $state = 'Pending' }
    elseif ($t -match 'unable to fix|no pudo corregir|no pudo reparar') { $state = 'Unrepaired' }
    elseif ($t -match 'successfully repaired|los repar. correctamente|repar. correctamente') { $state = 'Repaired' }
    elseif ($t -match 'did not find any integrity violations|no encontr. ninguna infracci.n|ninguna infracci.n de integridad') { $state = 'Clean' }
    elseif ($t -match 'could not perform the requested operation|no pudo realizar la operaci.n|could not start the repair service|no se pudo iniciar el servicio de reparaci.n') { $state = 'Failed' }

    if (ConvertTo-CSWRepairBool $IncludeCbsLog) {
        $sr = @(Get-CSWRepairCbsSrLines -Since $start)
        if ($sr.Count -gt 0) {
            $cannot = @($sr | Where-Object { $_ -match 'Cannot repair' }).Count
            $fixed = @($sr | Where-Object { $_ -match 'Repairing corrupted|Repaired file' }).Count
            Write-CSWLog ("CBS.log: {0} lineas [SR] relevantes ({1} reparadas, {2} sin reparar):" -f $sr.Count, $fixed, $cannot) -Level Info
            foreach ($l in ($sr | Select-Object -Last 25)) { Write-CSWLog $l -Level Data }
            try {
                $out = Join-Path (Get-CSWDataPath Reports) ("SFC_CBS_{0}_{1:yyyyMMdd_HHmmss}.txt" -f $env:COMPUTERNAME, (Get-Date))
                Set-Content -LiteralPath $out -Value $sr -Encoding UTF8 -ErrorAction Stop
                Write-CSWLog "Extracto [SR] guardado en $out" -Level Info
            }
            catch { }
            if ($state -eq 'Unknown') {
                if ($cannot -gt 0) { $state = 'Unrepaired' } elseif ($fixed -gt 0) { $state = 'Repaired' }
            }
        }
        else { Write-CSWLog 'CBS.log sin lineas [SR] relevantes en esta ejecucion.' -Level Info }
    }

    switch ($state) {
        'Clean' {
            Write-CSWLog 'SFC no encontro infracciones de integridad.' -Level Ok
            return (New-CSWResult -Summary 'Archivos del sistema verificados: sin danos' -Status OK)
        }
        'Repaired' {
            Write-CSWLog 'SFC encontro archivos danados y los reparo. Se recomienda reiniciar.' -Level Ok
            return (New-CSWResult -Summary 'Se repararon archivos del sistema danados (reinicio recomendado)' -Status OK)
        }
        'Unrepaired' {
            Write-CSWLog 'SFC no pudo reparar algunos archivos. Ejecute "DISM RestoreHealth" y despues repita SFC.' -Level Warn
            return (New-CSWResult -Summary 'Hay archivos del sistema danados que SFC no pudo reparar; se recomienda DISM RestoreHealth y repetir SFC' -Status Warn)
        }
        'Pending' {
            Write-CSWLog 'Hay una reparacion del sistema pendiente de reinicio. Reinicie y vuelva a ejecutar SFC.' -Level Warn
            return (New-CSWResult -Summary 'Reparacion pendiente de reinicio: reinicie el equipo y repita SFC' -Status Warn)
        }
        'Failed' {
            Write-CSWLog 'SFC no pudo completar el analisis. Pruebe DISM RestoreHealth o SFC en modo seguro.' -Level Error
            return (New-CSWResult -Summary 'SFC no pudo completar el analisis; se recomienda DISM RestoreHealth' -Status Error)
        }
        default {
            Write-CSWLog ("No se pudo interpretar el resultado de SFC (codigo {0}). Revise el log." -f $r.ExitCode) -Level Warn
            return (New-CSWResult -Summary ("SFC finalizo con resultado no determinado (codigo {0})" -f $r.ExitCode) -Status Warn)
        }
    }
}

# ---------------------------------------------------------------------------
# DISM
# ---------------------------------------------------------------------------
function Test-CSWRepairDismCheckHealth {
    $deny = Test-CSWRepairElevation 'DISM CheckHealth'
    if ($deny) { return $deny }
    Write-CSWLog 'Comprobacion rapida del almacen de componentes (DISM /CheckHealth)...' -Level Step
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'dism.exe') -Arguments '/Online /Cleanup-Image /CheckHealth /English'
    if ($r.ExitCode -ne 0) {
        return (New-CSWResult -Summary ("DISM CheckHealth fallo: {0}" -f (Get-CSWRepairDismErrorText $r.ExitCode)) -Status Error)
    }
    switch (Get-CSWRepairDismHealth $r.Text) {
        'Healthy'       { return (New-CSWResult -Summary 'Almacen de componentes de Windows sin danos registrados' -Status OK) }
        'Repairable'    { Write-CSWLog 'Se recomienda ejecutar "DISM RestoreHealth".' -Level Warn; return (New-CSWResult -Summary 'El almacen de componentes tiene danos reparables (ejecutar DISM RestoreHealth)' -Status Warn) }
        'NotRepairable' { return (New-CSWResult -Summary 'El almacen de componentes esta danado y no es reparable en linea; considerar reparacion in situ' -Status Error) }
        default         { return (New-CSWResult -Summary 'DISM CheckHealth completado (estado no determinado, ver log)' -Status Warn) }
    }
}

function Test-CSWRepairDismScanHealth {
    $deny = Test-CSWRepairElevation 'DISM ScanHealth'
    if ($deny) { return $deny }
    Write-CSWLog 'Analisis completo del almacen de componentes (DISM /ScanHealth, 5-20 minutos)...' -Level Step
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'dism.exe') -Arguments '/Online /Cleanup-Image /ScanHealth /English'
    if ($r.ExitCode -ne 0) {
        return (New-CSWResult -Summary ("DISM ScanHealth fallo: {0}" -f (Get-CSWRepairDismErrorText $r.ExitCode)) -Status Error)
    }
    switch (Get-CSWRepairDismHealth $r.Text) {
        'Healthy'       { return (New-CSWResult -Summary 'Analisis DISM: almacen de componentes sin danos' -Status OK) }
        'Repairable'    { Write-CSWLog 'Se recomienda ejecutar "DISM RestoreHealth".' -Level Warn; return (New-CSWResult -Summary 'Analisis DISM: danos reparables detectados (ejecutar DISM RestoreHealth)' -Status Warn) }
        'NotRepairable' { return (New-CSWResult -Summary 'Analisis DISM: almacen danado no reparable en linea; considerar reparacion in situ' -Status Error) }
        default         { return (New-CSWResult -Summary 'DISM ScanHealth completado (estado no determinado, ver log)' -Status Warn) }
    }
}

function Repair-CSWRepairDismRestore {
    param([string]$Source = '')
    $deny = Test-CSWRepairElevation 'DISM RestoreHealth'
    if ($deny) { return $deny }

    $dismArgs = '/Online /Cleanup-Image /RestoreHealth /English'
    if ($Source -and $Source.Trim()) {
        # Sin barra final: '\"' escaparia la comilla de cierre en la linea de comandos
        $src = $Source.Trim().Trim('"').TrimEnd('\')
        # El valor va dentro de comillas en la linea de comandos de DISM: se rechazan comillas y
        # se comprueba que el archivo/carpeta de origen exista (evita inyectar otros argumentos)
        if ($src -match '["`\r\n]') { return (New-CSWResult -Summary 'Origen de reparacion no valido (contiene comillas o saltos de linea).' -Status Error) }
        $srcPath = $src -replace '^(?i)(WIM|ESD):', '' -replace ':\d+$', ''
        if (-not (Test-Path -LiteralPath $srcPath)) { return (New-CSWResult -Summary "No existe el origen de reparacion indicado: $srcPath" -Status Error) }
        if ($src -notmatch '^(WIM|ESD):') {
            if ($src -match '\.wim$') { $src = "WIM:$($src):1" }
            elseif ($src -match '\.esd$') { $src = "ESD:$($src):1" }
        }
        $dismArgs += (' /Source:"{0}" /LimitAccess' -f $src)
        Write-CSWLog "Usando origen de reparacion: $src (sin Windows Update)" -Level Info
    }
    else { Write-CSWLog 'Origen: Windows Update (requiere Internet).' -Level Info }

    Write-CSWLog 'Reparando el almacen de componentes (DISM /RestoreHealth, 10-40 minutos)...' -Level Step
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'dism.exe') -Arguments $dismArgs
    if ($r.ExitCode -eq 0 -or $r.ExitCode -eq 3010) {
        $msg = 'Imagen de Windows reparada/verificada correctamente con DISM'
        if ($r.Text -match 'corruption was repaired') { $msg = 'DISM reparo danos en el almacen de componentes de Windows' }
        if ($r.ExitCode -eq 3010) { $msg += ' (requiere reinicio)' }
        Write-CSWLog 'DISM RestoreHealth completado. Se recomienda ejecutar SFC a continuacion.' -Level Ok
        return (New-CSWResult -Summary $msg -Status OK)
    }
    $txt = Get-CSWRepairDismErrorText $r.ExitCode
    Write-CSWLog "DISM RestoreHealth fallo: $txt" -Level Error
    Write-CSWLog ('Detalle en {0}' -f (Join-Path $env:windir 'Logs\DISM\dism.log')) -Level Info
    return (New-CSWResult -Summary "DISM RestoreHealth no pudo completar la reparacion: $txt" -Status Error)
}

function Test-CSWRepairComponentAnalyze {
    $deny = Test-CSWRepairElevation 'Analisis del almacen de componentes'
    if ($deny) { return $deny }
    Write-CSWLog 'Analizando el tamano del almacen de componentes WinSxS...' -Level Step
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'dism.exe') -Arguments '/Online /Cleanup-Image /AnalyzeComponentStore /English'
    if ($r.ExitCode -ne 0) {
        return (New-CSWResult -Summary ("Analisis WinSxS fallo: {0}" -f (Get-CSWRepairDismErrorText $r.ExitCode)) -Status Error)
    }
    $size = ''
    if ($r.Text -match 'Actual Size of Component Store\s*:\s*([^\n]+)') { $size = $Matches[1].Trim() }
    if ($r.Text -match 'Cleanup Recommended\s*:\s*Yes') {
        return (New-CSWResult -Summary "WinSxS ocupa $size; se recomienda limpieza de componentes" -Status Warn)
    }
    return (New-CSWResult -Summary "WinSxS ocupa $size; no requiere limpieza" -Status OK)
}

function Optimize-CSWRepairComponentCleanup {
    param([object]$ResetBase = $false)
    $deny = Test-CSWRepairElevation 'Limpieza de componentes'
    if ($deny) { return $deny }
    $before = Get-CSWRepairFreeBytes
    $a = '/Online /Cleanup-Image /StartComponentCleanup /English'
    if (ConvertTo-CSWRepairBool $ResetBase) {
        $a += ' /ResetBase'
        Write-CSWLog 'Con /ResetBase: las actualizaciones instaladas ya no podran desinstalarse.' -Level Warn
    }
    Write-CSWLog 'Limpiando componentes obsoletos de WinSxS (puede tardar bastante)...' -Level Step
    $r = Invoke-CSWRepairExternalCapture -FilePath (Get-CSWRepairSysExe 'dism.exe') -Arguments $a
    $after = Get-CSWRepairFreeBytes
    $freed = ''
    if ($before -ge 0 -and $after -ge 0) { $freed = ' ({0:N0} MB recuperados)' -f ([math]::Max(0, ($after - $before)) / 1MB) }
    if ($r.ExitCode -eq 0 -or $r.ExitCode -eq 3010) {
        return (New-CSWResult -Summary "Limpieza de componentes de Windows completada$freed" -Status OK)
    }
    return (New-CSWResult -Summary ("Limpieza de componentes fallo: {0}" -f (Get-CSWRepairDismErrorText $r.ExitCode)) -Status Error)
}

# ---------------------------------------------------------------------------
# CHKDSK
# ---------------------------------------------------------------------------
function Get-CSWRepairFileSystem {
    param([string]$Drive)
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction Stop
        if ($ld) { return [string]$ld.FileSystem }
    }
    catch { }
    return $null
}

function Test-CSWRepairChkdskScan {
    param([string]$Drive = 'C:')
    $deny = Test-CSWRepairElevation 'CHKDSK'
    if ($deny) { return $deny }
    $d = ConvertTo-CSWRepairDrive $Drive
    if (-not $d) { return (New-CSWResult -Summary "Unidad no valida: '$Drive'" -Status Error) }
    $fsType = Get-CSWRepairFileSystem $d
    if ($null -eq $fsType) { return (New-CSWResult -Summary "La unidad $d no existe" -Status Error) }
    if ($fsType -eq 'ReFS') { return (New-CSWResult -Summary "La unidad $d usa ReFS (se autorrepara; CHKDSK no aplica)" -Status Warn) }
    $chkArgs = $d
    if ($fsType -eq 'NTFS') { $chkArgs = "$d /scan" }
    Write-CSWLog "Analizando el sistema de archivos de $d ($fsType) en modo solo lectura..." -Level Step
    $code = Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'chkdsk.exe') -Arguments $chkArgs
    switch ($code) {
        0 { return (New-CSWResult -Summary "Sistema de archivos de $d sin errores" -Status OK) }
        1 { return (New-CSWResult -Summary "CHKDSK corrigio errores menores en $d" -Status OK) }
        2 { return (New-CSWResult -Summary "CHKDSK en $d finalizo con tareas de limpieza menores" -Status OK) }
        default {
            Write-CSWLog "Se detectaron problemas en $d. Programe 'CHKDSK al reinicio' para repararlos." -Level Warn
            return (New-CSWResult -Summary "Se detectaron errores en el sistema de archivos de $d; se recomienda CHKDSK /f /r al reiniciar" -Status Warn)
        }
    }
}

function Test-CSWRepairChkdskPending {
    param([string]$Drive)
    try {
        $be = @((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction Stop).BootExecute)
        $pat = [regex]::Escape('\??\' + $Drive)
        foreach ($e in $be) { if (([string]$e -match 'autochk') -and ([string]$e -match $pat)) { return $true } }
    }
    catch { }
    return $false
}

function Start-CSWRepairChkdskSchedule {
    param([string]$Drive = 'C:')
    $deny = Test-CSWRepairElevation 'Programar CHKDSK'
    if ($deny) { return $deny }
    $d = ConvertTo-CSWRepairDrive $Drive
    if (-not $d) { return (New-CSWResult -Summary "Unidad no valida: '$Drive'" -Status Error) }
    $fsType = Get-CSWRepairFileSystem $d
    if ($null -eq $fsType) { return (New-CSWResult -Summary "La unidad $d no existe" -Status Error) }
    if ($fsType -eq 'ReFS') { return (New-CSWResult -Summary "La unidad $d usa ReFS; CHKDSK no aplica" -Status Warn) }

    $sysDrive = ConvertTo-CSWRepairDrive $env:SystemDrive
    if ($d -ne $sysDrive) {
        # En unidades de datos chkdsk /f /r se ejecutaria AHORA (desmontando): marcamos como sucia
        Write-CSWLog "$d no es la unidad del sistema: se marca para comprobacion (autochk /f) en el arranque." -Level Info
        $code = Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'fsutil.exe') -Arguments "dirty set $d"
        if ($code -eq 0) { return (New-CSWResult -Summary "Comprobacion de $d programada para el proximo reinicio (reparacion /f)" -Status OK) }
        return (New-CSWResult -Summary "No se pudo programar la comprobacion de $d (codigo $code)" -Status Error)
    }

    if (Test-CSWRepairChkdskPending $d) {
        return (New-CSWResult -Summary "Ya habia una comprobacion de $d programada para el proximo reinicio" -Status OK)
    }

    # La respuesta S/N de chkdsk depende del idioma: se prueba primero la del idioma del sistema
    $lang = ''
    try { $lang = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName } catch { }
    $first = 'Y'
    if (@('es', 'it', 'pt', 'ca', 'gl') -contains $lang) { $first = 'S' }
    elseif ($lang -eq 'fr') { $first = 'O' }
    elseif (@('de', 'nl', 'sv', 'da', 'nb', 'no') -contains $lang) { $first = 'J' }
    $answers = @($first) + @('Y', 'S', 'J', 'O' | Where-Object { $_ -ne $first })

    $cmd = Get-CSWRepairSysExe 'cmd.exe'
    Write-CSWLog "Programando CHKDSK $d /f /r para el proximo reinicio..." -Level Step
    $ok = $false
    foreach ($ans in $answers) {
        [void](Invoke-CSWExternal -FilePath $cmd -Arguments ("/c echo {0}|chkdsk.exe {1} /f /r" -f $ans, $d))
        if (Test-CSWRepairChkdskPending $d) { $ok = $true; break }
    }
    if ($ok) {
        Write-CSWLog 'Al reiniciar, CHKDSK revisara el disco antes de cargar Windows. No apague el equipo durante el proceso.' -Level Ok
        return (New-CSWResult -Summary "CHKDSK /f /r programado en $d para el proximo reinicio (puede tardar de 1 a varias horas)" -Status OK)
    }
    # Respaldo fiable: marcar el volumen como sucio (autochk hara /f en el arranque)
    Write-CSWLog 'No se pudo confirmar la programacion con /r; se marca el volumen como sucio (fsutil dirty set).' -Level Warn
    $code = Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'fsutil.exe') -Arguments "dirty set $d"
    if ($code -eq 0) {
        return (New-CSWResult -Summary "Comprobacion de $d programada al reinicio solo con reparacion /f (sin analisis de sectores /r)" -Status Warn)
    }
    return (New-CSWResult -Summary "No se pudo programar CHKDSK en $d" -Status Error)
}

# ---------------------------------------------------------------------------
# Windows Update
# ---------------------------------------------------------------------------
function Reset-CSWRepairWindowsUpdate {
    $deny = Test-CSWRepairElevation 'Reparar Windows Update'
    if ($deny) { return $deny }

    $services = @('wuauserv', 'bits', 'cryptsvc', 'msiserver')
    $prev = @{}
    foreach ($n in $services) {
        $sc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($sc) { $prev[$n] = [string]$sc.Status } else { $prev[$n] = 'Missing' }
    }

    Write-CSWLog 'Deteniendo servicios de Windows Update...' -Level Step
    $stopState = @{}
    foreach ($n in $services) {
        $stopState[$n] = Stop-CSWRepairService -Name $n
        Write-CSWLog ("  {0}: {1}" -f $n, $stopState[$n]) -Level Info
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $targets = @(
        @{ Path = (Join-Path $env:windir 'SoftwareDistribution'); Svc = @('wuauserv', 'bits') },
        @{ Path = (Join-Path (Get-CSWRepairSysDir) 'catroot2'); Svc = @('cryptsvc') }
    )
    $renamed = 0; $failed = 0
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        $p = $t.Path
        $leaf = Split-Path $p -Leaf
        if (-not (Test-Path -LiteralPath $p)) {
            $rows.Add([pscustomobject]@{ Carpeta = $p; Resultado = 'No existe (se recreara)' }); continue
        }
        $newName = "$leaf.bak-$stamp"
        $done = $false
        for ($attempt = 1; $attempt -le 3 -and -not $done; $attempt++) {
            try {
                Rename-Item -LiteralPath $p -NewName $newName -ErrorAction Stop
                $done = $true
            }
            catch {
                Write-CSWLog ("Intento {0}: {1} en uso ({2}); reintentando..." -f $attempt, $leaf, $_.Exception.Message) -Level Warn
                foreach ($n in $t.Svc) { [void](Stop-CSWRepairService -Name $n -TimeoutSec 20) }
                Start-Sleep -Seconds 2
            }
        }
        if ($done) { $renamed++; $rows.Add([pscustomobject]@{ Carpeta = $p; Resultado = "Renombrada a $newName" }) }
        else { $failed++; $rows.Add([pscustomobject]@{ Carpeta = $p; Resultado = 'No se pudo renombrar (en uso)' }) }
    }

    # Cola de BITS (formato antiguo)
    $qmgr = Join-Path $env:ProgramData 'Microsoft\Network\Downloader'
    if (Test-Path -LiteralPath $qmgr) {
        Get-ChildItem -LiteralPath $qmgr -Filter 'qmgr*.dat' -Force -ErrorAction SilentlyContinue |
            ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { } }
    }

    Write-CSWLog 'Iniciando servicios...' -Level Step
    foreach ($n in @('cryptsvc', 'bits', 'wuauserv', 'msiserver')) {
        if ($prev[$n] -eq 'Missing') { continue }
        if ($n -eq 'msiserver' -and $prev[$n] -ne 'Running') { continue }
        $st = Start-CSWRepairService -Name $n
        if ($st -eq 'Disabled') {
            Write-CSWLog "El servicio $n estaba deshabilitado; se configura en Manual para que Windows Update funcione." -Level Warn
            try { Set-Service -Name $n -StartupType Manual -ErrorAction Stop; $st = Start-CSWRepairService -Name $n } catch { }
        }
        Write-CSWLog ("  {0}: {1}" -f $n, $st) -Level Info
    }

    $rows.ToArray()
    if ($failed -eq 0) {
        Write-CSWLog 'Componentes de Windows Update restablecidos. Reinicie y busque actualizaciones.' -Level Ok
        Write-CSWLog ('Las carpetas .bak-{0} pueden borrarse tras comprobar que Windows Update funciona.' -f $stamp) -Level Info
        return (New-CSWResult -Summary 'Componentes de Windows Update restablecidos (reinicio recomendado)' -Status OK)
    }
    return (New-CSWResult -Summary "Windows Update restablecido parcialmente: $failed carpeta(s) en uso; reinicie y repita" -Status Warn)
}

# ---------------------------------------------------------------------------
# Puntos de restauracion
# ---------------------------------------------------------------------------
function Get-CSWRepairRestorePointList {
    param([switch]$Quiet)
    $rp = @(Get-CimInstance -Namespace 'root/default' -ClassName SystemRestore -ErrorAction Stop)
    $types = @{ 0 = 'Instalacion de aplicacion'; 1 = 'Desinstalacion de aplicacion'; 7 = 'Copia de seguridad'; 10 = 'Instalacion de controlador'; 12 = 'Cambio de configuracion'; 13 = 'Operacion cancelada' }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($p in ($rp | Sort-Object SequenceNumber -Descending)) {
        $when = [string]$p.CreationTime
        $dt = [datetime]::MinValue
        if ($when.Length -ge 14 -and [datetime]::TryParseExact($when.Substring(0, 14), 'yyyyMMddHHmmss', $inv, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) { $when = $dt.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
        $tp = [int]$p.RestorePointType
        $tn = [string]$tp
        if ($types.ContainsKey($tp)) { $tn = $types[$tp] }
        [pscustomobject]@{ Num = $p.SequenceNumber; Fecha = $when; Tipo = $tn; Descripcion = $p.Description }
    }
}

function Get-CSWRepairRestorePoints {
    $deny = Test-CSWRepairElevation 'Listar puntos de restauracion'
    if ($deny) { return $deny }
    $enabled = $null
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -ErrorAction Stop).'{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}'
        $enabled = (@($v) | Where-Object { $_ }).Count -gt 0
    }
    catch { $enabled = $false }
    if ($enabled) { Write-CSWLog 'Proteccion del sistema: activada.' -Level Info }
    else { Write-CSWLog 'Proteccion del sistema: parece DESACTIVADA (no se crean puntos automaticamente).' -Level Warn }
    try { $list = @(Get-CSWRepairRestorePointList) }
    catch {
        Write-CSWLog "No se pudieron consultar los puntos: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudieron consultar los puntos de restauracion' -Status Error)
    }
    if ($list.Count -eq 0) {
        return (New-CSWResult -Summary 'No hay puntos de restauracion en el equipo' -Status Warn)
    }
    $list
    $st = 'OK'; if (-not $enabled) { $st = 'Warn' }
    return (New-CSWResult -Summary ("{0} punto(s) de restauracion; el mas reciente: {1}" -f $list.Count, $list[0].Fecha) -Status $st)
}

function Backup-CSWRepairRestorePoint {
    param([string]$Description = 'Cybersutro win - punto manual')
    $deny = Test-CSWRepairElevation 'Crear punto de restauracion'
    if ($deny) { return $deny }
    if (-not $Description) { $Description = 'Cybersutro win - punto manual' }
    # El nucleo usa Checkpoint-Computer (Windows PowerShell) o la clase WMI SystemRestore (PowerShell 7)
    $ok = $false
    try { $ok = [bool](New-CSWRestorePoint -Description $Description -Force) } catch { $ok = $false }
    if ($ok) { return (New-CSWResult -Summary "Punto de restauracion creado: $Description" -Status OK) }
    return (New-CSWResult -Summary 'No se pudo crear el punto de restauracion (proteccion del sistema desactivada o sin espacio)' -Status Error)
}

function Show-CSWRepairRestoreWizard {
    $exe = Get-CSWRepairSysExe 'rstrui.exe'
    try {
        Start-Process -FilePath $exe -ErrorAction Stop
        Write-CSWLog 'Asistente de Restaurar sistema abierto en pantalla.' -Level Ok
        return (New-CSWResult -Summary 'Se abrio el asistente de Restaurar sistema' -Status OK)
    }
    catch {
        Write-CSWLog "No se pudo abrir rstrui.exe: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudo abrir el asistente de Restaurar sistema' -Status Error)
    }
}

# ---------------------------------------------------------------------------
# Arranque (solo lectura)
# ---------------------------------------------------------------------------
function Get-CSWRepairBootInfo {
    $fw = Get-CSWRepairFirmwareType
    $sb = 'Desconocido'
    $sbOff = $false
    try {
        $v = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($v) { $sb = 'Activado' } else { $sb = 'Desactivado'; $sbOff = $true }
    }
    catch [System.PlatformNotSupportedException] { $sb = 'No soportado (BIOS heredada)' }
    catch [System.UnauthorizedAccessException] { $sb = 'Requiere administrador' }
    catch {
        $m = $_.Exception.Message
        if ($m -match 'not supported|no se admite|no compatible') { $sb = 'No soportado (BIOS heredada)' }
        elseif ($m -match 'denied|denegado') { $sb = 'Requiere administrador' }
        else { $sb = "No disponible ($m)" }
    }

    $style = 'Desconocido'
    try {
        $letter = $env:SystemDrive.Substring(0, 1)
        $disk = Get-Partition -DriveLetter $letter -ErrorAction Stop | Get-Disk -ErrorAction Stop
        $style = [string]$disk.PartitionStyle
    }
    catch { }

    $bootState = ''; $lastBoot = ''
    try { $bootState = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).BootupState } catch { }
    try { $lastBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }

    $tpm = 'Desconocido'
    try {
        $t = Get-Tpm -ErrorAction Stop
        if ($t.TpmPresent) { if ($t.TpmReady) { $tpm = 'Presente y listo' } else { $tpm = 'Presente, no preparado' } } else { $tpm = 'No presente' }
    }
    catch { if (-not (Test-CSWAdmin)) { $tpm = 'Requiere administrador' } }

    [pscustomobject]@{ Elemento = 'Firmware'; Valor = $fw }
    [pscustomobject]@{ Elemento = 'Secure Boot'; Valor = $sb }
    [pscustomobject]@{ Elemento = 'Estilo de particion (disco del sistema)'; Valor = $style }
    [pscustomobject]@{ Elemento = 'TPM'; Valor = $tpm }
    [pscustomobject]@{ Elemento = 'Modo de arranque'; Valor = $bootState }
    [pscustomobject]@{ Elemento = 'Ultimo arranque'; Valor = $lastBoot }

    if (Test-CSWAdmin) {
        Write-CSWLog 'Configuracion de arranque (bcdedit /enum):' -Level Step
        [void](Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'bcdedit.exe') -Arguments '/enum')
    }
    else { Write-CSWLog 'bcdedit /enum omitido: requiere administrador.' -Level Warn }

    $sum = "Arranque $fw, Secure Boot: $sb, particion $style"
    if ($fw -eq 'UEFI' -and $sbOff) { return (New-CSWResult -Summary "$sum (Secure Boot desactivado)" -Status Warn) }
    return (New-CSWResult -Summary $sum -Status OK)
}

# ---------------------------------------------------------------------------
# Iconos y miniaturas
# ---------------------------------------------------------------------------
function Reset-CSWRepairIconCache {
    $session = (Get-Process -Id $PID).SessionId
    $local = $env:LOCALAPPDATA
    Write-CSWLog "Restableciendo cache de iconos y miniaturas del usuario $env:USERNAME..." -Level Step
    try { [void](Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'ie4uinit.exe') -Arguments '-show') } catch { }

    $exp = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session })
    foreach ($p in $exp) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { } }
    for ($i = 0; $i -lt 10; $i++) {
        if (-not @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session }).Count) { break }
        Start-Sleep -Milliseconds 500
    }

    $files = New-Object System.Collections.Generic.List[object]
    $legacy = Join-Path $local 'IconCache.db'
    if (Test-Path -LiteralPath $legacy) { $files.Add((Get-Item -LiteralPath $legacy -Force)) }
    $expDir = Join-Path $local 'Microsoft\Windows\Explorer'
    if (Test-Path -LiteralPath $expDir) {
        foreach ($pat in 'iconcache_*.db', 'thumbcache_*.db') {
            foreach ($f in @(Get-ChildItem -LiteralPath $expDir -Filter $pat -Force -ErrorAction SilentlyContinue)) { $files.Add($f) }
        }
    }
    $bytes = [int64]0; $n = 0; $fail = 0
    foreach ($f in $files) {
        try { $len = [int64]$f.Length; Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $bytes += $len; $n++ }
        catch { $fail++ }
    }

    Start-Sleep -Seconds 2
    if (-not @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session }).Count) {
        try { Start-Process -FilePath (Join-Path $env:windir 'explorer.exe') -ErrorAction Stop } catch { Write-CSWLog 'No se pudo reiniciar el Explorador: pulse Ctrl+Mayus+Esc > Archivo > explorer.exe' -Level Warn }
    }
    Write-CSWLog ("Eliminados {0} archivos de cache ({1:N1} MB); {2} en uso." -f $n, ($bytes / 1MB), $fail) -Level Info
    if ($fail -gt 0 -and $n -eq 0) { return (New-CSWResult -Summary 'No se pudo eliminar la cache de iconos (archivos en uso); reinicie y repita' -Status Warn) }
    return (New-CSWResult -Summary ("Cache de iconos y miniaturas restablecida ({0} archivos)" -f $n) -Status OK)
}

# ---------------------------------------------------------------------------
# Microsoft Store
# ---------------------------------------------------------------------------
function Repair-CSWRepairStore {
    param([object]$AllApps = $false)
    $deny = Test-CSWRepairElevation 'Reparar Microsoft Store'
    if ($deny) { return $deny }
    if (-not (Import-CSWRepairAppx)) {
        return (New-CSWResult -Summary 'El modulo Appx no esta disponible en este sistema' -Status Warn)
    }
    $session = (Get-Process -Id $PID).SessionId
    Get-Process -Name 'WinStore.App' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session } |
        ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch { } }

    Write-CSWLog 'Limpiando la cache local de Microsoft Store...' -Level Step
    $cache = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache'
    if (Test-Path -LiteralPath $cache) {
        Get-ChildItem -LiteralPath $cache -Force -ErrorAction SilentlyContinue |
            ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch { } }
    }

    $warn = 0
    $pkg = @(Get-AppxPackage -AllUsers -Name 'Microsoft.WindowsStore' -ErrorAction SilentlyContinue | Sort-Object Version -Descending) | Select-Object -First 1
    if ($pkg -and $pkg.InstallLocation) {
        Write-CSWLog "Re-registrando Microsoft Store $($pkg.Version)..." -Level Step
        try {
            Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path $pkg.InstallLocation 'AppxManifest.xml') -ErrorAction Stop
            Write-CSWLog 'Microsoft Store re-registrada.' -Level Ok
        }
        catch { $warn++; Write-CSWLog "Error al re-registrar la Store: $($_.Exception.Message)" -Level Warn }
    }
    else {
        $warn++
        Write-CSWLog 'Microsoft Store no esta instalada. Intentando reinstalarla con wsreset -i...' -Level Warn
        try { [void](Invoke-CSWExternal -FilePath (Get-CSWRepairSysExe 'wsreset.exe') -Arguments '-i') }
        catch { Write-CSWLog "wsreset no disponible: $($_.Exception.Message)" -Level Warn }
    }

    if (ConvertTo-CSWRepairBool $AllApps) {
        Write-CSWLog 'Re-registrando todas las apps del sistema (varios minutos; los errores de apps en uso son normales)...' -Level Step
        $ok = 0; $bad = 0
        foreach ($a in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.InstallLocation -and -not $_.IsFramework -and ([string]$_.SignatureKind -eq 'System' -or [string]$_.SignatureKind -eq 'Store') })) {
            if (-not $a.InstallLocation) { continue }
            $man = Join-Path $a.InstallLocation 'AppxManifest.xml'
            if (-not (Test-Path -LiteralPath $man)) { continue }
            try { Add-AppxPackage -DisableDevelopmentMode -Register $man -ErrorAction Stop; $ok++ } catch { $bad++ }
        }
        Write-CSWLog ("Apps re-registradas: {0}; con error: {1}" -f $ok, $bad) -Level Info
    }
    if ($warn -gt 0) { return (New-CSWResult -Summary 'Reparacion de Microsoft Store completada con avisos (ver log)' -Status Warn) }
    return (New-CSWResult -Summary 'Microsoft Store reparada (cache limpia y app re-registrada)' -Status OK)
}

# ---------------------------------------------------------------------------
# Busqueda de Windows
# ---------------------------------------------------------------------------
function Reset-CSWRepairSearchIndex {
    $deny = Test-CSWRepairElevation 'Reconstruir indice de busqueda'
    if ($deny) { return $deny }
    $svc = Get-Service -Name WSearch -ErrorAction SilentlyContinue
    if (-not $svc) { return (New-CSWResult -Summary 'El servicio Windows Search no esta instalado' -Status Warn) }
    if ((Get-CSWRepairServiceStartType 'WSearch') -eq 'Disabled') {
        Write-CSWLog 'Windows Search esta deshabilitado (posible optimizacion intencionada). No se reconstruye el indice.' -Level Warn
        return (New-CSWResult -Summary 'Windows Search esta deshabilitado; indice no reconstruido' -Status Warn)
    }

    Write-CSWLog 'Deteniendo Windows Search...' -Level Step
    $st = Stop-CSWRepairService -Name WSearch -TimeoutSec 60
    if ($st -ne 'Stopped') { return (New-CSWResult -Summary 'No se pudo detener Windows Search; reinicie y repita' -Status Error) }

    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name SetupCompletedSuccessfully -Value 0 -Type DWord -ErrorAction Stop
    }
    catch { Write-CSWLog "No se pudo marcar el indice para reconstruccion: $($_.Exception.Message)" -Level Warn }

    $dataDir = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows'
    $freed = [int64]0
    if (Test-Path -LiteralPath $dataDir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dataDir -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Windows(-gather|-usn)?\.(edb|db)$' })) {
            try { $len = $f.Length; Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $freed += $len } catch { }
        }
    }
    Write-CSWLog ("Base de datos del indice eliminada ({0:N0} MB)." -f ($freed / 1MB)) -Level Info

    $st = Start-CSWRepairService -Name WSearch -TimeoutSec 60

    if (Import-CSWRepairAppx) {
        foreach ($name in 'Microsoft.Windows.Search', 'Microsoft.Windows.Cortana') {
            $pkg = @(Get-AppxPackage -AllUsers -Name $name -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($pkg -and $pkg.InstallLocation) {
                try {
                    Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path $pkg.InstallLocation 'AppxManifest.xml') -ErrorAction Stop
                    Write-CSWLog "Componente $name re-registrado." -Level Info
                }
                catch { Write-CSWLog "No se pudo re-registrar ${name}: $($_.Exception.Message)" -Level Warn }
            }
        }
    }
    if ($st -ne 'Running') { return (New-CSWResult -Summary 'Indice reiniciado pero Windows Search no arranco; reinicie el equipo' -Status Warn) }
    return (New-CSWResult -Summary 'Indice de busqueda reiniciado; se reconstruira en segundo plano (puede tardar horas)' -Status OK)
}

# ---------------------------------------------------------------------------
# Hora
# ---------------------------------------------------------------------------
function Update-CSWRepairTimeSync {
    $deny = Test-CSWRepairElevation 'Sincronizar hora'
    if ($deny) { return $deny }
    $w32 = Get-CSWRepairSysExe 'w32tm.exe'
    $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    if (-not $svc) { return (New-CSWResult -Summary 'El servicio de hora de Windows no existe' -Status Error) }
    if ((Get-CSWRepairServiceStartType 'W32Time') -eq 'Disabled') {
        Write-CSWLog 'El servicio de hora estaba deshabilitado; se configura en Automatico.' -Level Warn
        Set-Service -Name W32Time -StartupType Automatic -ErrorAction SilentlyContinue
    }
    if ((Start-CSWRepairService -Name W32Time) -ne 'Running') {
        Write-CSWLog 'Re-registrando el servicio de hora...' -Level Info
        [void](Invoke-CSWExternal -FilePath $w32 -Arguments '/unregister')
        [void](Invoke-CSWExternal -FilePath $w32 -Arguments '/register')
        if ((Start-CSWRepairService -Name W32Time) -ne 'Running') {
            return (New-CSWResult -Summary 'No se pudo iniciar el servicio de hora de Windows' -Status Error)
        }
    }

    $domain = $false
    try { $domain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
    if (-not $domain) {
        $src = Invoke-CSWRepairExternalCapture -FilePath $w32 -Arguments '/query /source'
        if ($src.Text -match 'Local CMOS Clock|Free-running System Clock|0x80070426') {
            Write-CSWLog 'Sin servidor de hora configurado: se configuran time.windows.com y pool.ntp.org.' -Level Warn
            [void](Invoke-CSWExternal -FilePath $w32 -Arguments '/config /manualpeerlist:"time.windows.com,0x9 pool.ntp.org,0x9" /syncfromflags:manual /reliable:no /update')
            Restart-Service -Name W32Time -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
    else { Write-CSWLog 'Equipo en dominio: se respeta la jerarquia de hora del dominio.' -Level Info }

    Write-CSWLog 'Sincronizando la hora...' -Level Step
    $code = Invoke-CSWExternal -FilePath $w32 -Arguments '/resync'
    if ($code -ne 0) {
        Start-Sleep -Seconds 2
        $code = Invoke-CSWExternal -FilePath $w32 -Arguments '/resync /rediscover'
    }
    $offset = $null
    if (-not $domain) {
        $sc = Invoke-CSWRepairExternalCapture -FilePath $w32 -Arguments '/stripchart /computer:time.windows.com /samples:1 /dataonly' -TimeoutSeconds 30
        if ($sc.Text -match '([+-]\d+[\.,]\d+)s') {
            try { $offset = [double]::Parse(($Matches[1] -replace ',', '.'), [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
        }
    }
    $now = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    if ($code -ne 0) {
        return (New-CSWResult -Summary ("No se pudo sincronizar la hora (codigo {0}); revise Internet o el firewall (UDP 123)" -f $code) -Status Warn)
    }
    if ($null -ne $offset -and [math]::Abs($offset) -gt 5) {
        return (New-CSWResult -Summary ("Hora sincronizada pero aun hay un desfase de {0:N1} s" -f $offset) -Status Warn)
    }
    return (New-CSWResult -Summary "Hora del sistema sincronizada ($now)" -Status OK)
}

# ---------------------------------------------------------------------------
# Reinicio pendiente
# ---------------------------------------------------------------------------
function Test-CSWRepairPendingReboot {
    $rows = New-Object System.Collections.Generic.List[object]
    $any = $false

    $cbs = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $rows.Add([pscustomobject]@{ Origen = 'Servicio de componentes (CBS)'; Pendiente = $cbs; Detalle = '' })
    if ($cbs) { $any = $true }

    $wu = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $rows.Add([pscustomobject]@{ Origen = 'Windows Update'; Pendiente = $wu; Detalle = '' })
    if ($wu) { $any = $true }

    $pfro = 0
    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        foreach ($nm in 'PendingFileRenameOperations', 'PendingFileRenameOperations2') {
            if ($sm.PSObject.Properties[$nm]) { $pfro += @($sm.$nm | Where-Object { $_ }).Count }
        }
    }
    catch { }
    $rows.Add([pscustomobject]@{ Origen = 'Renombrado de archivos pendiente'; Pendiente = ($pfro -gt 0); Detalle = $(if ($pfro -gt 0) { "$pfro entrada(s)" } else { '' }) })
    if ($pfro -gt 0) { $any = $true }

    $upd = $false
    try {
        $u = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction Stop
        if ([int]$u.UpdateExeVolatile -ne 0) { $upd = $true }
    }
    catch { }
    $rows.Add([pscustomobject]@{ Origen = 'Instalador de actualizaciones'; Pendiente = $upd; Detalle = '' })
    if ($upd) { $any = $true }

    $ren = $false; $renDet = ''
    try {
        $act = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
        $pend = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
        if ($act -ne $pend) { $ren = $true; $renDet = "$act -> $pend" }
    }
    catch { }
    $rows.Add([pscustomobject]@{ Origen = 'Cambio de nombre del equipo'; Pendiente = $ren; Detalle = $renDet })
    if ($ren) { $any = $true }

    $rows.ToArray()
    if ($any) {
        $who = (@($rows | Where-Object { $_.Pendiente }) | ForEach-Object { $_.Origen }) -join ', '
        Write-CSWLog "Reinicio pendiente por: $who" -Level Warn
        return (New-CSWResult -Summary "El equipo necesita reiniciarse ($who)" -Status Warn)
    }
    return (New-CSWResult -Summary 'No hay reinicios pendientes' -Status OK)
}

# ---------------------------------------------------------------------------
# Registro del modulo
# ---------------------------------------------------------------------------
Register-CSWModule -Id 'Repair' -Name 'Reparación' -Order 30 -Icon 'repair' `
    -Description 'Reparación de archivos de sistema, imagen de Windows, disco, Windows Update y componentes' -Actions @(
    @{ Id = 'Sfc'; Name = 'SFC /scannow'; Command = 'Repair-CSWRepairSfc'; Risk = 'Low'; ModifiesSystem = $true; LongRunning = $true
       Description = 'Comprueba y repara los archivos protegidos de Windows (System File Checker).'
       Inputs = @(@{ Name = 'IncludeCbsLog'; Label = 'Extraer detalle de CBS.log'; Type = 'Bool'; Default = 'True' }) }
    @{ Id = 'DismCheckHealth'; Name = 'DISM CheckHealth'; Command = 'Test-CSWRepairDismCheckHealth'; Risk = 'Low'
       Description = 'Comprobación rápida de si la imagen de Windows está marcada como dañada.' }
    @{ Id = 'DismScanHealth'; Name = 'DISM ScanHealth'; Command = 'Test-CSWRepairDismScanHealth'; Risk = 'Low'; LongRunning = $true
       Description = 'Análisis completo del almacén de componentes en busca de daños (no repara).' }
    @{ Id = 'DismRestore'; Name = 'DISM RestoreHealth'; Command = 'Repair-CSWRepairDismRestore'; Risk = 'Low'; ModifiesSystem = $true; LongRunning = $true
       Description = 'Repara la imagen de Windows desde Windows Update o desde una ISO (install.wim/esd).'
       Inputs = @(@{ Name = 'Source'; Label = 'Origen opcional (ej. D:\sources\install.wim, vacío = Windows Update)'; Default = '' }) }
    @{ Id = 'ComponentAnalyze'; Name = 'Analizar WinSxS'; Command = 'Test-CSWRepairComponentAnalyze'; Risk = 'Low'; LongRunning = $true
       Description = 'Muestra el tamaño real del almacén de componentes y si conviene limpiarlo.' }
    @{ Id = 'ComponentCleanup'; Name = 'Limpiar componentes WinSxS'; Command = 'Optimize-CSWRepairComponentCleanup'; Risk = 'Medium'; ModifiesSystem = $true; LongRunning = $true
       Description = 'Elimina versiones antiguas de componentes de Windows (StartComponentCleanup).'
       ConfirmMessage = 'Se eliminarán versiones antiguas de componentes de Windows. Puede tardar 10-30 minutos. Con ResetBase no se podrán desinstalar las actualizaciones instaladas.'
       Inputs = @(@{ Name = 'ResetBase'; Label = 'ResetBase (impide desinstalar actualizaciones)'; Type = 'Bool'; Default = 'False' }) }
    @{ Id = 'ChkdskScan'; Name = 'CHKDSK (solo lectura)'; Command = 'Test-CSWRepairChkdskScan'; Risk = 'Low'; LongRunning = $true
       Description = 'Analiza el sistema de archivos en línea sin desmontar ni modificar (chkdsk /scan).'
       Inputs = @(@{ Name = 'Drive'; Label = 'Unidad'; Default = 'C:' }) }
    @{ Id = 'ChkdskSchedule'; Name = 'CHKDSK /f /r al reiniciar'; Command = 'Start-CSWRepairChkdskSchedule'; Risk = 'High'; ModifiesSystem = $true
       Description = 'Programa una revisión y reparación completa del disco (incluye sectores) en el próximo arranque.'
       ConfirmMessage = 'Se programará CHKDSK /f /r para el próximo reinicio. Al reiniciar, la revisión puede tardar de 1 a varias horas según el tamaño y estado del disco, y el equipo NO debe apagarse durante el proceso.'
       Inputs = @(@{ Name = 'Drive'; Label = 'Unidad'; Default = 'C:' }) }
    @{ Id = 'WindowsUpdateReset'; Name = 'Reparar Windows Update'; Command = 'Reset-CSWRepairWindowsUpdate'; Risk = 'High'; ModifiesSystem = $true
       Description = 'Detiene servicios, renombra SoftwareDistribution y catroot2 y reinicia los servicios de Windows Update.'
       ConfirmMessage = 'Se detendrán los servicios de Windows Update y se renombrarán las carpetas SoftwareDistribution y catroot2 (se pierde el historial de actualizaciones mostrado y las descargas pendientes). Se recomienda reiniciar después.' }
    @{ Id = 'RestorePointList'; Name = 'Ver puntos de restauración'; Command = 'Get-CSWRepairRestorePoints'; Risk = 'Low'
       Description = 'Lista los puntos de restauración existentes y el estado de la protección del sistema.' }
    @{ Id = 'RestorePointCreate'; Name = 'Crear punto de restauración'; Command = 'Backup-CSWRepairRestorePoint'; Risk = 'Low'
       Description = 'Crea un punto de restauración del sistema ahora.'
       Inputs = @(@{ Name = 'Description'; Label = 'Descripción'; Default = 'Cybersutro win - punto manual' }) }
    @{ Id = 'RestorePointOpen'; Name = 'Abrir Restaurar sistema'; Command = 'Show-CSWRepairRestoreWizard'; Risk = 'Low'
       Description = 'Abre el asistente de Windows para volver a un punto de restauración.' }
    @{ Id = 'BootInfo'; Name = 'Información de arranque'; Command = 'Get-CSWRepairBootInfo'; Risk = 'Low'
       Description = 'Muestra modo UEFI/BIOS, Secure Boot, estilo de partición, TPM y la configuración BCD (solo lectura).' }
    @{ Id = 'IconCacheReset'; Name = 'Restablecer iconos y miniaturas'; Command = 'Reset-CSWRepairIconCache'; Risk = 'Medium'
       Description = 'Borra la cache de iconos y miniaturas del usuario y reinicia el Explorador.'
       ConfirmMessage = 'El Explorador de Windows (escritorio y barra de tareas) se cerrará y volverá a abrir. Guarde el trabajo abierto en ventanas del Explorador.' }
    @{ Id = 'StoreRepair'; Name = 'Reparar Microsoft Store'; Command = 'Repair-CSWRepairStore'; Risk = 'Medium'
       Description = 'Limpia la cache de Microsoft Store y la re-registra (opcionalmente todas las apps del sistema).'
       ConfirmMessage = 'Se cerrará Microsoft Store, se limpiará su cache y se re-registrará la aplicación. Re-registrar todas las apps puede tardar varios minutos.'
       Inputs = @(@{ Name = 'AllApps'; Label = 'Re-registrar también todas las apps'; Type = 'Bool'; Default = 'False' }) }
    @{ Id = 'SearchRebuild'; Name = 'Reconstruir índice de búsqueda'; Command = 'Reset-CSWRepairSearchIndex'; Risk = 'Medium'
       Description = 'Reinicia Windows Search, borra el índice y re-registra los componentes de búsqueda.'
       ConfirmMessage = 'Se borrará el índice de búsqueda. Durante horas la búsqueda de Windows mostrará resultados incompletos mientras se reconstruye.' }
    @{ Id = 'TimeSync'; Name = 'Sincronizar hora'; Command = 'Update-CSWRepairTimeSync'; Risk = 'Medium'; ModifiesSystem = $true
       Description = 'Activa el servicio de hora si está detenido, configura servidores NTP si faltan y sincroniza.'
       ConfirmMessage = 'Se pondrá en marcha el servicio de hora de Windows (inicio Automático si estaba deshabilitado) y, si no tiene servidor configurado, se usarán time.windows.com y pool.ntp.org. En equipos de dominio no se cambia la configuración.' }
    @{ Id = 'PendingReboot'; Name = 'Reinicio pendiente'; Command = 'Test-CSWRepairPendingReboot'; Risk = 'Low'
       Description = 'Comprueba si Windows tiene un reinicio pendiente (CBS, Windows Update, archivos, nombre).' }
)

Export-ModuleMember -Function *
