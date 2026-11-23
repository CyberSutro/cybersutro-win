#Requires -Version 5.1
<#
    Cybersutro win - Modulo de Disco y limpieza (Disk)
    Estado SMART de discos, espacio, limpiezas (temporales, profunda, navegadores, cleanmgr),
    optimizacion de unidades, analisis de carpetas/archivos grandes, hibernacion y pagefile.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Escaner de disco en C# (rapido y tolerante a accesos denegados; no sigue uniones)
# ---------------------------------------------------------------------------
$script:CSWDiskScannerSource = @'
using System;
using System.IO;
using System.Collections.Generic;

namespace CybersutroWin
{
    public class DiskScanEntry
    {
        public string Path;
        public long Bytes;
        public long Files;
        public long Errors;
        public DateTime LastWrite;
    }

    public static class DiskScanner
    {
        // Offline | RecallOnOpen | RecallOnDataAccess: archivos solo en la nube (OneDrive)
        private const int CloudMask = 0x1000 | 0x40000 | 0x400000;

        public static DiskScanEntry Measure(string root)
        {
            return Walk(root, -1, null);
        }

        public static DiskScanEntry FindLarge(string root, long minBytes, List<DiskScanEntry> hits)
        {
            return Walk(root, minBytes, hits);
        }

        private static DiskScanEntry Walk(string root, long minBytes, List<DiskScanEntry> hits)
        {
            DiskScanEntry r = new DiskScanEntry();
            r.Path = root;
            Stack<string> st = new Stack<string>();
            st.Push(root);
            while (st.Count > 0)
            {
                string dir = st.Pop();
                IEnumerator<FileSystemInfo> en;
                try { en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); }
                catch { r.Errors++; continue; }
                using (en)
                {
                    while (true)
                    {
                        FileSystemInfo fi;
                        try
                        {
                            if (!en.MoveNext()) break;
                            fi = en.Current;
                        }
                        catch { r.Errors++; break; }
                        try
                        {
                            int a = (int)fi.Attributes;
                            if ((a & 0x10) != 0)
                            {
                                if ((a & 0x400) == 0) st.Push(fi.FullName);
                            }
                            else
                            {
                                r.Files++;
                                if ((a & CloudMask) == 0)
                                {
                                    long len = ((FileInfo)fi).Length;
                                    r.Bytes += len;
                                    if (hits != null && minBytes >= 0 && len >= minBytes)
                                    {
                                        DiskScanEntry h = new DiskScanEntry();
                                        h.Path = fi.FullName;
                                        h.Bytes = len;
                                        h.Files = 1;
                                        h.LastWrite = fi.LastWriteTime;
                                        hits.Add(h);
                                    }
                                }
                            }
                        }
                        catch { r.Errors++; }
                    }
                }
            }
            return r;
        }
    }
}
'@

function Initialize-CSWDiskScanner {
    if ('CybersutroWin.DiskScanner' -as [type]) { return $true }
    try {
        Add-Type -TypeDefinition $script:CSWDiskScannerSource -Language CSharp -ErrorAction Stop
        return $true
    }
    catch {
        Write-CSWLog "Escaner rapido no disponible ($($_.Exception.Message)); se usa el metodo lento." -Level Warn
        return $false
    }
}

function Measure-CSWDiskTreeFallback {
    # Version PowerShell pura del escaner (si Add-Type no esta permitido)
    param([string]$Root, [int64]$MinBytes = -1, [System.Collections.ArrayList]$Hits)
    $r = [pscustomobject]@{ Path = $Root; Bytes = [int64]0; Files = [int64]0; Errors = [int64]0 }
    $st = New-Object 'System.Collections.Generic.Stack[string]'
    $st.Push($Root)
    while ($st.Count -gt 0) {
        $dir = $st.Pop()
        $items = $null
        try { $items = (New-Object System.IO.DirectoryInfo($dir)).GetFileSystemInfos() } catch { $r.Errors++; continue }
        foreach ($fi in $items) {
            try {
                $a = [int]$fi.Attributes
                if ($a -band 0x10) { if (-not ($a -band 0x400)) { $st.Push($fi.FullName) } }
                else {
                    $r.Files++
                    if (-not ($a -band 0x441000)) {
                        $len = [int64]$fi.Length
                        $r.Bytes += $len
                        if ($null -ne $Hits -and $MinBytes -ge 0 -and $len -ge $MinBytes) {
                            [void]$Hits.Add([pscustomobject]@{ Path = $fi.FullName; Bytes = $len; LastWrite = $fi.LastWriteTime })
                        }
                    }
                }
            }
            catch { $r.Errors++ }
        }
    }
    return $r
}

function Measure-CSWDiskPath {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [System.IO.Directory]::Exists($Path)) { return [pscustomobject]@{ Path = $Path; Bytes = [int64]0; Files = [int64]0; Errors = [int64]0 } }
    if (Initialize-CSWDiskScanner) {
        $e = [CybersutroWin.DiskScanner]::Measure($Path)
        return [pscustomobject]@{ Path = $Path; Bytes = [int64]$e.Bytes; Files = [int64]$e.Files; Errors = [int64]$e.Errors }
    }
    return (Measure-CSWDiskTreeFallback -Root $Path)
}

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------
function Get-CSWDiskSysExe {
    param([Parameter(Mandatory)][string]$Name)
    $dir = Join-Path $env:windir 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $nat = Join-Path $env:windir 'Sysnative'
        if (Test-Path -LiteralPath $nat) { $dir = $nat }
    }
    $p = Join-Path $dir $Name
    if (Test-Path -LiteralPath $p) { return $p }
    return $Name
}

function ConvertTo-CSWDiskBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ([string]$Value -match '^\s*(1|true|\$true|s|si|y|yes|on)\s*$')
}

function Format-CSWDiskSize {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Get-CSWDiskProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-CSWDiskElevation {
    param([string]$What)
    if (Test-CSWAdmin) { return $null }
    return (New-CSWAdminRequiredResult $What)
}

function Get-CSWDiskFreeBytes {
    param([string]$Drive = $env:SystemDrive)
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction Stop
        if ($ld) { return [int64]$ld.FreeSpace }
    }
    catch { }
    return [int64]-1
}

function Get-CSWDiskToolExclusions {
    $ex = New-Object System.Collections.Generic.List[string]
    try { $ex.Add((Split-Path -Path $PSScriptRoot -Parent)) } catch { }
    try {
        $s = Get-CSWState
        if ($s.ContainsKey('RootPath') -and $s.RootPath) { $ex.Add([string]$s.RootPath) }
    }
    catch { }
    return , $ex.ToArray()
}

function Get-CSWDiskProfilePaths {
    <# Carpetas de perfil de usuario existentes (C:\Users\* y ProfileList), sin uniones. #>
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.Generic.List[string]
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    try {
        foreach ($d in (New-Object System.IO.DirectoryInfo($usersRoot)).GetDirectories()) {
            if (([int]$d.Attributes -band 0x400) -ne 0) { continue }
            if ($set.Add($d.FullName)) { $list.Add($d.FullName) }
        }
    }
    catch { }
    try {
        foreach ($k in @(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop)) {
            if ($k.PSChildName -notmatch '^S-1-(5-21|12-1)-') { continue }
            $p = [Environment]::ExpandEnvironmentVariables([string]$k.GetValue('ProfileImagePath'))
            if ($p -and [System.IO.Directory]::Exists($p) -and $set.Add($p)) { $list.Add($p) }
        }
    }
    catch { }
    return , $list.ToArray()
}

function Remove-CSWDiskFolderContent {
    <#
        Borra el CONTENIDO de una carpeta (no la carpeta). Ignora archivos en uso, no sigue
        uniones/enlaces, respeta exclusiones y edad minima. Devuelve bytes y archivos borrados.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinAgeMinutes = 0,
        [string[]]$Exclude = @(),
        [string[]]$KeepNames = @()
    )
    $res = [pscustomobject]@{ Path = $Path; Bytes = [int64]0; Files = 0; Failed = 0 }
    if (-not [System.IO.Directory]::Exists($Path)) { return $res }
    $rootInfo = New-Object System.IO.DirectoryInfo($Path)
    if (([int]$rootInfo.Attributes -band 0x400) -ne 0) {
        Write-CSWLog "Se omite $Path (es un enlace/union)." -Level Warn
        return $res
    }
    $cut = (Get-Date).AddMinutes(-$MinAgeMinutes)
    $excl = @($Exclude | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' })
    $dirs = New-Object System.Collections.Generic.List[string]
    $st = New-Object 'System.Collections.Generic.Stack[string]'
    $st.Push($rootInfo.FullName)
    while ($st.Count -gt 0) {
        $d = $st.Pop()
        $items = $null
        try { $items = (New-Object System.IO.DirectoryInfo($d)).GetFileSystemInfos() } catch { $res.Failed++; continue }
        foreach ($it in $items) {
            $full = $it.FullName
            $skip = $false
            foreach ($e in $excl) { if (($full + '\').StartsWith($e, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break } }
            if ($skip) { continue }
            $a = [int]$it.Attributes
            if ($a -band 0x10) {
                if ($a -band 0x400) { continue }
                $st.Push($full); $dirs.Add($full); continue
            }
            if ($KeepNames -contains $it.Name) { continue }
            if ($MinAgeMinutes -gt 0 -and $it.LastWriteTime -gt $cut) { continue }
            try {
                $len = [int64]$it.Length
                if ($a -band 0x1) { $it.Attributes = [System.IO.FileAttributes]::Normal }
                $it.Delete()
                $res.Bytes += $len; $res.Files++
            }
            catch { $res.Failed++ }
        }
    }
    foreach ($d in ($dirs | Sort-Object -Property Length -Descending)) {
        try {
            $di = New-Object System.IO.DirectoryInfo($d)
            if ($MinAgeMinutes -gt 0 -and $di.CreationTime -gt $cut) { continue }
            if (([int]$di.Attributes -band 0x1) -ne 0) { $di.Attributes = [System.IO.FileAttributes]::Directory }
            $di.Delete($false)
        }
        catch { }
    }
    return $res
}

function Stop-CSWDiskService {
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 45)
    $sc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $sc) { return 'Missing' }
    if ($sc.Status -eq 'Stopped') { return 'Stopped' }
    try { $sc.Stop() } catch { }
    try { $sc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSec)); return 'Stopped' } catch { }
    $sc.Refresh()
    return [string]$sc.Status
}

function Start-CSWDiskService {
    param([Parameter(Mandatory)][string]$Name)
    $sc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $sc) { return 'Missing' }
    if ($sc.Status -eq 'Running') { return 'Running' }
    try { $sc.Start(); $sc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)); return 'Running' }
    catch { Write-CSWLog "No se pudo iniciar ${Name}: $($_.Exception.Message)" -Level Warn; return 'Failed' }
}

function Get-CSWDiskMediaType {
    param([string]$Letter)
    try {
        $part = Get-Partition -DriveLetter $Letter -ErrorAction Stop
        $num = [string]$part.DiskNumber
        $pd = @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq $num }) | Select-Object -First 1
        if ($pd) {
            $m = [string]$pd.MediaType
            if ($m -eq 'SSD' -or $m -eq 'HDD' -or $m -eq 'SCM') { return $m }
            if ([string]$pd.BusType -eq 'NVMe') { return 'SSD' }
            $spin = Get-CSWDiskProp $pd 'SpindleSpeed'
            if ($null -ne $spin -and [int64]$spin -eq 0) { return 'SSD' }
            return 'Unspecified'
        }
    }
    catch { }
    return 'Unspecified'
}

# ---------------------------------------------------------------------------
# Estado de discos y espacio
# ---------------------------------------------------------------------------
function Get-CSWDiskHealth {
    <#
        Vista RAPIDA del estado de los discos. Si el modulo Hardware esta cargado se reutiliza su
        motor (Get-CSWHwDiskFindings) para que el veredicto sea identico al de
        "Salud de hardware > Salud de discos (SMART)"; si no, se aplica la misma logica basica
        con los mismos umbrales (desgaste SSD >= 70 % aviso, temperatura >= 60 C).
    #>
    if (Get-Command -Name Get-CSWHwDiskFindings -ErrorAction SilentlyContinue) {
        $f = @(Get-CSWHwDiskFindings)
        $verd = @($f | Where-Object { $_.EsVeredicto })
        foreach ($v in $verd) {
            $estado = [string]$v.Estado
            if ($estado -eq 'OK') { $estado = 'Correcto' }
            [pscustomobject]@{ Disco = $v.Componente; Estado = $estado; Veredicto = $v.Valor }
        }
        $issues = @($f | Where-Object { -not $_.EsVeredicto -and ($_.Estado -eq 'Fallo' -or $_.Estado -eq 'Aviso') })
        foreach ($i in $issues) { Write-CSWLog ("{0} - {1}: {2}. {3}" -f $i.Componente, $i.Prueba, $i.Valor, $i.Recomendacion) -Level Warn }
        $nd = @($f | Where-Object { -not $_.EsVeredicto -and $_.Estado -eq 'Sin datos' }).Count
        if ($nd) { Write-CSWLog "$nd dato(s) no disponibles (SMART/contadores requieren administrador o la controladora no los expone)." -Level Info }
        Write-CSWLog 'Detalle completo en Salud de hardware > Salud de discos (SMART).' -Level Info
        if (-not $verd.Count) { return (New-CSWResult -Summary 'No se detectaron discos fisicos' -Status Warn) }
        $bad = @($verd | Where-Object { $_.Estado -eq 'Fallo' })
        $obs = @($verd | Where-Object { $_.Estado -eq 'Aviso' })
        if ($bad.Count) { return (New-CSWResult -Summary ('Disco con fallo: {0}. Haga copia de seguridad y reemplace el disco.' -f (($bad | ForEach-Object { $_.Componente }) -join ', ')) -Status Warn) }
        if ($obs.Count) { return (New-CSWResult -Summary ('Discos con observaciones: {0}. Mantenga copias de seguridad al dia.' -f (($obs | ForEach-Object { $_.Componente }) -join ', ')) -Status Warn) }
        return (New-CSWResult -Summary ("{0} disco(s) fisico(s) en buen estado" -f $verd.Count))
    }

    $warns = New-Object System.Collections.Generic.List[string]
    $isAdmin = Test-CSWAdmin
    if (-not (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        Write-CSWLog 'Get-PhysicalDisk no disponible; se usa Win32_DiskDrive.' -Level Warn
        $dd = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
        foreach ($d in $dd) {
            [pscustomobject]@{ Modelo = $d.Model; Interfaz = $d.InterfaceType; Tamano = (Format-CSWDiskSize ([double]$d.Size)); Estado = $d.Status }
            if ([string]$d.Status -ne 'OK') { $warns.Add("$($d.Model): $($d.Status)") }
        }
        if ($warns.Count) { return (New-CSWResult -Summary ('Discos con problemas: ' + ($warns -join '; ')) -Status Warn) }
        return (New-CSWResult -Summary ("{0} disco(s) en estado correcto" -f $dd.Count) -Status OK)
    }

    $disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object { [int]$_.DeviceId })
    $noCounters = 0
    foreach ($d in $disks) {
        $rc = $null
        try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
        if (-not $rc) { $noCounters++ }
        $temp = Get-CSWDiskProp $rc 'Temperature'
        $wear = Get-CSWDiskProp $rc 'Wear'
        $hours = Get-CSWDiskProp $rc 'PowerOnHours'
        $rErr = Get-CSWDiskProp $rc 'ReadErrorsTotal'
        $wErr = Get-CSWDiskProp $rc 'WriteErrorsTotal'
        $rUnc = Get-CSWDiskProp $rc 'ReadErrorsUncorrected'
        $wUnc = Get-CSWDiskProp $rc 'WriteErrorsUncorrected'
        $health = [string]$d.HealthStatus
        $op = (@($d.OperationalStatus) | ForEach-Object { [string]$_ }) -join ', '
        $name = [string]$d.FriendlyName

        if ($health -ne 'Healthy') { $warns.Add("$name salud $health") }
        if ($null -ne $wear -and [int]$wear -ge 70) { $warns.Add("$name desgaste $wear%") }
        if ($null -ne $temp -and [int]$temp -ge 60) { $warns.Add("$name temperatura $temp C") }
        if ($null -ne $rUnc -and [int64]$rUnc -gt 0) { $warns.Add("$name $rUnc errores de lectura no corregidos") }
        if ($null -ne $wUnc -and [int64]$wUnc -gt 0) { $warns.Add("$name $wUnc errores de escritura no corregidos") }

        $na = 'N/D'
        [pscustomobject]@{
            Disco    = [string]$d.DeviceId
            Modelo   = $name
            Medio    = [string]$d.MediaType
            Bus      = [string]$d.BusType
            Tamano   = (Format-CSWDiskSize ([double]$d.Size))
            Salud    = $health
            Estado   = $op
            TempC    = $(if ($null -ne $temp -and [int]$temp -gt 0) { $temp } else { $na })
            Desgaste = $(if ($null -ne $wear) { "$wear%" } else { $na })
            Horas    = $(if ($null -ne $hours) { $hours } else { $na })
            ErrLect  = $(if ($null -ne $rErr) { $rErr } else { $na })
            ErrEscr  = $(if ($null -ne $wErr) { $wErr } else { $na })
        }
    }
    if ($noCounters -gt 0) {
        if (-not $isAdmin) { Write-CSWLog 'Los contadores de fiabilidad (temperatura, desgaste, errores) requieren administrador.' -Level Warn }
        else { Write-CSWLog "El controlador de $noCounters disco(s) no expone contadores de fiabilidad (normal en USB/RAID)." -Level Info }
    }

    # Prediccion de fallo SMART (driver de almacenamiento)
    try {
        $pf = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop | Where-Object { $_.PredictFailure })
        foreach ($p in $pf) { $warns.Add("SMART predice fallo en $($p.InstanceName)") }
    }
    catch { }

    if ($disks.Count -eq 0) { return (New-CSWResult -Summary 'No se detectaron discos fisicos' -Status Warn) }
    if ($warns.Count -gt 0) {
        foreach ($w in $warns) { Write-CSWLog $w -Level Warn }
        return (New-CSWResult -Summary ('Atencion en discos: ' + ($warns -join '; ') + '. Haga copia de seguridad cuanto antes.') -Status Warn)
    }
    return (New-CSWResult -Summary ("{0} disco(s) fisico(s) en buen estado" -f $disks.Count) -Status OK)
}

function Get-CSWDiskVolumeSpace {
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -gt 0 })
    $low = New-Object System.Collections.Generic.List[string]
    foreach ($v in $vols) {
        $pct = [math]::Round(([double]$v.FreeSpace / [double]$v.Size) * 100, 1)
        $tipo = 'Fijo'; if ([int]$v.DriveType -eq 2) { $tipo = 'Extraible' }
        $estado = 'OK'
        if ($pct -lt 15 -and [int]$v.DriveType -eq 3) { $estado = 'POCO ESPACIO'; $low.Add(('{0} ({1}% libre)' -f $v.DeviceID, $pct)) }
        [pscustomobject]@{
            Unidad    = $v.DeviceID
            Etiqueta  = $v.VolumeName
            Tipo      = $tipo
            FS        = $v.FileSystem
            Total     = (Format-CSWDiskSize ([double]$v.Size))
            Libre     = (Format-CSWDiskSize ([double]$v.FreeSpace))
            PctLibre  = $pct
            Estado    = $estado
        }
    }
    if ($vols.Count -eq 0) { return (New-CSWResult -Summary 'No se encontraron volumenes' -Status Warn) }
    if ($low.Count -gt 0) {
        Write-CSWLog ('Poco espacio libre en: ' + ($low -join ', ') + '. Windows necesita al menos un 15% libre para funcionar con fluidez.') -Level Warn
        return (New-CSWResult -Summary ('Poco espacio libre en ' + ($low -join ', ')) -Status Warn)
    }
    $sys = @($vols | Where-Object { $_.DeviceID -eq $env:SystemDrive }) | Select-Object -First 1
    $txt = "{0} volumen(es) con espacio suficiente" -f $vols.Count
    if ($sys) { $txt += (' ({0} {1} libres)' -f $sys.DeviceID, (Format-CSWDiskSize ([double]$sys.FreeSpace))) }
    return (New-CSWResult -Summary $txt -Status OK)
}

# ---------------------------------------------------------------------------
# Limpiezas
# ---------------------------------------------------------------------------
function Clear-CSWDiskTemp {
    $isAdmin = Test-CSWAdmin
    if (-not $isAdmin) { Write-CSWLog 'Sin permisos de administrador: solo se limpiaran los temporales accesibles.' -Level Warn }
    $exclude = Get-CSWDiskToolExclusions
    $minAge = 60

    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Get-CSWDiskProfilePaths)) { $targets.Add((Join-Path $p 'AppData\Local\Temp')) }
    if ($env:TEMP) { $targets.Add($env:TEMP) }
    $targets.Add((Join-Path $env:windir 'Temp'))
    $targets.Add((Join-Path $env:windir 'ServiceProfiles\LocalService\AppData\Local\Temp'))
    $targets.Add((Join-Path $env:windir 'ServiceProfiles\NetworkService\AppData\Local\Temp'))
    $targets.Add((Join-Path $env:windir 'System32\config\systemprofile\AppData\Local\Temp'))

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $before = Get-CSWDiskFreeBytes
    Write-CSWLog "Limpiando temporales (se conservan archivos en uso y los modificados en los ultimos $minAge minutos)..." -Level Step
    $totBytes = [int64]0; $totFiles = 0; $totFail = 0
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        $full = $t
        try { $full = (Get-Item -LiteralPath $t -Force -ErrorAction Stop).FullName } catch { continue }
        if (-not $seen.Add($full.TrimEnd('\'))) { continue }
        $r = Remove-CSWDiskFolderContent -Path $full -MinAgeMinutes $minAge -Exclude $exclude
        $totBytes += $r.Bytes; $totFiles += $r.Files; $totFail += $r.Failed
        if ($r.Files -gt 0 -or $r.Failed -gt 0) {
            $rows.Add([pscustomobject]@{ Carpeta = $full; Liberado = (Format-CSWDiskSize $r.Bytes); Archivos = $r.Files; EnUso = $r.Failed })
        }
    }
    $rows.ToArray()
    $after = Get-CSWDiskFreeBytes
    $mb = [math]::Round($totBytes / 1MB, 1)
    Write-CSWLog ("Eliminados {0} archivos; {1} en uso o protegidos se omitieron." -f $totFiles, $totFail) -Level Info
    if ($before -ge 0 -and $after -ge 0) { Write-CSWLog ("Espacio libre en {0}: {1} -> {2}" -f $env:SystemDrive, (Format-CSWDiskSize $before), (Format-CSWDiskSize $after)) -Level Info }
    return (New-CSWResult -Summary ("Archivos temporales eliminados: {0} MB liberados ({1} archivos)" -f $mb, $totFiles) -Status OK)
}

function Clear-CSWDiskDeep {
    $deny = Test-CSWDiskElevation 'Limpieza profunda'
    if ($deny) { return $deny }
    $rows = New-Object System.Collections.Generic.List[object]
    $total = [int64]0
    $profiles = Get-CSWDiskProfilePaths

    # 1) Cache de descargas de Windows Update
    Write-CSWLog 'Limpiando cache de descargas de Windows Update...' -Level Step
    $wuWas = @{}
    foreach ($n in 'wuauserv', 'bits') {
        $sc = Get-Service -Name $n -ErrorAction SilentlyContinue
        $wuWas[$n] = ($sc -and $sc.Status -eq 'Running')
        [void](Stop-CSWDiskService -Name $n)
    }
    $r = Remove-CSWDiskFolderContent -Path (Join-Path $env:windir 'SoftwareDistribution\Download')
    foreach ($n in 'bits', 'wuauserv') { if ($wuWas[$n]) { [void](Start-CSWDiskService -Name $n) } }
    $total += $r.Bytes
    $rows.Add([pscustomobject]@{ Elemento = 'Descargas de Windows Update'; Liberado = (Format-CSWDiskSize $r.Bytes); Archivos = $r.Files; Omitidos = $r.Failed })

    # 2) Miniaturas de todos los perfiles
    Write-CSWLog 'Limpiando cache de miniaturas...' -Level Step
    $tb = [int64]0; $tf = 0; $tx = 0
    foreach ($p in $profiles) {
        $dir = Join-Path $p 'AppData\Local\Microsoft\Windows\Explorer'
        if (-not [System.IO.Directory]::Exists($dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter 'thumbcache_*.db' -Force -ErrorAction SilentlyContinue)) {
            try { $len = [int64]$f.Length; Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $tb += $len; $tf++ } catch { $tx++ }
        }
    }
    $total += $tb
    $rows.Add([pscustomobject]@{ Elemento = 'Miniaturas'; Liberado = (Format-CSWDiskSize $tb); Archivos = $tf; Omitidos = $tx })

    # 3) Informes de errores de Windows (WER)
    Write-CSWLog 'Limpiando informes de errores de Windows...' -Level Step
    $werDirs = New-Object System.Collections.Generic.List[string]
    foreach ($s in 'ReportArchive', 'ReportQueue', 'Temp') { $werDirs.Add((Join-Path $env:ProgramData "Microsoft\Windows\WER\$s")) }
    foreach ($p in $profiles) { $werDirs.Add((Join-Path $p 'AppData\Local\Microsoft\Windows\WER')) }
    $wb = [int64]0; $wf = 0; $wx = 0
    foreach ($d in $werDirs) {
        $r = Remove-CSWDiskFolderContent -Path $d
        $wb += $r.Bytes; $wf += $r.Files; $wx += $r.Failed
    }
    $total += $wb
    $rows.Add([pscustomobject]@{ Elemento = 'Informes de errores (WER)'; Liberado = (Format-CSWDiskSize $wb); Archivos = $wf; Omitidos = $wx })

    # 4) Optimizacion de distribucion (Delivery Optimization)
    Write-CSWLog 'Limpiando cache de Optimizacion de distribucion...' -Level Step
    $doPaths = @((Join-Path $env:windir 'SoftwareDistribution\DeliveryOptimization'),
        (Join-Path $env:windir 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache'))
    $doBefore = [int64]0; foreach ($d in $doPaths) { $doBefore += (Measure-CSWDiskPath $d).Bytes }
    $doState = ''
    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        try { Delete-DeliveryOptimizationCache -Force -ErrorAction Stop | Out-Null }
        catch { $doState = 'Error'; Write-CSWLog "Delivery Optimization: $($_.Exception.Message)" -Level Warn }
    }
    else { $doState = 'No disponible'; Write-CSWLog 'Delete-DeliveryOptimizationCache no disponible en esta version de Windows.' -Level Info }
    $doAfter = [int64]0; foreach ($d in $doPaths) { $doAfter += (Measure-CSWDiskPath $d).Bytes }
    $doFreed = [math]::Max([int64]0, $doBefore - $doAfter)
    $total += $doFreed
    $rows.Add([pscustomobject]@{ Elemento = 'Optimizacion de distribucion'; Liberado = (Format-CSWDiskSize $doFreed); Archivos = ''; Omitidos = $doState })

    # 5) Papelera de reciclaje (todas las unidades y usuarios)
    Write-CSWLog 'Vaciando la papelera de reciclaje...' -Level Step
    $bins = New-Object System.Collections.Generic.List[string]
    foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $b = Join-Path ($ld.DeviceID + '\') '$Recycle.Bin'
        if ([System.IO.Directory]::Exists($b)) { $bins.Add($b) }
    }
    $rbBefore = [int64]0; foreach ($b in $bins) { $rbBefore += (Measure-CSWDiskPath $b).Bytes }
    if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
        try { Clear-RecycleBin -Force -ErrorAction Stop } catch { }
    }
    foreach ($b in $bins) {
        try {
            foreach ($sid in (New-Object System.IO.DirectoryInfo($b)).GetDirectories()) {
                if ($sid.Name -notmatch '^S-1-') { continue }
                [void](Remove-CSWDiskFolderContent -Path $sid.FullName -KeepNames @('desktop.ini'))
            }
        }
        catch { }
    }
    $rbAfter = [int64]0; foreach ($b in $bins) { $rbAfter += (Measure-CSWDiskPath $b).Bytes }
    $rbFreed = [math]::Max([int64]0, $rbBefore - $rbAfter)
    $total += $rbFreed
    $rows.Add([pscustomobject]@{ Elemento = 'Papelera de reciclaje'; Liberado = (Format-CSWDiskSize $rbFreed); Archivos = ''; Omitidos = '' })

    $rows.ToArray()
    return (New-CSWResult -Summary ("Limpieza profunda completada: {0:N1} MB liberados" -f ($total / 1MB)) -Status OK)
}

function Clear-CSWDiskBrowserCache {
    if (-not (Test-CSWAdmin)) { Write-CSWLog 'Sin administrador solo se limpiara el perfil del usuario actual.' -Level Warn }
    $browsers = @(
        @{ Name = 'Google Chrome'; Proc = 'chrome'; Rel = 'AppData\Local\Google\Chrome\User Data'; Kind = 'Chromium' },
        @{ Name = 'Microsoft Edge'; Proc = 'msedge'; Rel = 'AppData\Local\Microsoft\Edge\User Data'; Kind = 'Chromium' },
        @{ Name = 'Brave'; Proc = 'brave'; Rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; Kind = 'Chromium' },
        @{ Name = 'Mozilla Firefox'; Proc = 'firefox'; Rel = 'AppData\Local\Mozilla\Firefox\Profiles'; Kind = 'Gecko' }
    )
    $profiles = Get-CSWDiskProfilePaths
    $rows = New-Object System.Collections.Generic.List[object]
    $total = [int64]0; $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($b in $browsers) {
        $roots = @($profiles | ForEach-Object { Join-Path $_ $b.Rel } | Where-Object { [System.IO.Directory]::Exists($_) })
        if ($roots.Count -eq 0) { continue }
        if (@(Get-Process -Name $b.Proc -ErrorAction SilentlyContinue).Count -gt 0) {
            $extra = ''
            if ($b.Proc -eq 'msedge') { $extra = ' (Edge puede seguir en segundo plano por "Inicio rapido")' }
            Write-CSWLog ("{0} esta abierto{1}: se omite. Cierrelo y repita la limpieza." -f $b.Name, $extra) -Level Warn
            $skipped.Add($b.Name)
            $rows.Add([pscustomobject]@{ Navegador = $b.Name; Perfiles = ''; Liberado = ''; Archivos = ''; Estado = 'Omitido (abierto)' })
            continue
        }
        Write-CSWLog "Limpiando cache de $($b.Name)..." -Level Step
        $bytes = [int64]0; $files = 0; $nprof = 0
        foreach ($root in $roots) {
            $dirs = @()
            try { $dirs = @((New-Object System.IO.DirectoryInfo($root)).GetDirectories() | Where-Object { ([int]$_.Attributes -band 0x400) -eq 0 }) } catch { continue }
            foreach ($pd in $dirs) {
                $sub = @()
                if ($b.Kind -eq 'Chromium') {
                    if (-not [System.IO.File]::Exists((Join-Path $pd.FullName 'Preferences'))) { continue }
                    $sub = @('Cache', 'Code Cache', 'GPUCache')
                }
                else { $sub = @('cache2') }
                $nprof++
                foreach ($s in $sub) {
                    $r = Remove-CSWDiskFolderContent -Path (Join-Path $pd.FullName $s)
                    $bytes += $r.Bytes; $files += $r.Files
                }
            }
        }
        $total += $bytes
        $rows.Add([pscustomobject]@{ Navegador = $b.Name; Perfiles = $nprof; Liberado = (Format-CSWDiskSize $bytes); Archivos = $files; Estado = 'Limpio' })
    }
    if ($rows.Count -eq 0) { return (New-CSWResult -Summary 'No se encontraron navegadores compatibles (Chrome, Edge, Brave, Firefox)' -Status Warn) }
    $rows.ToArray()
    $sum = "Cache de navegadores limpiada: {0:N1} MB liberados (sin tocar cookies, contrasenas ni historial)" -f ($total / 1MB)
    if ($skipped.Count -gt 0) { return (New-CSWResult -Summary ($sum + '. Omitidos por estar abiertos: ' + ($skipped -join ', ')) -Status Warn) }
    return (New-CSWResult -Summary $sum -Status OK)
}

function Invoke-CSWDiskCleanMgr {
    param([object]$IncludePreviousInstall = $false)
    $deny = Test-CSWDiskElevation 'Liberador de espacio'
    if ($deny) { return $deny }
    $exe = Get-CSWDiskSysExe 'cleanmgr.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return (New-CSWResult -Summary 'El Liberador de espacio (cleanmgr) no esta disponible en este sistema' -Status Warn) }

    $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $flag = 'StateFlags0099'
    # Lista segura: NO incluye Descargas del usuario, archivos ESD de restablecimiento ni minidumps
    $allow = @('Active Setup Temp Folders', 'BranchCache', 'D3D Shader Cache', 'Delivery Optimization Files',
        'Device Driver Packages', 'Diagnostic Data Viewer database files', 'Downloaded Program Files',
        'Internet Cache Files', 'Old ChkDsk Files', 'Recycle Bin', 'RetailDemo Offline Content',
        'Setup Log Files', 'System error memory dump files', 'Temporary Files', 'Temporary Setup Files',
        'Temporary Sync Files', 'Thumbnail Cache', 'Update Cleanup', 'Upgrade Discarded Files',
        'Windows Defender', 'Windows Error Reporting Files', 'Windows Upgrade Log Files',
        'Feedback Hub Archive log files')
    if (ConvertTo-CSWDiskBool $IncludePreviousInstall) {
        $allow += 'Previous Installations'
        Write-CSWLog 'Se incluye Windows.old: ya no se podra volver a la version anterior de Windows.' -Level Warn
    }
    $keys = @(Get-ChildItem -Path $base -ErrorAction SilentlyContinue)
    $set = 0
    foreach ($k in $keys) {
        try {
            if ($allow -contains $k.PSChildName) { Set-ItemProperty -Path $k.PSPath -Name $flag -Value 2 -Type DWord -ErrorAction Stop; $set++ }
            else { Remove-ItemProperty -Path $k.PSPath -Name $flag -ErrorAction SilentlyContinue }
        }
        catch { }
    }
    Write-CSWLog "Categorias de limpieza preconfiguradas: $set" -Level Info

    $before = Get-CSWDiskFreeBytes
    $start = Get-Date
    try {
        Write-CSWLog 'Ejecutando el Liberador de espacio (cleanmgr /sagerun:99); puede tardar bastante...' -Level Step
        $p = Start-Process -FilePath $exe -ArgumentList '/sagerun:99' -PassThru -WindowStyle Hidden -ErrorAction Stop
        $limit = $start.AddMinutes(120); $lastLog = $start
        while ($true) {
            $running = @(Get-Process -Name cleanmgr -ErrorAction SilentlyContinue)
            if ($p.HasExited -and $running.Count -eq 0) { break }
            if ((Get-Date) -gt $limit) { Write-CSWLog 'El Liberador de espacio supera 2 horas; se deja en segundo plano.' -Level Warn; break }
            if (((Get-Date) - $lastLog).TotalMinutes -ge 2) { Write-CSWLog ("Liberador de espacio en curso ({0:N0} min)..." -f ((Get-Date) - $start).TotalMinutes) -Level Info; $lastLog = Get-Date }
            Start-Sleep -Seconds 5
        }
    }
    catch {
        Write-CSWLog "No se pudo ejecutar cleanmgr: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudo ejecutar el Liberador de espacio' -Status Error)
    }
    finally {
        foreach ($k in $keys) { Remove-ItemProperty -Path $k.PSPath -Name $flag -ErrorAction SilentlyContinue }
    }
    $after = Get-CSWDiskFreeBytes
    $freed = ''
    if ($before -ge 0 -and $after -ge 0) { $freed = ' ({0:N0} MB liberados)' -f ([math]::Max(0, $after - $before) / 1MB) }
    return (New-CSWResult -Summary "Liberador de espacio de Windows completado$freed" -Status OK)
}

# ---------------------------------------------------------------------------
# Optimizacion de unidades
# ---------------------------------------------------------------------------
function Optimize-CSWDiskVolumes {
    param([string]$Drive = 'C')
    $deny = Test-CSWDiskElevation 'Optimizar unidades'
    if ($deny) { return $deny }
    if (-not (Get-Command Optimize-Volume -ErrorAction SilentlyContinue)) {
        return (New-CSWResult -Summary 'Optimize-Volume no esta disponible en este sistema' -Status Warn)
    }
    $letters = @()
    if (-not $Drive -or $Drive.Trim() -match '^(todas|todos|all|\*)$') {
        $letters = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
                Where-Object { @('NTFS', 'ReFS') -contains [string]$_.FileSystem } | ForEach-Object { $_.DeviceID.Substring(0, 1) })
    }
    else {
        $l = $Drive.Trim().TrimEnd('\').TrimEnd(':')
        if ($l -notmatch '^[A-Za-z]$') { return (New-CSWResult -Summary "Unidad no valida: '$Drive' (use una letra o TODAS)" -Status Error) }
        $letters = @($l.ToUpper())
    }
    if ($letters.Count -eq 0) { return (New-CSWResult -Summary 'No hay unidades NTFS/ReFS para optimizar' -Status Warn) }

    $rows = New-Object System.Collections.Generic.List[object]
    $errors = 0
    foreach ($l in $letters) {
        $media = Get-CSWDiskMediaType $l
        $op = 'Automatica'
        $params = @{ DriveLetter = $l; Verbose = $true; ErrorAction = 'Stop' }
        if ($media -eq 'SSD' -or $media -eq 'SCM') { $op = 'ReTrim'; $params.ReTrim = $true }
        elseif ($media -eq 'HDD') { $op = 'Desfragmentar'; $params.Defrag = $true }
        Write-CSWLog "Optimizando ${l}: (medio $media, operacion $op)..." -Level Step
        $t0 = Get-Date
        $res = 'Correcto'
        try {
            $out = Optimize-Volume @params 4>&1
            foreach ($o in @($out)) {
                if ($o -is [System.Management.Automation.VerboseRecord]) {
                    $m = [string]$o.Message
                    if ($m -and $m -notmatch '\d+\s*%') { Write-CSWLog $m -Level Data }
                }
            }
        }
        catch {
            $errors++
            $res = 'Error: ' + $_.Exception.Message
            Write-CSWLog "Error al optimizar ${l}: $($_.Exception.Message)" -Level Warn
        }
        $rows.Add([pscustomobject]@{ Unidad = "${l}:"; Medio = $media; Operacion = $op; Resultado = $res; Duracion = ('{0:mm\:ss}' -f ((Get-Date) - $t0)) })
    }
    $rows.ToArray()
    if ($errors -gt 0) { return (New-CSWResult -Summary ("Optimizacion completada con {0} error(es)" -f $errors) -Status Warn) }
    return (New-CSWResult -Summary ("Unidades optimizadas: {0}" -f (($rows | ForEach-Object { "$($_.Unidad) $($_.Operacion)" }) -join ', ')) -Status OK)
}

# ---------------------------------------------------------------------------
# Analisis de espacio
# ---------------------------------------------------------------------------
function Get-CSWDiskLargestFolders {
    param([string]$Path = 'C:\Users', [int]$Top = 15)
    if (-not $Path) { $Path = 'C:\Users' }
    $Path = $Path.Trim().Trim('"')
    if ($Path -match '^[A-Za-z]:$') { $Path += '\' }
    if (-not [System.IO.Directory]::Exists($Path)) { return (New-CSWResult -Summary "La ruta '$Path' no existe" -Status Error) }
    if (-not (Test-CSWAdmin)) { Write-CSWLog 'Sin administrador, las carpetas de otros usuarios no se pueden medir.' -Level Warn }
    $fast = Initialize-CSWDiskScanner
    Write-CSWLog "Midiendo subcarpetas de $Path..." -Level Step

    $rootInfo = New-Object System.IO.DirectoryInfo($Path)
    $children = @()
    try { $children = @($rootInfo.GetFileSystemInfos()) }
    catch { return (New-CSWResult -Summary "Acceso denegado a '$Path'" -Status Error) }

    $results = New-Object System.Collections.Generic.List[object]
    $looseBytes = [int64]0; $looseFiles = 0
    $errTotal = [int64]0
    foreach ($c in $children) {
        $a = [int]$c.Attributes
        if ($a -band 0x10) {
            if ($a -band 0x400) { continue }
            if ($fast) { $e = [CybersutroWin.DiskScanner]::Measure($c.FullName) } else { $e = Measure-CSWDiskTreeFallback -Root $c.FullName }
            $errTotal += [int64]$e.Errors
            $results.Add([pscustomobject]@{ Carpeta = $c.FullName; Bytes = [int64]$e.Bytes; Archivos = [int64]$e.Files; Inaccesibles = [int64]$e.Errors })
        }
        elseif (-not ($a -band 0x441000)) {
            try { $looseBytes += [int64]$c.Length; $looseFiles++ } catch { }
        }
    }
    if ($looseFiles -gt 0) {
        $results.Add([pscustomobject]@{ Carpeta = (Join-Path $Path '(archivos sueltos)'); Bytes = $looseBytes; Archivos = [int64]$looseFiles; Inaccesibles = [int64]0 })
    }
    $sum = [int64]0; foreach ($r in $results) { $sum += $r.Bytes }
    $topList = @($results | Sort-Object -Property Bytes -Descending | Select-Object -First $Top)
    foreach ($r in $topList) {
        $pct = 0; if ($sum -gt 0) { $pct = [math]::Round(($r.Bytes / $sum) * 100, 1) }
        [pscustomobject]@{ Carpeta = $r.Carpeta; Tamano = (Format-CSWDiskSize $r.Bytes); Pct = $pct; Archivos = $r.Archivos; Inaccesibles = $r.Inaccesibles }
    }
    if ($errTotal -gt 0) { Write-CSWLog "$errTotal elementos no se pudieron leer (permisos o rutas largas); los tamanos pueden ser algo menores." -Level Info }
    if ($topList.Count -eq 0) { return (New-CSWResult -Summary "La carpeta '$Path' esta vacia" -Status OK) }
    return (New-CSWResult -Summary ("{0} ocupa {1}; la carpeta mas grande es {2} ({3})" -f $Path, (Format-CSWDiskSize $sum), (Split-Path $topList[0].Carpeta -Leaf), (Format-CSWDiskSize $topList[0].Bytes)) -Status OK)
}

function Get-CSWDiskLargestFiles {
    param([string]$Path = 'C:\', [int]$MinMB = 500, [int]$Top = 25)
    if (-not $Path) { $Path = 'C:\' }
    $Path = $Path.Trim().Trim('"')
    if ($Path -match '^[A-Za-z]:$') { $Path += '\' }
    if (-not [System.IO.Directory]::Exists($Path)) { return (New-CSWResult -Summary "La ruta '$Path' no existe" -Status Error) }
    if ($MinMB -lt 1) { $MinMB = 1 }
    $min = [int64]$MinMB * 1MB
    Write-CSWLog "Buscando archivos de mas de $MinMB MB en $Path (puede tardar unos minutos)..." -Level Step
    $hits = @()
    $errors = [int64]0
    if (Initialize-CSWDiskScanner) {
        $list = New-Object 'System.Collections.Generic.List[CybersutroWin.DiskScanEntry]'
        $e = [CybersutroWin.DiskScanner]::FindLarge($Path, $min, $list)
        $errors = $e.Errors
        $hits = @($list | ForEach-Object { [pscustomobject]@{ Path = $_.Path; Bytes = [int64]$_.Bytes; LastWrite = $_.LastWrite } })
    }
    else {
        $al = New-Object System.Collections.ArrayList
        $e = Measure-CSWDiskTreeFallback -Root $Path -MinBytes $min -Hits $al
        $errors = $e.Errors
        $hits = @($al)
    }
    $topList = @($hits | Sort-Object -Property Bytes -Descending | Select-Object -First $Top)
    foreach ($h in $topList) {
        [pscustomobject]@{ Archivo = $h.Path; Tamano = (Format-CSWDiskSize $h.Bytes); Modificado = $h.LastWrite.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
    }
    if ($errors -gt 0) { Write-CSWLog "$errors carpetas/elementos no se pudieron leer (permisos)." -Level Info }
    if ($hits.Count -eq 0) { return (New-CSWResult -Summary "No hay archivos de mas de $MinMB MB en $Path" -Status OK) }
    $sum = [int64]0; foreach ($h in $hits) { $sum += $h.Bytes }
    return (New-CSWResult -Summary ("{0} archivo(s) de mas de {1} MB en {2} (total {3})" -f $hits.Count, $MinMB, $Path, (Format-CSWDiskSize $sum)) -Status OK)
}

# ---------------------------------------------------------------------------
# Hibernacion y archivo de paginacion
# ---------------------------------------------------------------------------
function Get-CSWDiskRootFileSize {
    param([string]$Name)
    try {
        $f = @((New-Object System.IO.DirectoryInfo($env:SystemDrive + '\')).GetFiles($Name))
        if ($f.Count -gt 0) { return [int64]$f[0].Length }
    }
    catch { }
    return [int64]-1
}

function Get-CSWDiskHibernationInfo {
    $hib = Get-CSWDiskRootFileSize 'hiberfil.sys'
    $pag = Get-CSWDiskRootFileSize 'pagefile.sys'
    $swp = Get-CSWDiskRootFileSize 'swapfile.sys'
    $hibOn = $null; $fast = $null
    try { $hibOn = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction Stop).HibernateEnabled -eq 1 } catch { }
    try { $fast = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled -eq 1 } catch { }
    $auto = $null; $ram = [int64]0
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $auto = [bool]$cs.AutomaticManagedPagefile; $ram = [int64]$cs.TotalPhysicalMemory } catch { }
    $laptop = $false
    try { $laptop = @(Get-CimInstance Win32_Battery -ErrorAction Stop).Count -gt 0 } catch { }

    $yn = { param($v) if ($null -eq $v) { 'Desconocido' } elseif ($v) { 'Si' } else { 'No' } }
    $sz = { param($v) if ($v -lt 0) { 'No existe' } else { Format-CSWDiskSize $v } }

    [pscustomobject]@{ Elemento = 'Memoria RAM'; Valor = (Format-CSWDiskSize $ram) }
    [pscustomobject]@{ Elemento = 'Hibernacion activada'; Valor = (& $yn $hibOn) }
    [pscustomobject]@{ Elemento = 'Inicio rapido'; Valor = (& $yn $fast) }
    [pscustomobject]@{ Elemento = 'hiberfil.sys'; Valor = (& $sz $hib) }
    [pscustomobject]@{ Elemento = 'pagefile.sys'; Valor = (& $sz $pag) }
    [pscustomobject]@{ Elemento = 'swapfile.sys'; Valor = (& $sz $swp) }
    [pscustomobject]@{ Elemento = 'Paginacion gestionada por Windows'; Valor = (& $yn $auto) }
    try {
        foreach ($u in @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)) {
            [pscustomobject]@{ Elemento = "Uso de $($u.Name)"; Valor = ('{0} MB asignados, uso actual {1} MB, pico {2} MB' -f $u.AllocatedBaseSize, $u.CurrentUsage, $u.PeakUsage) }
        }
    }
    catch { }
    [pscustomobject]@{ Elemento = 'Tipo de equipo'; Valor = $(if ($laptop) { 'Portatil (con bateria)' } else { 'Sobremesa' }) }

    if ($hib -gt 0) {
        if ($laptop) { Write-CSWLog 'Portatil: se recomienda mantener la hibernacion (protege ante bateria agotada).' -Level Info }
        else { Write-CSWLog ("Sobremesa: desactivar la hibernacion liberaria {0} (tambien desactiva el inicio rapido)." -f (Format-CSWDiskSize $hib)) -Level Info }
    }
    if ($null -ne $auto -and -not $auto) { Write-CSWLog 'El archivo de paginacion tiene tamano manual; si hay errores de memoria, vuelva a gestion automatica.' -Level Info }
    $txt = 'hiberfil.sys: {0}; pagefile.sys: {1}' -f (& $sz $hib), (& $sz $pag)
    return (New-CSWResult -Summary $txt -Status OK)
}

function Disable-CSWDiskHibernation {
    $deny = Test-CSWDiskElevation 'Desactivar hibernacion'
    if ($deny) { return $deny }
    $before = Get-CSWDiskRootFileSize 'hiberfil.sys'
    $code = Invoke-CSWExternal -FilePath (Get-CSWDiskSysExe 'powercfg.exe') -Arguments '/hibernate off'
    if ($code -ne 0) { return (New-CSWResult -Summary "No se pudo desactivar la hibernacion (codigo $code)" -Status Error) }
    Start-Sleep -Seconds 1
    $after = Get-CSWDiskRootFileSize 'hiberfil.sys'
    $freed = ''
    if ($before -gt 0 -and $after -lt 0) { $freed = " ({0} liberados)" -f (Format-CSWDiskSize $before) }
    return (New-CSWResult -Summary "Hibernacion e inicio rapido desactivados$freed" -Status OK)
}

function Enable-CSWDiskHibernation {
    $deny = Test-CSWDiskElevation 'Activar hibernacion'
    if ($deny) { return $deny }
    $code = Invoke-CSWExternal -FilePath (Get-CSWDiskSysExe 'powercfg.exe') -Arguments '/hibernate on'
    if ($code -ne 0) { return (New-CSWResult -Summary "No se pudo activar la hibernacion (codigo $code)" -Status Error) }
    return (New-CSWResult -Summary 'Hibernacion activada (y disponible el inicio rapido)' -Status OK)
}

# ---------------------------------------------------------------------------
# Registro del modulo
# ---------------------------------------------------------------------------
Register-CSWModule -Id 'Disk' -Name 'Disco y limpieza' -Order 40 -Icon 'disk' `
    -Description 'Salud de discos, espacio libre, limpieza y optimización de unidades' -Actions @(
    @{ Id = 'DiskHealth'; Name = 'Estado de discos'; Command = 'Get-CSWDiskHealth'; Risk = 'Low'
       Description = 'Vista rápida: veredicto de salud de cada disco físico (mismo criterio que Salud de hardware > Salud de discos).' }
    @{ Id = 'VolumeSpace'; Name = 'Espacio en unidades'; Command = 'Get-CSWDiskVolumeSpace'; Risk = 'Low'
       Description = 'Espacio total y libre de cada unidad; avisa si queda menos del 15%.' }
    @{ Id = 'CleanTemp'; Name = 'Limpiar temporales'; Command = 'Clear-CSWDiskTemp'; Risk = 'Low'
       Description = 'Borra archivos temporales de todos los usuarios y de Windows (omite archivos en uso).' }
    @{ Id = 'DeepClean'; Name = 'Limpieza profunda'; Command = 'Clear-CSWDiskDeep'; Risk = 'Medium'; LongRunning = $true
       Description = 'Borra descargas de Windows Update, miniaturas, informes de errores, cache de Optimización de distribución y vacía la papelera.'
       ConfirmMessage = 'Se vaciará la papelera de reciclaje de TODOS los usuarios y se borrarán caches de Windows Update, miniaturas e informes de errores. Lo que haya en la papelera no se podrá recuperar.' }
    @{ Id = 'BrowserCache'; Name = 'Limpiar caché de navegadores'; Command = 'Clear-CSWDiskBrowserCache'; Risk = 'Medium'
       Description = 'Borra solo la cache (Cache, Code Cache, GPUCache, cache2) de Chrome, Edge, Brave y Firefox. No toca cookies, contraseñas ni historial.'
       ConfirmMessage = 'Los navegadores deben estar cerrados; los que estén abiertos se omitirán. Las páginas cargarán algo más lentas la primera vez. No se borran cookies, contraseñas ni historial.' }
    @{ Id = 'CleanMgr'; Name = 'Liberador de espacio de Windows'; Command = 'Invoke-CSWDiskCleanMgr'; Risk = 'Medium'; LongRunning = $true
       Description = 'Ejecuta cleanmgr con una selección segura de categorías (incluye limpieza de actualizaciones).'
       ConfirmMessage = 'Se ejecutará el Liberador de espacio de Windows con categorías seguras (no borra la carpeta Descargas). Puede tardar de 5 a 60 minutos.'
       Inputs = @(@{ Name = 'IncludePreviousInstall'; Label = 'Incluir Windows.old (impide volver a la versión anterior)'; Type = 'Bool'; Default = 'False' }) }
    @{ Id = 'Optimize'; Name = 'Optimizar unidades'; Command = 'Optimize-CSWDiskVolumes'; Risk = 'Medium'; LongRunning = $true
       Description = 'ReTrim en SSD y desfragmentación en HDD, detectando automáticamente el tipo de disco.'
       ConfirmMessage = 'Se optimizará la unidad (TRIM en SSD, desfragmentación en HDD). En discos duros mecánicos puede tardar horas y ralentizar el equipo mientras tanto.'
       Inputs = @(@{ Name = 'Drive'; Label = 'Unidad (letra o TODAS)'; Default = 'C' }) }
    @{ Id = 'LargestFolders'; Name = 'Carpetas más grandes'; Command = 'Get-CSWDiskLargestFolders'; Risk = 'Low'; LongRunning = $true
       Description = 'Mide el tamaño de cada subcarpeta de la ruta indicada y muestra las 15 mayores.'
       Inputs = @(@{ Name = 'Path'; Label = 'Ruta'; Default = 'C:\Users' }) }
    @{ Id = 'LargestFiles'; Name = 'Archivos más grandes'; Command = 'Get-CSWDiskLargestFiles'; Risk = 'Low'; LongRunning = $true
       Description = 'Busca los 25 archivos más grandes por encima del tamaño mínimo indicado.'
       Inputs = @(@{ Name = 'Path'; Label = 'Ruta'; Default = 'C:\' }, @{ Name = 'MinMB'; Label = 'Tamaño mínimo (MB)'; Default = '500' }) }
    @{ Id = 'HibernationInfo'; Name = 'Hibernación y paginación'; Command = 'Get-CSWDiskHibernationInfo'; Risk = 'Low'
       Description = 'Muestra el tamaño de hiberfil.sys, pagefile.sys y swapfile.sys y el estado de hibernación e inicio rápido.' }
    @{ Id = 'DisableHibernation'; Name = 'Desactivar hibernación'; Command = 'Disable-CSWDiskHibernation'; Risk = 'High'; ModifiesSystem = $true
       Description = 'Desactiva la hibernación (powercfg -h off) y elimina hiberfil.sys para liberar espacio.'
       ConfirmMessage = 'Se desactivará la hibernación y el inicio rápido de Windows y se eliminará hiberfil.sys. En portátiles, si la batería se agota no se guardará la sesión. Se puede revertir con "Activar hibernación".' }
    @{ Id = 'EnableHibernation'; Name = 'Activar hibernación'; Command = 'Enable-CSWDiskHibernation'; Risk = 'Medium'; ModifiesSystem = $true
       Description = 'Vuelve a activar la hibernación y el inicio rápido (powercfg -h on).'
       ConfirmMessage = 'Se activará la hibernación; se creará hiberfil.sys (ocupa parte del tamaño de la RAM en C:).' }
)

Export-ModuleMember -Function *
