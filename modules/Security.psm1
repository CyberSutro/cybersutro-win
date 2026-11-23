#Requires -Version 5.1
<#
    Cybersutro win - Modulo Seguridad (Security)
    Herramienta DEFENSIVA de soporte: diagnostico de Defender, firewall, puertos,
    autoarranques, administradores, BitLocker, postura de seguridad, parches y hosts.
    Nunca desactiva protecciones. Nunca muestra claves de recuperacion de BitLocker.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

$script:SecRunKeys = @(
    @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
    @{ Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
)

# Rutas donde un ejecutable de arranque merece revision
$script:SecSuspiciousPathRegex = '(?i)(\\AppData\\|\\Temp\\|\\Tmp\\|^[A-Z]:\\ProgramData\\|\\Users\\Public\\|\\Windows\\Tasks\\|\\Recycle)'

# Cache de firmas Authenticode por ruta (evita verificar el mismo binario muchas veces)
$script:SecSigCache = @{}

# Interpretes / binarios del sistema que suelen abusarse para lanzar otra cosa
$script:SecScriptHosts = @('powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'conhost.exe', 'msiexec.exe', 'forfiles.exe', 'bitsadmin.exe', 'certutil.exe')

# Puertos que conviene no exponer en todas las interfaces de un equipo de cliente
$script:SecRiskyPorts = @{
    21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 3389 = 'Escritorio remoto (RDP)'; 5800 = 'VNC web'; 5900 = 'VNC'; 5901 = 'VNC'; 5938 = 'TeamViewer'
    1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL'; 6379 = 'Redis'; 27017 = 'MongoDB'
}
$script:SecInfoPorts = @{ 135 = 'RPC'; 139 = 'NetBIOS'; 445 = 'SMB (compartir archivos)'; 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS'; 22 = 'SSH'; 80 = 'HTTP'; 443 = 'HTTPS'; 7680 = 'Optimizacion de distribucion' }

$script:SecDefaultHosts = @'
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
'@

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------
function Get-CSWSecProp {
    # Lectura segura de propiedades (StrictMode lanza si no existen)
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

function ConvertTo-CSWSecBool {
    param($Value)
    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $false }
    return ([string]$Value -match '^\s*(1|true|\$true|si|s|yes|y)\s*$')
}

function New-CSWSecRow {
    param([string]$Elemento, $Valor, [string]$Estado = 'OK')
    return [pscustomobject]@{ Elemento = $Elemento; Valor = [string]$Valor; Estado = $Estado }
}

function Get-CSWSecYesNo { param($Value) if ($Value) { return 'Si' } return 'No' }

function Test-CSWSecSuspiciousPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -match $script:SecSuspiciousPathRegex)
}

function Get-CSWSecSignature {
    # Devuelve estado de firma Authenticode y firmante (CN)
    param([string]$Path)
    $r = [pscustomobject]@{ Status = 'N/D'; Signer = ''; Valid = $false }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $r }
    $key = $Path.ToLowerInvariant()
    if ($script:SecSigCache.ContainsKey($key)) { return $script:SecSigCache[$key] }
    $script:SecSigCache[$key] = $r
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $r.Status = [string]$sig.Status
        $r.Valid = ($r.Status -eq 'Valid')
        if ($sig.SignerCertificate) {
            $subj = $sig.SignerCertificate.Subject
            if ($subj -match 'CN=("[^"]+"|[^,]+)') { $r.Signer = $Matches[1].Trim('"') } else { $r.Signer = $subj }
        }
    }
    catch { $r.Status = 'Error' }
    return $r
}

function Resolve-CSWSecExecutable {
    # Convierte un nombre de programa en ruta completa si es posible
    param([string]$Exe)
    if (-not $Exe) { return '' }
    $Exe = $Exe.Trim().Trim('"')
    if ([System.IO.Path]::IsPathRooted($Exe)) { return $Exe }
    $candidates = @()
    $names = @($Exe)
    if (-not [System.IO.Path]::HasExtension($Exe)) { $names += "$Exe.exe" }
    foreach ($n in $names) {
        $candidates += (Join-Path $env:SystemRoot "System32\$n")
        $candidates += (Join-Path $env:SystemRoot $n)
        $candidates += (Join-Path $env:SystemRoot "SysWOW64\$n")
    }
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    $cmd = Get-Command -Name $Exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $Exe
}

function Split-CSWSecCommandLine {
    # Separa una linea de comando en ejecutable + argumentos
    param([string]$CommandLine)
    $res = [pscustomobject]@{ Exe = ''; Arguments = '' }
    if (-not $CommandLine) { return $res }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $res.Exe = $c.Substring(1, $end - 1); $res.Arguments = $c.Substring($end + 1).Trim() }
        else { $res.Exe = $c.Trim('"') }
    }
    else {
        $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|lnk|msi|dll|cpl|pif))(?=\s|,|$)', 'IgnoreCase')
        if ($m.Success) { $res.Exe = $m.Groups[1].Value; $res.Arguments = $c.Substring($m.Groups[1].Length).Trim() }
        else {
            $parts = $c -split '\s+', 2
            $res.Exe = $parts[0]
            if ($parts.Count -gt 1) { $res.Arguments = $parts[1] }
        }
    }
    $res.Exe = Resolve-CSWSecExecutable $res.Exe
    return $res
}

function Test-CSWSecAutorunEntry {
    # Analiza un comando de autoarranque y devuelve una fila de informe
    param([string]$Location, [string]$Name, [string]$Command)
    $split = Split-CSWSecCommandLine $Command
    $exe = $split.Exe
    $reasons = New-Object System.Collections.ArrayList
    $high = $false
    $exists = $false
    if ($exe) { $exists = Test-Path -LiteralPath $exe -PathType Leaf -ErrorAction SilentlyContinue }
    $sig = Get-CSWSecSignature $exe

    if (-not $exists) { [void]$reasons.Add('Archivo no encontrado (entrada huerfana)') }
    if (Test-CSWSecSuspiciousPath $exe) { [void]$reasons.Add('Ruta de usuario/temporal/ProgramData') }
    if ($exists -and -not $sig.Valid) { [void]$reasons.Add("Firma: $($sig.Status)") }
    if ((Test-CSWSecSuspiciousPath $exe) -and $exists -and -not $sig.Valid) { $high = $true }

    $leaf = ''
    if ($exe) { $leaf = [System.IO.Path]::GetFileName($exe).ToLowerInvariant() }
    if ($script:SecScriptHosts -contains $leaf) {
        $a = $split.Arguments
        if ($a -match '(?i)(-enc(odedcommand)?\s|frombase64|downloadstring|downloadfile|invoke-webrequest|iwr\s|iex[\s(]|invoke-expression|https?://|-w(indowstyle)?\s+h(idden)?|javascript:|vbscript:|scrobj\.dll|/i:http)') {
            [void]$reasons.Add('Interprete con argumentos ofuscados o descarga remota')
            $high = $true
        }
        $pm = [regex]::Match($a, '(?i)([A-Z]:\\[^"\s,;]+)')
        if ($pm.Success) {
            $target = $pm.Groups[1].Value
            if (Test-CSWSecSuspiciousPath $target) {
                $tsig = Get-CSWSecSignature $target
                if (-not $tsig.Valid) { [void]$reasons.Add("Interprete lanzando archivo sin firma en ruta de usuario: $target"); $high = $true }
                else { [void]$reasons.Add("Interprete lanzando archivo en ruta de usuario: $target") }
            }
        }
    }

    $estado = 'OK'
    if ($reasons.Count -gt 0) { $estado = 'Sospechoso' }
    $riesgo = 'Bajo'
    if ($estado -eq 'Sospechoso') { $riesgo = 'Medio' }
    if ($high) { $riesgo = 'Alto' }
    $cmdShort = $Command
    if ($cmdShort -and $cmdShort.Length -gt 110) { $cmdShort = $cmdShort.Substring(0, 107) + '...' }
    return [pscustomobject]@{
        Estado    = $estado
        Riesgo    = $riesgo
        Ubicacion = $Location
        Nombre    = $Name
        Firmante  = $sig.Signer
        Firma     = $sig.Status
        Comando   = $cmdShort
        Motivo    = ($reasons -join '; ')
    }
}

function Get-CSWSecProcessMap {
    # PID -> nombre, ruta y servicios alojados (una sola consulta CIM)
    $map = @{}
    try {
        foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $map[[int]$p.ProcessId] = [pscustomobject]@{ Name = $p.Name; Path = [string]$p.ExecutablePath; Services = '' }
        }
    }
    catch {
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            $path = ''
            try { $path = [string]$p.Path } catch { }
            $map[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path; Services = '' }
        }
    }
    try {
        $svc = Get-CimInstance Win32_Service -Filter 'ProcessId > 0' -ErrorAction Stop | Group-Object ProcessId
        foreach ($g in $svc) {
            $procId = [int]$g.Name
            if ($map.ContainsKey($procId)) { $map[$procId].Services = (($g.Group | ForEach-Object { $_.Name }) -join ',') }
        }
    }
    catch { }
    if ($map.ContainsKey(4)) { $map[4].Name = 'System'; $map[4].Path = 'Kernel (System)' }
    return $map
}

function Get-CSWSecAVProducts {
    # Antivirus registrados en el Centro de seguridad (no existe en Windows Server)
    $out = @()
    try {
        $items = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        foreach ($i in $items) {
            $state = [int](Get-CSWSecProp $i 'productState' 0)
            $hex = '{0:X6}' -f $state
            $enabled = @('10', '11') -contains $hex.Substring(2, 2)
            $upToDate = ($hex.Substring(4, 2) -eq '00')
            $name = [string](Get-CSWSecProp $i 'displayName' '')
            $out += [pscustomobject]@{
                Producto  = $name
                Activo    = $enabled
                FirmasOK  = $upToDate
                EsDefender = ($name -match '(?i)Windows Defender|Microsoft Defender|Antivirus de Microsoft Defender')
                Ruta      = [string](Get-CSWSecProp $i 'pathToSignedProductExe' '')
            }
        }
    }
    catch { }
    # Algunos productos se registran varias veces: una fila por nombre (prioriza la activa)
    $uniq = @()
    foreach ($g in @($out | Group-Object Producto)) {
        $uniq += @($g.Group | Sort-Object @{ Expression = { [int]$_.Activo } } -Descending)[0]
    }
    return $uniq
}

function Get-CSWSecFirewallProducts {
    $out = @()
    try {
        $items = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop
        foreach ($i in $items) {
            $state = [int](Get-CSWSecProp $i 'productState' 0)
            $hex = '{0:X6}' -f $state
            $out += [pscustomobject]@{ Producto = [string](Get-CSWSecProp $i 'displayName' ''); Activo = (@('10', '11') -contains $hex.Substring(2, 2)) }
        }
    }
    catch { }
    $uniq = @()
    foreach ($g in @($out | Group-Object Producto)) { $uniq += @($g.Group | Sort-Object @{ Expression = { [int]$_.Activo } } -Descending)[0] }
    return $uniq
}

function Get-CSWSecMpCmdRun {
    $plat = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path $plat) {
        $c = Get-ChildItem -Path $plat -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]($_.Name -replace '-.*$', '') } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' } |
            Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($c) { return $c }
    }
    $p = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $p) { return $p }
    return $null
}

function Get-CSWSecDefenderInfo {
    # Estado resumido de Defender (o $null si no esta disponible)
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { return $null }
    $sigDate = Get-CSWSecProp $mp 'AntivirusSignatureLastUpdated'
    $sigAge = $null
    if ($sigDate) { $sigAge = [int][math]::Floor(((Get-Date) - [datetime]$sigDate).TotalDays) }
    else {
        $a = Get-CSWSecProp $mp 'AntivirusSignatureAge'
        if ($null -ne $a -and [int]$a -lt 65000) { $sigAge = [int]$a }
    }
    return [pscustomobject]@{
        Raw            = $mp
        Mode           = [string](Get-CSWSecProp $mp 'AMRunningMode' 'Normal')
        ServiceEnabled = [bool](Get-CSWSecProp $mp 'AMServiceEnabled' $false)
        AVEnabled      = [bool](Get-CSWSecProp $mp 'AntivirusEnabled' $false)
        RealTime       = [bool](Get-CSWSecProp $mp 'RealTimeProtectionEnabled' $false)
        Behavior       = [bool](Get-CSWSecProp $mp 'BehaviorMonitorEnabled' $false)
        Ioav           = [bool](Get-CSWSecProp $mp 'IoavProtectionEnabled' $false)
        OnAccess       = [bool](Get-CSWSecProp $mp 'OnAccessProtectionEnabled' $false)
        Tamper         = Get-CSWSecProp $mp 'IsTamperProtected'
        SigVersion     = [string](Get-CSWSecProp $mp 'AntivirusSignatureVersion' '')
        SigDate        = $sigDate
        SigAge         = $sigAge
        EngineVersion  = [string](Get-CSWSecProp $mp 'AMEngineVersion' '')
        ProductVersion = [string](Get-CSWSecProp $mp 'AMProductVersion' '')
        QuickScanEnd   = Get-CSWSecProp $mp 'QuickScanEndTime'
        FullScanEnd    = Get-CSWSecProp $mp 'FullScanEndTime'
    }
}

function Test-CSWSecDefenderUsable {
    # Comprueba que Defender este disponible y sea el antivirus activo antes de escanear/actualizar
    $d = Get-CSWSecDefenderInfo
    if (-not $d) {
        Write-CSWLog 'Microsoft Defender no esta disponible (servicio detenido, desinstalado o sustituido por otro antivirus).' -Level Warn
        return $null
    }
    if ($d.Mode -match '(?i)passive' -or -not $d.AVEnabled) {
        $third = @(Get-CSWSecAVProducts | Where-Object { $_.Activo -and -not $_.EsDefender })
        if ($third.Count) { Write-CSWLog ("Defender esta en modo pasivo/deshabilitado; antivirus activo: {0}" -f (($third | ForEach-Object { $_.Producto }) -join ', ')) -Level Warn }
    }
    return $d
}

function Get-CSWSecThreatNameMap {
    $map = @{}
    try { foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $map[[string]$t.ThreatID] = $t } } catch { }
    return $map
}

function Get-CSWSecThreatStatusText {
    param([int]$Id)
    switch ($Id) {
        0 { 'Desconocido' } 1 { 'Detectada' } 2 { 'Limpiada' } 3 { 'En cuarentena' } 4 { 'Eliminada' } 5 { 'Permitida' } 6 { 'Bloqueada' }
        102 { 'Fallo al poner en cuarentena' } 103 { 'Fallo al eliminar' } 104 { 'Fallo al permitir' } 105 { 'Abandonada' } 107 { 'Fallo al bloquear' }
        default { "Estado $Id" }
    }
}

function Get-CSWSecSeverityText {
    param($Id)
    switch ([int]$Id) { 1 { 'Baja' } 2 { 'Moderada' } 4 { 'Alta' } 5 { 'Grave' } default { 'Desconocida' } }
}

function Get-CSWSecRecentThreats {
    param([datetime]$Since = [datetime]::MinValue)
    $names = Get-CSWSecThreatNameMap
    $rows = @()
    try { $det = @(Get-MpThreatDetection -ErrorAction Stop) } catch { return $rows }
    foreach ($d in $det) {
        $when = Get-CSWSecProp $d 'InitialDetectionTime'
        if ($when -and [datetime]$when -lt $Since) { continue }
        $tid = [string](Get-CSWSecProp $d 'ThreatID' '')
        $t = $null
        if ($names.ContainsKey($tid)) { $t = $names[$tid] }
        $res = @(Get-CSWSecProp $d 'Resources' @())
        $resTxt = (($res | Select-Object -First 2) -join ' | ') -replace '^(file|process|regkey|containerfile|amsi):_', ''
        if ($resTxt.Length -gt 100) { $resTxt = $resTxt.Substring(0, 97) + '...' }
        $statusId = [int](Get-CSWSecProp $d 'ThreatStatusID' 0)
        $rows += [pscustomobject]@{
            Fecha     = $when
            Amenaza   = [string](Get-CSWSecProp $t 'ThreatName' "ID $tid")
            Gravedad  = (Get-CSWSecSeverityText (Get-CSWSecProp $t 'SeverityID' 0))
            Estado    = (Get-CSWSecThreatStatusText $statusId)
            Activa    = (Get-CSWSecYesNo ([bool](Get-CSWSecProp $t 'IsActive' $false)))
            Ejecutada = (Get-CSWSecYesNo ([bool](Get-CSWSecProp $t 'DidThreatExecute' $false)))
            Proceso   = [string](Get-CSWSecProp $d 'ProcessName' '')
            Recurso   = $resTxt
            StatusId  = $statusId
        }
    }
    return @($rows | Sort-Object Fecha -Descending)
}

function Get-CSWSecFirewallData {
    $profiles = $null
    try { $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) }
    catch { try { $profiles = @(Get-NetFirewallProfile -ErrorAction Stop) } catch { $profiles = $null } }
    return $profiles
}

function Get-CSWSecLastPatchInfo {
    $hf = @()
    try { $hf = @(Get-HotFix -ErrorAction Stop) } catch { }
    $rows = @()
    foreach ($h in $hf) {
        $d = $null
        try { $d = $h.InstalledOn } catch { }
        if (-not $d) {
            $raw = [string](Get-CSWSecProp $h 'InstallDate' '')
            if ($raw) { try { $d = [datetime]::Parse($raw, [Globalization.CultureInfo]::InvariantCulture) } catch { } }
        }
        $rows += [pscustomobject]@{ HotFixID = $h.HotFixID; Tipo = $h.Description; Instalado = $d; InstaladoPor = $h.InstalledBy }
    }
    $rows = @($rows | Sort-Object @{ Expression = { if ($_.Instalado) { [datetime]$_.Instalado } else { [datetime]::MinValue } } } -Descending)
    $last = $null
    $withDate = @($rows | Where-Object { $_.Instalado })
    if ($withDate.Count) { $last = [datetime]$withDate[0].Instalado }
    $days = $null
    if ($last) { $days = [int][math]::Floor(((Get-Date) - $last).TotalDays) }
    return [pscustomobject]@{ Items = $rows; Last = $last; Days = $days }
}

function Get-CSWSecHostsPath { return (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') }

function Get-CSWSecHostsEntries {
    $path = Get-CSWSecHostsPath
    $rows = @()
    if (-not (Test-Path -LiteralPath $path)) { return $rows }
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $path -ErrorAction Stop)) {
        $n++
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $comment = ''
        $hashPos = $t.IndexOf('#')
        if ($hashPos -ge 0) { $comment = $t.Substring($hashPos + 1).Trim(); $t = $t.Substring(0, $hashPos).Trim() }
        $parts = @($t -split '\s+' | Where-Object { $_ })
        if ($parts.Count -lt 1) { continue }
        $ip = $parts[0]
        $hostNames = ''
        if ($parts.Count -gt 1) { $hostNames = ($parts[1..($parts.Count - 1)] -join ' ') }
        $nota = ''
        if ($hostNames -match '^(localhost|localhost\.localdomain)$' -and $ip -match '^(127\.0\.0\.1|::1)$') { $nota = 'Normal' }
        elseif ($hostNames -match '(?i)(microsoft|windowsupdate|windows\.com|update|defender|avast|avg|eset|kaspersky|norton|mcafee|bitdefender|malwarebytes|sophos|virustotal|google|bing|facebook|paypal|bank|banco|apple|amazon)') {
            if ($ip -match '^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)$') { $nota = 'Bloqueo de dominio de seguridad/actualizacion' }
            else { $nota = 'REDIRECCION de dominio conocido (posible secuestro)' }
        }
        elseif ($ip -match '^(0\.0\.0\.0|127\.0\.0\.1)$') { $nota = 'Bloqueo (posible bloqueador de anuncios)' }
        else { $nota = 'Redireccion personalizada' }
        $rows += [pscustomobject]@{ Linea = $n; IP = $ip; Hosts = $hostNames; Comentario = $comment; Nota = $nota }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Acciones: Defender
# ---------------------------------------------------------------------------
function Get-CSWSecDefenderStatus {
    Write-CSWLog 'Consultando antivirus registrados en el Centro de seguridad...' -Level Step
    $warns = New-Object System.Collections.ArrayList
    $avs = @(Get-CSWSecAVProducts)
    $third = @($avs | Where-Object { -not $_.EsDefender })
    $thirdActive = @($third | Where-Object { $_.Activo })
    foreach ($a in $avs) {
        $lvl = 'Info'
        if (-not $a.Activo) { $lvl = 'Data' }
        Write-CSWLog ("Antivirus: {0} | Activo: {1} | Firmas al dia: {2}" -f $a.Producto, (Get-CSWSecYesNo $a.Activo), (Get-CSWSecYesNo $a.FirmasOK)) -Level $lvl
    }
    foreach ($a in $thirdActive) { if (-not $a.FirmasOK) { [void]$warns.Add("Firmas de $($a.Producto) desactualizadas") } }

    Write-CSWLog 'Consultando Microsoft Defender...' -Level Step
    $d = Get-CSWSecDefenderInfo
    $rows = @()
    if (-not $d) {
        if ($thirdActive.Count) {
            Write-CSWLog 'Defender no responde, pero hay otro antivirus activo (normal: Defender se desactiva solo).' -Level Info
            $s = 'OK'
            if ($warns.Count) { $s = 'Warn' }
            return (New-CSWResult -Summary ("Antivirus activo: {0}. {1}" -f (($thirdActive | ForEach-Object { $_.Producto }) -join ', '), ($warns -join '; ')).Trim() -Status $s)
        }
        Write-CSWLog 'No se pudo consultar Defender y no hay otro antivirus activo.' -Level Error
        return (New-CSWResult -Summary 'No se detecta ningun antivirus activo en el equipo' -Status Warn)
    }

    $passive = ($d.Mode -match '(?i)passive')
    $defenderPrimary = (-not $passive) -and ($thirdActive.Count -eq 0 -or $d.RealTime)
    $rows += New-CSWSecRow 'Modo de ejecucion' $d.Mode
    $rows += New-CSWSecRow 'Version de plataforma / motor' ("{0} / {1}" -f $d.ProductVersion, $d.EngineVersion)

    $checks = @(
        @{ N = 'Servicio antimalware'; V = $d.ServiceEnabled },
        @{ N = 'Antivirus'; V = $d.AVEnabled },
        @{ N = 'Proteccion en tiempo real'; V = $d.RealTime },
        @{ N = 'Supervision de comportamiento'; V = $d.Behavior },
        @{ N = 'Analisis de descargas (IOAV)'; V = $d.Ioav },
        @{ N = 'Proteccion al acceso'; V = $d.OnAccess }
    )
    foreach ($c in $checks) {
        $st = 'OK'
        if (-not $c.V) {
            if ($defenderPrimary) { $st = 'DESACTIVADO'; [void]$warns.Add("$($c.N) desactivada") } else { $st = 'Pasivo (otro AV)' }
        }
        $rows += New-CSWSecRow $c.N (Get-CSWSecYesNo $c.V) $st
    }

    if ($null -eq $d.Tamper) { $rows += New-CSWSecRow 'Proteccion contra alteraciones' 'N/D' 'N/D' }
    else {
        $st = 'OK'
        if (-not [bool]$d.Tamper -and $defenderPrimary) { $st = 'DESACTIVADO'; [void]$warns.Add('Proteccion contra alteraciones desactivada') }
        $rows += New-CSWSecRow 'Proteccion contra alteraciones' (Get-CSWSecYesNo ([bool]$d.Tamper)) $st
    }

    $sigSt = 'OK'
    $sigTxt = 'Desconocida'
    if ($null -ne $d.SigAge) {
        $sigTxt = "{0} dias" -f $d.SigAge
        if ($d.SigAge -gt 3 -and $defenderPrimary) { $sigSt = 'ANTIGUAS'; [void]$warns.Add("Firmas con $($d.SigAge) dias de antiguedad") }
    }
    elseif ($defenderPrimary) { $sigSt = 'REVISAR'; [void]$warns.Add('No se pudo determinar la antiguedad de las firmas') }
    $rows += New-CSWSecRow 'Version de firmas' $d.SigVersion
    $sigDateTxt = ''
    if ($d.SigDate) { $sigDateTxt = '{0:dd\/MM\/yyyy HH:mm}' -f [datetime]$d.SigDate }
    $rows += New-CSWSecRow 'Firmas actualizadas el' $sigDateTxt
    $rows += New-CSWSecRow 'Antiguedad de firmas' $sigTxt $sigSt

    foreach ($sc in @(@{ N = 'Ultimo analisis rapido'; V = $d.QuickScanEnd }, @{ N = 'Ultimo analisis completo'; V = $d.FullScanEnd })) {
        if ($sc.V) {
            $age = [int][math]::Floor(((Get-Date) - [datetime]$sc.V).TotalDays)
            $st = 'OK'
            if ($age -gt 30) { $st = 'Antiguo' }
            $rows += New-CSWSecRow $sc.N ('{0:dd\/MM\/yyyy HH:mm} (hace {1} dias)' -f [datetime]$sc.V, $age) $st
        }
        else { $rows += New-CSWSecRow $sc.N 'Nunca' 'Info' }
    }
    $rows

    if ($passive -and $thirdActive.Count) {
        Write-CSWLog ("Defender en modo pasivo; protege: {0}" -f (($thirdActive | ForEach-Object { $_.Producto }) -join ', ')) -Level Info
    }
    if ($warns.Count) {
        foreach ($w in $warns) { Write-CSWLog $w -Level Warn }
        return (New-CSWResult -Summary ("Antivirus con avisos: {0}" -f ($warns -join '; ')) -Status Warn)
    }
    if (-not $defenderPrimary -and $thirdActive.Count) {
        return (New-CSWResult -Summary ("Antivirus activo y al dia: {0} (Defender en reserva)" -f (($thirdActive | ForEach-Object { $_.Producto }) -join ', ')))
    }
    return (New-CSWResult -Summary ("Antivirus activo y al dia (Microsoft Defender; firmas de {0})" -f $sigTxt))
}

function Update-CSWSecSignatures {
    $d = Test-CSWSecDefenderUsable
    if (-not $d) { return (New-CSWResult -Summary 'Defender no disponible: no se pueden actualizar sus firmas' -Status Warn) }
    $before = $d.SigVersion
    Write-CSWLog "Version de firmas actual: $before" -Level Info
    Write-CSWLog 'Actualizando firmas de Microsoft Defender...' -Level Step
    $ok = $false
    try { Update-MpSignature -ErrorAction Stop; $ok = $true }
    catch {
        Write-CSWLog "Update-MpSignature fallo: $($_.Exception.Message). Probando con MpCmdRun..." -Level Warn
        $mpc = Get-CSWSecMpCmdRun
        if ($mpc) {
            $code = Invoke-CSWExternal -FilePath $mpc -Arguments '-SignatureUpdate'
            if ($code -eq 0) { $ok = $true }
            else { Write-CSWLog "MpCmdRun devolvio codigo $code" -Level Warn }
        }
    }
    $after = Get-CSWSecDefenderInfo
    $afterVer = ''
    if ($after) { $afterVer = $after.SigVersion }
    if (-not $ok) { return (New-CSWResult -Summary 'No se pudieron actualizar las firmas del antivirus (revise conexion a Internet)' -Status Error) }
    if ($afterVer -and $afterVer -ne $before) {
        Write-CSWLog "Firmas actualizadas: $before -> $afterVer" -Level Ok
        return (New-CSWResult -Summary "Firmas del antivirus actualizadas a la version $afterVer")
    }
    Write-CSWLog 'Las firmas ya estaban en la ultima version.' -Level Ok
    return (New-CSWResult -Summary "Firmas del antivirus al dia (version $afterVer)")
}

function Start-CSWSecDefenderScan {
    param([ValidateSet('QuickScan', 'FullScan')][string]$ScanType = 'QuickScan')
    $d = Test-CSWSecDefenderUsable
    $label = 'rapido'
    if ($ScanType -eq 'FullScan') { $label = 'completo' }
    if (-not $d) { return (New-CSWResult -Summary "Defender no disponible: no se pudo realizar el analisis $label" -Status Warn) }
    $start = Get-Date
    Write-CSWLog "Iniciando analisis $label de Microsoft Defender (puede tardar)..." -Level Step
    $ran = $false
    try { Start-MpScan -ScanType $ScanType -ErrorAction Stop; $ran = $true }
    catch {
        Write-CSWLog "Start-MpScan fallo: $($_.Exception.Message). Probando con MpCmdRun..." -Level Warn
        $mpc = Get-CSWSecMpCmdRun
        if ($mpc) {
            $st = 1
            if ($ScanType -eq 'FullScan') { $st = 2 }
            $code = Invoke-CSWExternal -FilePath $mpc -Arguments "-Scan -ScanType $st"
            if ($code -eq 0 -or $code -eq 2) { $ran = $true }
            else { Write-CSWLog "MpCmdRun devolvio codigo $code" -Level Warn }
        }
    }
    $dur = (Get-Date) - $start
    if (-not $ran) { return (New-CSWResult -Summary "No se pudo ejecutar el analisis $label del antivirus" -Status Error) }
    Write-CSWLog ('Analisis finalizado en {0:hh\:mm\:ss}' -f $dur) -Level Ok
    $found = @(Get-CSWSecRecentThreats -Since $start.AddMinutes(-1))
    if ($found.Count) {
        $found | Select-Object Fecha, Amenaza, Gravedad, Estado, Recurso
        $pending = @($found | Where-Object { @(2, 3, 4, 6) -notcontains $_.StatusId })
        if ($pending.Count) { return (New-CSWResult -Summary ("Analisis {0}: {1} amenaza(s) detectada(s), {2} requieren atencion" -f $label, $found.Count, $pending.Count) -Status Warn) }
        return (New-CSWResult -Summary ("Analisis {0}: {1} amenaza(s) detectada(s) y neutralizada(s)" -f $label, $found.Count) -Status Warn)
    }
    return (New-CSWResult -Summary "Analisis $label del antivirus completado: no se encontraron amenazas")
}

function Start-CSWSecQuickScan { Start-CSWSecDefenderScan -ScanType QuickScan }
function Start-CSWSecFullScan { Start-CSWSecDefenderScan -ScanType FullScan }

function Start-CSWSecOfflineScan {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $d = Test-CSWSecDefenderUsable
    if (-not $d) { return (New-CSWResult -Summary 'Defender no disponible: no se puede programar el analisis sin conexion' -Status Warn) }
    if (-not (Get-Command Start-MpWDOScan -ErrorAction SilentlyContinue)) { return (New-CSWResult -Summary 'Esta version de Windows no admite el analisis sin conexion de Defender' -Status Warn) }
    Write-CSWLog 'Programando Microsoft Defender sin conexion. El equipo se REINICIARA en breve y el analisis dura unos 15 minutos.' -Level Warn
    try {
        Start-MpWDOScan -ErrorAction Stop
        Write-CSWLog 'Analisis sin conexion programado; reinicio en curso.' -Level Ok
        return (New-CSWResult -Summary 'Analisis sin conexion de Defender iniciado (el equipo se reinicia)')
    }
    catch {
        Write-CSWLog "No se pudo iniciar: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudo iniciar el analisis sin conexion de Defender' -Status Error)
    }
}

function Get-CSWSecThreats {
    Write-CSWLog 'Consultando historial de amenazas de Microsoft Defender...' -Level Step
    if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) { return (New-CSWResult -Summary 'Defender no disponible en este equipo' -Status Warn) }
    $rows = @(Get-CSWSecRecentThreats)
    if (-not $rows.Count) {
        if (-not (Test-CSWAdmin)) { Write-CSWLog 'Sin privilegios de administrador el historial puede aparecer vacio.' -Level Warn }
        return (New-CSWResult -Summary 'No hay amenazas registradas en el historial del antivirus')
    }
    $rows | Select-Object -First 50 | Select-Object Fecha, Amenaza, Gravedad, Estado, Activa, Ejecutada, Proceso, Recurso
    $active = @($rows | Where-Object { $_.Activa -eq 'Si' -or @(2, 3, 4, 6) -notcontains $_.StatusId })
    if ($active.Count) {
        Write-CSWLog ("{0} amenaza(s) siguen activas o no se pudieron neutralizar. Ejecute un analisis completo o sin conexion." -f $active.Count) -Level Warn
        return (New-CSWResult -Summary ("{0} amenaza(s) en historial, {1} sin resolver" -f $rows.Count, $active.Count) -Status Warn)
    }
    return (New-CSWResult -Summary ("{0} amenaza(s) en historial, todas neutralizadas" -f $rows.Count))
}

# ---------------------------------------------------------------------------
# Acciones: Firewall y red
# ---------------------------------------------------------------------------
function Get-CSWSecFirewallStatus {
    Write-CSWLog 'Consultando Firewall de Windows por perfil...' -Level Step
    $profiles = Get-CSWSecFirewallData
    if (-not $profiles) { return (New-CSWResult -Summary 'No se pudo consultar el Firewall de Windows' -Status Error) }
    $active = @()
    try {
        foreach ($cp in @(Get-NetConnectionProfile -ErrorAction Stop)) {
            $cat = [string]$cp.NetworkCategory
            if ($cat -eq 'DomainAuthenticated') { $cat = 'Domain' }
            $active += $cat
        }
    }
    catch { }
    $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
    if ($svc) {
        $lvl = 'Info'
        if ($svc.Status -ne 'Running') { $lvl = 'Warn' }
        Write-CSWLog ("Servicio Firewall de Windows Defender (MpsSvc): {0}" -f $svc.Status) -Level $lvl
    }
    $off = @()
    $rows = foreach ($p in $profiles) {
        $en = ([string]$p.Enabled -eq 'True')
        if (-not $en) { $off += [string]$p.Name }
        [pscustomobject]@{
            Perfil          = [string]$p.Name
            Activado        = (Get-CSWSecYesNo $en)
            EnUso           = (Get-CSWSecYesNo ($active -contains [string]$p.Name))
            EntradaDefecto  = [string]$p.DefaultInboundAction
            SalidaDefecto   = [string]$p.DefaultOutboundAction
            Notificaciones  = [string](Get-CSWSecProp $p 'NotifyOnListen' '')
        }
    }
    $rows
    $fw3 = @(Get-CSWSecFirewallProducts | Where-Object { $_.Activo -and $_.Producto -notmatch '(?i)Windows' })
    if ($fw3.Count) { Write-CSWLog ("Firewall de terceros activo: {0}" -f (($fw3 | ForEach-Object { $_.Producto }) -join ', ')) -Level Info }
    if ($svc -and $svc.Status -ne 'Running' -and -not $fw3.Count) {
        return (New-CSWResult -Summary 'El servicio del Firewall de Windows no esta en ejecucion' -Status Warn)
    }
    if ($off.Count) {
        $extra = ''
        if ($fw3.Count) { $extra = " (hay firewall de terceros: $(($fw3 | ForEach-Object { $_.Producto }) -join ', '))" }
        Write-CSWLog ("Perfiles con firewall DESACTIVADO: {0}" -f ($off -join ', ')) -Level Warn
        return (New-CSWResult -Summary ("Firewall desactivado en: {0}{1}" -f ($off -join ', '), $extra) -Status Warn)
    }
    return (New-CSWResult -Summary 'Firewall de Windows activo en todos los perfiles')
}

function Repair-CSWSecFirewall {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Write-CSWLog 'Iniciando servicio del Firewall (MpsSvc)...' -Level Step
        try { Start-Service -Name MpsSvc -ErrorAction Stop; Write-CSWLog 'Servicio iniciado.' -Level Ok }
        catch { Write-CSWLog "No se pudo iniciar MpsSvc: $($_.Exception.Message)" -Level Warn }
    }
    Write-CSWLog 'Activando Firewall de Windows en perfiles Dominio, Privado y Publico...' -Level Step
    $done = $false
    try { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop; $done = $true }
    catch {
        Write-CSWLog "Set-NetFirewallProfile fallo: $($_.Exception.Message). Probando con netsh..." -Level Warn
        $code = Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'advfirewall set allprofiles state on'
        if ($code -eq 0) { $done = $true }
    }
    if (-not $done) { return (New-CSWResult -Summary 'No se pudo reactivar el Firewall de Windows' -Status Error) }
    $profiles = Get-CSWSecFirewallData
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { [string]$_.Name })
    if ($off.Count) {
        Write-CSWLog ("Siguen desactivados (posible directiva de grupo): {0}" -f ($off -join ', ')) -Level Warn
        return (New-CSWResult -Summary ("Firewall reactivado parcialmente; una directiva mantiene apagado: {0}" -f ($off -join ', ')) -Status Warn)
    }
    Write-CSWLog 'Firewall activo en todos los perfiles.' -Level Ok
    return (New-CSWResult -Summary 'Firewall de Windows reactivado en todos los perfiles')
}

function Get-CSWSecListeningPorts {
    param($IncludeUdp = $false)
    $udp = ConvertTo-CSWSecBool $IncludeUdp
    Write-CSWLog 'Enumerando puertos en escucha y procesos propietarios...' -Level Step
    $pmap = Get-CSWSecProcessMap
    $rows = New-Object System.Collections.ArrayList
    $seen = @{}
    $risky = @()
    $suspProc = @()
    $tcp = @()
    try { $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) }
    catch { return (New-CSWResult -Summary "No se pudieron enumerar las conexiones TCP: $($_.Exception.Message)" -Status Error) }
    $items = @()
    foreach ($c in $tcp) { $items += [pscustomobject]@{ Proto = 'TCP'; Addr = [string]$c.LocalAddress; Port = [int]$c.LocalPort; ProcId = [int]$c.OwningProcess } }
    if ($udp) {
        try { foreach ($c in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $items += [pscustomobject]@{ Proto = 'UDP'; Addr = [string]$c.LocalAddress; Port = [int]$c.LocalPort; ProcId = [int]$c.OwningProcess } } }
        catch { Write-CSWLog "No se pudieron enumerar puertos UDP: $($_.Exception.Message)" -Level Warn }
    }
    foreach ($i in $items) {
        $scope = 'IP concreta'
        if ($i.Addr -match '^(0\.0\.0\.0|::)$') { $scope = 'Todas' }
        elseif ($i.Addr -match '^(127\.|::1$)') { $scope = 'Solo local' }
        # Agrupa IPv4/IPv6 del mismo puerto y proceso
        $key = '{0}|{1}|{2}|{3}' -f $i.Proto, $i.Port, $i.ProcId, $scope
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $pi = $null
        if ($pmap.ContainsKey($i.ProcId)) { $pi = $pmap[$i.ProcId] }
        $pname = [string](Get-CSWSecProp $pi 'Name' '?')
        $ppath = [string](Get-CSWSecProp $pi 'Path' '')
        $nota = ''
        if ($scope -eq 'Todas' -and $i.Proto -eq 'TCP' -and $script:SecRiskyPorts.ContainsKey($i.Port)) {
            $nota = "EXPUESTO: $($script:SecRiskyPorts[$i.Port])"
            $risky += "$($i.Port) ($($script:SecRiskyPorts[$i.Port]))"
        }
        elseif ($script:SecInfoPorts.ContainsKey($i.Port)) { $nota = $script:SecInfoPorts[$i.Port] }
        if ($ppath -and (Test-CSWSecSuspiciousPath $ppath) -and $scope -ne 'Solo local') {
            $sig = Get-CSWSecSignature $ppath
            if (-not $sig.Valid) { $nota = (($nota, 'Proceso sin firma en ruta de usuario') | Where-Object { $_ }) -join '; '; $suspProc += "$pname ($($i.Port))" }
        }
        [void]$rows.Add([pscustomobject]@{
                Proto     = $i.Proto
                Puerto    = $i.Port
                Alcance   = $scope
                PID       = $i.ProcId
                Proceso   = $pname
                Servicios = [string](Get-CSWSecProp $pi 'Services' '')
                Nota      = $nota
                Ruta      = $ppath
            })
    }
    $rows | Sort-Object Proto, Puerto
    if (-not (Test-CSWAdmin)) { Write-CSWLog 'Sin administrador algunas rutas de procesos del sistema no se muestran.' -Level Info }
    $tcpCount = @($rows | Where-Object { $_.Proto -eq 'TCP' }).Count
    $msg = "$tcpCount puertos TCP en escucha"
    if ($udp) { $msg += (", {0} UDP" -f @($rows | Where-Object { $_.Proto -eq 'UDP' }).Count) }
    $warn = @()
    if ($risky.Count) { $warn += ("expuestos: {0}" -f (($risky | Select-Object -Unique) -join ', ')) }
    if ($suspProc.Count) { $warn += ("procesos sospechosos: {0}" -f (($suspProc | Select-Object -Unique) -join ', ')) }
    if ($warn.Count) {
        foreach ($w in $warn) { Write-CSWLog $w -Level Warn }
        return (New-CSWResult -Summary ("{0}; {1}" -f $msg, ($warn -join '; ')) -Status Warn)
    }
    return (New-CSWResult -Summary "$msg; ninguno de riesgo expuesto")
}

function Get-CSWSecConnections {
    param($ResolveNames = $false)
    $resolve = ConvertTo-CSWSecBool $ResolveNames
    Write-CSWLog 'Enumerando conexiones TCP establecidas con equipos remotos...' -Level Step
    $pmap = Get-CSWSecProcessMap
    try { $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop) }
    catch { return (New-CSWResult -Summary "No se pudieron enumerar las conexiones: $($_.Exception.Message)" -Status Error) }
    $conns = @($conns | Where-Object {
            $r = [string]$_.RemoteAddress
            $r -notmatch '^(127\.|::1$|0\.0\.0\.0|::$|fe80:|169\.254\.)'
        })
    $dns = @{}
    if ($resolve) {
        $ips = @($conns | ForEach-Object { [string]$_.RemoteAddress } | Select-Object -Unique | Select-Object -First 60)
        Write-CSWLog ("Resolviendo nombres de {0} IP remotas (max. 1,5 s cada una)..." -f $ips.Count) -Level Info
        foreach ($ip in $ips) {
            $dns[$ip] = ''
            try {
                $task = [System.Net.Dns]::GetHostEntryAsync($ip)
                if ($task.Wait(1500)) { $dns[$ip] = $task.Result.HostName }
            }
            catch { }
        }
    }
    $susp = @()
    $rows = foreach ($c in $conns) {
        $procId = [int]$c.OwningProcess
        $pi = $null
        if ($pmap.ContainsKey($procId)) { $pi = $pmap[$procId] }
        $ppath = [string](Get-CSWSecProp $pi 'Path' '')
        $pname = [string](Get-CSWSecProp $pi 'Name' '?')
        $nota = ''
        if ($ppath -and (Test-CSWSecSuspiciousPath $ppath)) {
            $sig = Get-CSWSecSignature $ppath
            if (-not $sig.Valid) { $nota = 'Proceso sin firma en ruta de usuario'; $susp += $pname }
        }
        $ip = [string]$c.RemoteAddress
        $o = [ordered]@{
            Proceso   = $pname
            PID       = $procId
            Local     = [int]$c.LocalPort
            Remoto    = $ip
            RPuerto   = [int]$c.RemotePort
        }
        if ($resolve) { $o['Nombre'] = [string]$dns[$ip] }
        $o['Nota'] = $nota
        $o['Ruta'] = $ppath
        [pscustomobject]$o
    }
    $rows = @($rows | Sort-Object Proceso, Remoto)
    $rows
    $ipCount = @($rows | ForEach-Object { $_.Remoto } | Select-Object -Unique).Count
    $procCount = @($rows | ForEach-Object { $_.PID } | Select-Object -Unique).Count
    $msg = "{0} conexiones a {1} IP remotas desde {2} procesos" -f $rows.Count, $ipCount, $procCount
    if ($susp.Count) {
        Write-CSWLog ("Procesos sin firma en rutas de usuario con conexiones: {0}" -f (($susp | Select-Object -Unique) -join ', ')) -Level Warn
        return (New-CSWResult -Summary ("{0}; revisar: {1}" -f $msg, (($susp | Select-Object -Unique) -join ', ')) -Status Warn)
    }
    return (New-CSWResult -Summary $msg)
}

# ---------------------------------------------------------------------------
# Acciones: Autoarranques y cuentas
# ---------------------------------------------------------------------------
function Get-CSWSecAutoruns {
    $rows = New-Object System.Collections.ArrayList
    Write-CSWLog 'Revisando claves Run/RunOnce del registro...' -Level Step
    foreach ($k in $script:SecRunKeys) {
        if (-not (Test-Path $k.Path)) { continue }
        $item = Get-Item -Path $k.Path -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $short = $k.Path -replace '^(HKLM|HKCU):\\SOFTWARE\\', '$1\' -replace 'Microsoft\\Windows\\CurrentVersion\\', ''
        foreach ($vn in $item.GetValueNames()) {
            if (-not $vn) { continue }
            $val = [string]$item.GetValue($vn)
            if (-not $val) { continue }
            [void]$rows.Add((Test-CSWSecAutorunEntry -Location $short -Name $vn -Command $val))
        }
    }

    Write-CSWLog 'Revisando carpetas de Inicio...' -Level Step
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($f in @(@{ N = 'Inicio (usuario)'; P = [Environment]::GetFolderPath('Startup') }, @{ N = 'Inicio (todos)'; P = [Environment]::GetFolderPath('CommonStartup') })) {
        if (-not $f.P -or -not (Test-Path -LiteralPath $f.P)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f.P -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $cmd = '"' + $file.FullName + '"'
            if ($file.Extension -eq '.lnk' -and $shell) {
                try {
                    $lnk = $shell.CreateShortcut($file.FullName)
                    if ($lnk.TargetPath) { $cmd = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim() }
                }
                catch { }
            }
            [void]$rows.Add((Test-CSWSecAutorunEntry -Location $f.N -Name $file.Name -Command $cmd))
        }
    }
    if ($shell) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { } }

    Write-CSWLog 'Revisando tareas programadas de terceros...' -Level Step
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and [string]$_.State -ne 'Disabled' }) }
    catch { Write-CSWLog "No se pudieron leer las tareas programadas: $($_.Exception.Message)" -Level Warn }
    foreach ($t in $tasks) {
        foreach ($a in @($t.Actions)) {
            $exe = [string](Get-CSWSecProp $a 'Execute' '')
            if (-not $exe) {
                $cls = [string](Get-CSWSecProp $a 'ClassId' '')
                [void]$rows.Add([pscustomobject]@{ Estado = 'OK'; Riesgo = 'Bajo'; Ubicacion = 'Tarea programada'; Nombre = ($t.TaskPath + $t.TaskName); Firmante = ''; Firma = 'N/D'; Comando = "Accion COM $cls"; Motivo = '' })
                continue
            }
            $argsTxt = [string](Get-CSWSecProp $a 'Arguments' '')
            $cmd = ('"{0}" {1}' -f $exe.Trim('"'), $argsTxt).Trim()
            [void]$rows.Add((Test-CSWSecAutorunEntry -Location 'Tarea programada' -Name ($t.TaskPath + $t.TaskName) -Command $cmd))
        }
    }

    $order = @{ 'Alto' = 0; 'Medio' = 1; 'Bajo' = 2 }
    $sorted = @($rows | Sort-Object @{ Expression = { $order[$_.Riesgo] } }, Ubicacion, Nombre)
    $sorted
    $susp = @($sorted | Where-Object { $_.Estado -eq 'Sospechoso' })
    $high = @($sorted | Where-Object { $_.Riesgo -eq 'Alto' })
    foreach ($h in $high) { Write-CSWLog ("RIESGO ALTO: {0} [{1}] -> {2}" -f $h.Nombre, $h.Ubicacion, $h.Motivo) -Level Warn }
    $msg = "{0} elementos de inicio revisados" -f $sorted.Count
    if ($susp.Count) {
        Write-CSWLog 'Nota: "Sospechoso" indica que conviene revisarlo (muchas apps legitimas se instalan en AppData). Riesgo Alto = sin firma en ruta de usuario o interprete ofuscado.' -Level Info
        return (New-CSWResult -Summary ("{0}: {1} a revisar, {2} de riesgo alto" -f $msg, $susp.Count, $high.Count) -Status Warn)
    }
    return (New-CSWResult -Summary "$msg; ninguno sospechoso")
}

function Get-CSWSecLocalAdmins {
    $sidAdmins = 'S-1-5-32-544'
    $groupName = 'Administradores'
    try { $groupName = (New-Object System.Security.Principal.SecurityIdentifier($sidAdmins)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] } catch { }
    Write-CSWLog "Miembros del grupo local '$groupName' ($sidAdmins)..." -Level Step
    $members = @()
    $ok = $false
    try {
        foreach ($m in @(Get-LocalGroupMember -SID $sidAdmins -ErrorAction Stop)) {
            $members += [pscustomobject]@{ Name = [string]$m.Name; Class = [string]$m.ObjectClass; Source = [string](Get-CSWSecProp $m 'PrincipalSource' ''); SID = [string]$m.SID }
        }
        $ok = $true
    }
    catch { Write-CSWLog "Get-LocalGroupMember fallo ($($_.Exception.Message)); usando ADSI..." -Level Info }
    if (-not $ok) {
        try {
            $grp = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")
            foreach ($m in @($grp.psbase.Invoke('Members'))) {
                $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $cls = [string]$m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                $sidTxt = ''
                try {
                    $sidBytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                    $sidTxt = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                }
                catch { }
                $name = ($path -replace '^WinNT://', '') -replace '/', '\'
                $src = 'Dominio'
                if ($name -like "*\$env:COMPUTERNAME\*") { $src = 'Local'; $name = $name.Substring($name.IndexOf("$env:COMPUTERNAME\")) }
                elseif ($name -match '^S-1-12-1-') { $src = 'AzureAD' }
                $members += [pscustomobject]@{ Name = $name; Class = $cls; Source = $src; SID = $sidTxt }
            }
            $ok = $true
        }
        catch { Write-CSWLog "No se pudo leer el grupo por ADSI: $($_.Exception.Message)" -Level Error }
    }
    if (-not $ok) { return (New-CSWResult -Summary 'No se pudieron leer los administradores locales' -Status Error) }

    $warns = @()
    $enabledCount = 0
    $rows = foreach ($m in $members) {
        $enabled = ''
        $last = ''
        $pwdReq = ''
        if ($m.SID -and ($m.Source -match 'Local')) {
            try {
                $u = Get-LocalUser -SID $m.SID -ErrorAction Stop
                $enabled = Get-CSWSecYesNo $u.Enabled
                if ($u.Enabled) { $enabledCount++ }
                if ($u.LastLogon) { $last = '{0:dd\/MM\/yyyy}' -f $u.LastLogon } else { $last = 'Nunca' }
                $pwdReq = Get-CSWSecYesNo $u.PasswordRequired
                if ($m.SID -match '-500$' -and $u.Enabled) { $warns += "cuenta Administrador integrada habilitada ($($m.Name))" }
                if ($u.Enabled -and -not $u.PasswordRequired) { $warns += "$($m.Name) puede no tener contrasena" }
            }
            catch { }
        }
        else { $enabledCount++ }
        $tipo = $m.Class
        if ($tipo -match '(?i)group') { $tipo = 'Grupo' } elseif ($tipo -match '(?i)user') { $tipo = 'Usuario' }
        [pscustomobject]@{ Nombre = $m.Name; Tipo = $tipo; Origen = $m.Source; Habilitado = $enabled; UltimoInicio = $last; RequiereClave = $pwdReq; SID = $m.SID }
    }
    $rows
    if ($enabledCount -gt 3) { $warns += "$enabledCount cuentas con privilegios de administrador" }
    if ($warns.Count) {
        foreach ($w in $warns) { Write-CSWLog $w -Level Warn }
        return (New-CSWResult -Summary ("{0} administradores locales; revisar: {1}" -f @($rows).Count, ($warns -join '; ')) -Status Warn)
    }
    return (New-CSWResult -Summary ("{0} miembros en el grupo de administradores" -f @($rows).Count))
}

# ---------------------------------------------------------------------------
# Acciones: Cifrado y postura
# ---------------------------------------------------------------------------
function Get-CSWSecBitLockerData {
    # Devuelve filas SIN secretos. Nunca se lee ni muestra la contrasena de recuperacion.
    $rows = @()
    $vols = $null
    try {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $vols = @(Get-BitLockerVolume -ErrorAction Stop) }
    }
    catch { $vols = $null }
    if ($vols) {
        foreach ($v in $vols) {
            $types = @()
            foreach ($kp in @($v.KeyProtector)) { if ($kp) { $types += [string]$kp.KeyProtectorType } }
            $rows += [pscustomobject]@{
                Unidad        = [string]$v.MountPoint
                Tipo          = [string]$v.VolumeType
                Estado        = [string]$v.VolumeStatus
                Proteccion    = [string]$v.ProtectionStatus
                Cifrado       = ('{0}%' -f $v.EncryptionPercentage)
                Metodo        = [string]$v.EncryptionMethod
                Protectores   = (($types | Select-Object -Unique) -join ', ')
                ClaveRecuperacion = (Get-CSWSecYesNo ($types -contains 'RecoveryPassword'))
            }
        }
        return $rows
    }
    # Alternativa CIM (solo identificadores de protector, nunca la clave)
    $enc = @(Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop)
    foreach ($e in $enc) {
        $prot = switch ([int]$e.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } }
        $hasRec = $false
        $pct = ''
        $status = ''
        try {
            $r = Invoke-CimMethod -InputObject $e -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]3 } -ErrorAction Stop
            $hasRec = (@($r.VolumeKeyProtectorID).Count -gt 0)
        }
        catch { }
        try {
            $cs = Invoke-CimMethod -InputObject $e -MethodName GetConversionStatus -ErrorAction Stop
            $pct = '{0}%' -f $cs.EncryptionPercentage
            $status = switch ([int]$cs.ConversionStatus) { 0 { 'FullyDecrypted' } 1 { 'FullyEncrypted' } 2 { 'EncryptionInProgress' } 3 { 'DecryptionInProgress' } 4 { 'EncryptionPaused' } 5 { 'DecryptionPaused' } default { 'Unknown' } }
        }
        catch { }
        $rows += [pscustomobject]@{
            Unidad = [string]$e.DriveLetter; Tipo = ''; Estado = $status; Proteccion = $prot; Cifrado = $pct; Metodo = ''
            Protectores = ''; ClaveRecuperacion = (Get-CSWSecYesNo $hasRec)
        }
    }
    return $rows
}

function Get-CSWSecBitLocker {
    Write-CSWLog 'Consultando estado de BitLocker (no se muestran claves de recuperacion)...' -Level Step
    $rows = $null
    try { $rows = @(Get-CSWSecBitLockerData) }
    catch {
        if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult 'estado de BitLocker') }
        $why = 'BitLocker no disponible en esta edicion de Windows'
        Write-CSWLog "$why ($($_.Exception.Message))" -Level Warn
        return (New-CSWResult -Summary $why -Status Warn)
    }
    if (-not $rows.Count) { return (New-CSWResult -Summary 'No se encontraron volumenes cifrables' -Status Warn) }
    $rows
    $sys = $env:SystemDrive
    $warns = @()
    $osRow = @($rows | Where-Object { $_.Unidad -eq $sys }) | Select-Object -First 1
    foreach ($r in $rows) {
        if ($r.Estado -match 'FullyEncrypted|InProgress' -and $r.Proteccion -eq 'Off') { $warns += "$($r.Unidad) cifrada pero con proteccion suspendida" }
        if ($r.Proteccion -eq 'On' -and $r.ClaveRecuperacion -ne 'Si') { $warns += "$($r.Unidad) sin contrasena de recuperacion (riesgo de perder datos)" }
    }
    $encrypted = @($rows | Where-Object { $_.Proteccion -eq 'On' })
    if ($encrypted.Count) {
        Write-CSWLog 'Recuerde confirmar que el cliente tiene guardada la clave de recuperacion (cuenta Microsoft: https://aka.ms/myrecoverykey o Azure AD/AD).' -Level Info
    }
    if ($warns.Count) {
        foreach ($w in $warns) { Write-CSWLog $w -Level Warn }
        return (New-CSWResult -Summary ("BitLocker: {0}" -f ($warns -join '; ')) -Status Warn)
    }
    if ($osRow -and $osRow.Proteccion -eq 'On') { return (New-CSWResult -Summary "Unidad del sistema $sys cifrada con BitLocker y protegida") }
    Write-CSWLog "La unidad del sistema $sys no esta cifrada." -Level Info
    return (New-CSWResult -Summary "Unidad del sistema $sys sin cifrar (BitLocker desactivado)")
}

function Get-CSWSecPostureChecks {
    $checks = New-Object System.Collections.ArrayList
    function Add-Check([string]$Control, [string]$Result, [string]$Detail, [int]$Weight) {
        [void]$checks.Add([pscustomobject]@{ Control = $Control; Resultado = $Result; Detalle = $Detail; Peso = $Weight })
    }

    # Antivirus
    $avs = @(Get-CSWSecAVProducts)
    $d = Get-CSWSecDefenderInfo
    $active = @($avs | Where-Object { $_.Activo })
    $defOn = ($d -and $d.RealTime -and $d.Mode -notmatch '(?i)passive')
    if ($defOn -or $active.Count) {
        $names = @($active | ForEach-Object { $_.Producto })
        if (-not $names.Count) { $names = @('Microsoft Defender') }
        Add-Check 'Antivirus en tiempo real' 'OK' ($names -join ', ') 20
    }
    elseif ($d -or $avs.Count) { Add-Check 'Antivirus en tiempo real' 'FALLO' 'Proteccion en tiempo real desactivada' 20 }
    else { Add-Check 'Antivirus en tiempo real' 'N/D' 'No se pudo consultar' 20 }

    if ($defOn -and $null -ne $d.SigAge) {
        if ($d.SigAge -le 3) { Add-Check 'Firmas del antivirus' 'OK' "$($d.SigAge) dias" 10 } else { Add-Check 'Firmas del antivirus' 'FALLO' "$($d.SigAge) dias de antiguedad" 10 }
    }
    elseif ($active.Count) {
        $bad = @($active | Where-Object { -not $_.FirmasOK })
        if ($bad.Count) { Add-Check 'Firmas del antivirus' 'FALLO' 'Desactualizadas segun Centro de seguridad' 10 } else { Add-Check 'Firmas del antivirus' 'OK' 'Al dia segun Centro de seguridad' 10 }
    }
    else { Add-Check 'Firmas del antivirus' 'N/D' '' 10 }

    if ($defOn) {
        if ($null -eq $d.Tamper) { Add-Check 'Proteccion contra alteraciones' 'N/D' '' 5 }
        elseif ([bool]$d.Tamper) { Add-Check 'Proteccion contra alteraciones' 'OK' 'Activada' 5 }
        else { Add-Check 'Proteccion contra alteraciones' 'FALLO' 'Desactivada' 5 }
    }

    # Firewall
    $fw = Get-CSWSecFirewallData
    if ($fw) {
        $off = @($fw | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { [string]$_.Name })
        $fw3 = @(Get-CSWSecFirewallProducts | Where-Object { $_.Activo -and $_.Producto -notmatch '(?i)Windows' })
        if (-not $off.Count) { Add-Check 'Firewall' 'OK' 'Activo en todos los perfiles' 15 }
        elseif ($fw3.Count) { Add-Check 'Firewall' 'OK' ("Tercero: {0}" -f (($fw3 | ForEach-Object { $_.Producto }) -join ', ')) 15 }
        else { Add-Check 'Firewall' 'FALLO' ("Apagado en: {0}" -f ($off -join ', ')) 15 }
    }
    else { Add-Check 'Firewall' 'N/D' 'No se pudo consultar' 15 }

    # UAC
    $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $lua = [int](Get-CSWSecProp $pol 'EnableLUA' 1)
    $cpa = [int](Get-CSWSecProp $pol 'ConsentPromptBehaviorAdmin' 5)
    $psd = [int](Get-CSWSecProp $pol 'PromptOnSecureDesktop' 1)
    if ($lua -eq 0) { Add-Check 'Control de cuentas (UAC)' 'FALLO' 'UAC desactivado (EnableLUA=0)' 15 }
    elseif ($cpa -eq 0) { Add-Check 'Control de cuentas (UAC)' 'FALLO' 'Eleva sin preguntar (nivel minimo)' 15 }
    else {
        $lvl = 'Activado'
        if ($cpa -eq 2) { $lvl = 'Activado (notificar siempre)' } elseif ($psd -eq 0) { $lvl = 'Activado (sin escritorio seguro)' }
        Add-Check 'Control de cuentas (UAC)' 'OK' $lvl 15
    }

    # SmartScreen
    $ssPol = Get-CSWSecProp (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue) 'EnableSmartScreen'
    $ssExp = [string](Get-CSWSecProp (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue) 'SmartScreenEnabled' '')
    if ($null -ne $ssPol -and [int]$ssPol -eq 0) { Add-Check 'SmartScreen' 'FALLO' 'Desactivado por directiva' 5 }
    elseif ($ssExp -eq 'Off') { Add-Check 'SmartScreen' 'FALLO' 'Desactivado' 5 }
    else {
        $det = 'Activado'
        if ($ssExp) { $det = "Activado ($ssExp)" }
        Add-Check 'SmartScreen' 'OK' $det 5
    }

    # Secure Boot
    $sbState = Get-CSWSecProp (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue) 'UEFISecureBootEnabled'
    if ($null -ne $sbState) {
        if ([int]$sbState -eq 1) { Add-Check 'Arranque seguro (Secure Boot)' 'OK' 'Activado' 10 } else { Add-Check 'Arranque seguro (Secure Boot)' 'FALLO' 'Desactivado en UEFI' 10 }
    }
    else {
        try {
            if (Confirm-SecureBootUEFI -ErrorAction Stop) { Add-Check 'Arranque seguro (Secure Boot)' 'OK' 'Activado' 10 } else { Add-Check 'Arranque seguro (Secure Boot)' 'FALLO' 'Desactivado en UEFI' 10 }
        }
        catch {
            if ($_.Exception.Message -match '(?i)not supported|no se admite|no es compatible') { Add-Check 'Arranque seguro (Secure Boot)' 'FALLO' 'BIOS heredada (sin UEFI)' 10 }
            else { Add-Check 'Arranque seguro (Secure Boot)' 'N/D' 'Requiere administrador' 10 }
        }
    }

    # TPM
    $tpmDone = $false
    try {
        $t = Get-Tpm -ErrorAction Stop
        $tpmDone = $true
        $ver = ''
        try { $w = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop; $ver = ([string]$w.SpecVersion).Split(',')[0].Trim() } catch { }
        if ($t.TpmPresent -and $t.TpmReady) { Add-Check 'Chip TPM' 'OK' ("Presente y listo {0}" -f $ver).Trim() 5 }
        elseif ($t.TpmPresent) { Add-Check 'Chip TPM' 'FALLO' 'Presente pero no inicializado' 5 }
        else { Add-Check 'Chip TPM' 'FALLO' 'No presente o desactivado en BIOS' 5 }
    }
    catch { }
    if (-not $tpmDone) { Add-Check 'Chip TPM' 'N/D' 'Requiere administrador' 5 }

    # VBS / HVCI
    try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbs = [int](Get-CSWSecProp $dg 'VirtualizationBasedSecurityStatus' 0)
        $running = @(Get-CSWSecProp $dg 'SecurityServicesRunning' @())
        $hvci = ($running -contains 2) -or ($running -contains [uint32]2)
        if ($hvci) { Add-Check 'VBS / Integridad de memoria' 'OK' 'VBS en ejecucion con HVCI' 5 }
        elseif ($vbs -eq 2) { Add-Check 'VBS / Integridad de memoria' 'FALLO' 'VBS activo, integridad de memoria desactivada' 5 }
        else { Add-Check 'VBS / Integridad de memoria' 'FALLO' 'Seguridad basada en virtualizacion desactivada' 5 }
    }
    catch { Add-Check 'VBS / Integridad de memoria' 'N/D' 'No disponible' 5 }

    # BitLocker (unidad del sistema)
    try {
        $bl = @(Get-CSWSecBitLockerData | Where-Object { $_.Unidad -eq $env:SystemDrive }) | Select-Object -First 1
        if ($bl -and $bl.Proteccion -eq 'On') { Add-Check 'Cifrado de disco (BitLocker)' 'OK' "$env:SystemDrive protegida" 10 }
        elseif ($bl) { Add-Check 'Cifrado de disco (BitLocker)' 'FALLO' "$env:SystemDrive sin proteger ($($bl.Estado))" 10 }
        else { Add-Check 'Cifrado de disco (BitLocker)' 'N/D' '' 10 }
    }
    catch { Add-Check 'Cifrado de disco (BitLocker)' 'N/D' 'No disponible o requiere administrador' 10 }

    # Actualizaciones
    $pi = Get-CSWSecLastPatchInfo
    if ($null -ne $pi.Days) {
        if ($pi.Days -le 45) { Add-Check 'Actualizaciones de Windows' 'OK' ("Ultimo parche hace {0} dias" -f $pi.Days) 15 }
        else { Add-Check 'Actualizaciones de Windows' 'FALLO' ("Ultimo parche hace {0} dias" -f $pi.Days) 15 }
    }
    else { Add-Check 'Actualizaciones de Windows' 'N/D' 'Sin fecha de parches' 15 }

    return $checks
}

function Get-CSWSecPosture {
    <#
        Resumen de PROTECCIONES ACTIVAS (antivirus, firewall, UAC, SmartScreen, Secure Boot, TPM,
        VBS, BitLocker, parches). Deliberadamente SIN puntuacion /100: la unica puntuacion de
        seguridad de la herramienta es la de "Auditoria de ciberseguridad" (catalogo completo,
        ponderado por severidad), para no dar al cliente dos notas distintas del mismo equipo.
    #>
    Write-CSWLog 'Comprobando las protecciones basicas del equipo...' -Level Step
    $checks = @(Get-CSWSecPostureChecks)
    $checks | ForEach-Object {
        $st = 'Activa'
        if ($_.Resultado -eq 'FALLO') { $st = 'NO ACTIVA' } elseif ($_.Resultado -eq 'N/D') { $st = 'Sin datos' }
        [pscustomobject]@{ Proteccion = $_.Control; Estado = $st; Detalle = $_.Detalle }
    }
    $eval = @($checks | Where-Object { $_.Resultado -ne 'N/D' })
    if (-not $eval.Count) { return (New-CSWResult -Summary 'No se pudo comprobar ninguna proteccion del equipo' -Status Warn) }
    $ok = @($eval | Where-Object { $_.Resultado -eq 'OK' })
    $fails = @($checks | Where-Object { $_.Resultado -eq 'FALLO' } | ForEach-Object { $_.Control })
    $nd = @($checks | Where-Object { $_.Resultado -eq 'N/D' }).Count
    if ($nd -and -not (Test-CSWAdmin)) { Write-CSWLog 'Ejecute como administrador para comprobar TPM, Secure Boot y BitLocker.' -Level Info }
    Write-CSWLog 'Para una evaluacion completa con puntuacion use "Auditoria de ciberseguridad > Auditoria completa".' -Level Info
    $msg = 'Protecciones activas: {0} de {1}' -f $ok.Count, $eval.Count
    if ($nd) { $msg += (' ({0} sin datos)' -f $nd) }
    if ($fails.Count) { return (New-CSWResult -Summary ('{0}. Desactivadas: {1}' -f $msg, ($fails -join ', ')) -Status Warn) }
    return (New-CSWResult -Summary "$msg. Todas las protecciones comprobadas estan activas.")
}

function Get-CSWSecHotfixes {
    Write-CSWLog 'Consultando parches instalados (Get-HotFix)...' -Level Step
    $pi = Get-CSWSecLastPatchInfo
    if (-not $pi.Items.Count) { return (New-CSWResult -Summary 'No se pudo obtener la lista de parches instalados' -Status Warn) }
    $pi.Items | Select-Object -First 15 | Select-Object HotFixID, Tipo, @{ N = 'Instalado'; E = { if ($_.Instalado) { '{0:dd\/MM\/yyyy}' -f [datetime]$_.Instalado } else { '' } } }, InstaladoPor
    if ($null -eq $pi.Days) { return (New-CSWResult -Summary ("{0} parches instalados; fecha del ultimo desconocida" -f $pi.Items.Count) -Status Warn) }
    Write-CSWLog ("Ultimo parche: {0:dd\/MM\/yyyy} (hace {1} dias)" -f $pi.Last, $pi.Days) -Level Info
    if ($pi.Days -gt 45) {
        Write-CSWLog 'Mas de 45 dias sin actualizaciones: revisar Windows Update.' -Level Warn
        return (New-CSWResult -Summary ("Windows sin actualizar desde hace {0} dias (ultimo parche {1:dd\/MM\/yyyy})" -f $pi.Days, $pi.Last) -Status Warn)
    }
    return (New-CSWResult -Summary ("Windows actualizado: ultimo parche hace {0} dias ({1:dd\/MM\/yyyy})" -f $pi.Days, $pi.Last))
}

# ---------------------------------------------------------------------------
# Acciones: archivo hosts
# ---------------------------------------------------------------------------
function Show-CSWSecHosts {
    $path = Get-CSWSecHostsPath
    Write-CSWLog "Leyendo $path (solo lectura)..." -Level Step
    if (-not (Test-Path -LiteralPath $path)) { return (New-CSWResult -Summary 'El archivo hosts no existe (Windows usara solo DNS)' -Status Warn) }
    try { $rows = @(Get-CSWSecHostsEntries) }
    catch { return (New-CSWResult -Summary "No se pudo leer el archivo hosts: $($_.Exception.Message)" -Status Error) }
    if (-not $rows.Count) { return (New-CSWResult -Summary 'Archivo hosts limpio (sin entradas activas)') }
    $rows
    $hijack = @($rows | Where-Object { $_.Nota -like 'REDIRECCION*' })
    $custom = @($rows | Where-Object { $_.Nota -ne 'Normal' })
    if ($hijack.Count) {
        foreach ($h in $hijack) { Write-CSWLog ("Linea {0}: {1} -> {2}" -f $h.Linea, $h.Hosts, $h.IP) -Level Warn }
        return (New-CSWResult -Summary ("Archivo hosts con {0} redireccion(es) sospechosa(s) de dominios conocidos" -f $hijack.Count) -Status Warn)
    }
    if ($custom.Count) { return (New-CSWResult -Summary ("Archivo hosts con {0} entrada(s) personalizada(s); revisar si son intencionadas" -f $custom.Count) -Status Warn) }
    return (New-CSWResult -Summary 'Archivo hosts sin entradas anomalas')
}

function Reset-CSWSecHosts {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $path = Get-CSWSecHostsPath
    $backupDir = Get-CSWDataPath Backups
    $active = @()
    if (Test-Path -LiteralPath $path) {
        try { $active = @(Get-CSWSecHostsEntries) } catch { }
        $dest = Join-Path $backupDir ('hosts_{0}_{1:yyyyMMdd_HHmmss}.bak' -f $env:COMPUTERNAME, (Get-Date))
        Write-CSWLog "Copia de seguridad del hosts actual en $dest" -Level Step
        try { Copy-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop }
        catch {
            Write-CSWLog "No se pudo hacer la copia de seguridad: $($_.Exception.Message)" -Level Error
            return (New-CSWResult -Summary 'No se restauro el hosts: fallo la copia de seguridad previa' -Status Error)
        }
        Write-CSWLog ("El hosts anterior tenia {0} entrada(s) activa(s)." -f $active.Count) -Level Info
        try {
            $fi = Get-Item -LiteralPath $path -Force
            if ($fi.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                Write-CSWLog 'Quitando atributo de solo lectura del hosts.' -Level Info
                $fi.Attributes = ($fi.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
            }
        }
        catch { }
    }
    Write-CSWLog 'Escribiendo archivo hosts por defecto de Microsoft...' -Level Step
    try {
        $content = ($script:SecDefaultHosts -replace "`r?`n", "`r`n") + "`r`n"
        [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::ASCII)
    }
    catch {
        Write-CSWLog "No se pudo escribir el hosts: $($_.Exception.Message) (el antivirus puede bloquearlo)" -Level Error
        return (New-CSWResult -Summary 'No se pudo restaurar el archivo hosts' -Status Error)
    }
    [void](Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/flushdns')
    Write-CSWLog 'Archivo hosts restaurado y cache DNS vaciada.' -Level Ok
    return (New-CSWResult -Summary ("Archivo hosts restaurado al original de Windows ({0} entrada(s) retirada(s); copia guardada)" -f $active.Count))
}

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------
Register-CSWModule -Id 'Security' -Name 'Seguridad' -Order 50 -Icon 'shield' `
    -Description 'Antivirus, firewall, puertos, autoarranques, cuentas, cifrado y postura de seguridad' -Actions @(
    @{ Id = 'DefenderStatus'; Name = 'Estado del antivirus'; Command = 'Get-CSWSecDefenderStatus'; Risk = 'Low'
        Description = 'Estado de Microsoft Defender (tiempo real, firmas, análisis, protección contra alteraciones) y antivirus de terceros' },
    @{ Id = 'UpdateSignatures'; Name = 'Actualizar firmas'; Command = 'Update-CSWSecSignatures'; Risk = 'Low'
        Description = 'Descarga las últimas firmas de Microsoft Defender' },
    @{ Id = 'QuickScan'; Name = 'Análisis rápido'; Command = 'Start-CSWSecQuickScan'; Risk = 'Low'; LongRunning = $true
        Description = 'Análisis rápido de Microsoft Defender en las zonas habituales de malware' },
    @{ Id = 'FullScan'; Name = 'Análisis completo'; Command = 'Start-CSWSecFullScan'; Risk = 'Medium'; LongRunning = $true
        ConfirmMessage = 'El análisis completo puede tardar una hora o más y ralentizar el equipo mientras dura.'
        Description = 'Análisis completo de todos los discos con Microsoft Defender' },
    @{ Id = 'OfflineScan'; Name = 'Análisis sin conexión'; Command = 'Start-CSWSecOfflineScan'; Risk = 'High'
        ConfirmMessage = 'El equipo se REINICIARÁ inmediatamente para ejecutar Defender sin conexión (unos 15 min). Guarde y cierre todo antes de continuar.'
        Description = 'Reinicia y analiza fuera de Windows para eliminar malware persistente (rootkits)' },
    @{ Id = 'Threats'; Name = 'Amenazas detectadas'; Command = 'Get-CSWSecThreats'; Risk = 'Low'
        Description = 'Historial de amenazas detectadas por Defender y su estado' },
    @{ Id = 'FirewallStatus'; Name = 'Estado del firewall'; Command = 'Get-CSWSecFirewallStatus'; Risk = 'Low'
        Description = 'Estado del Firewall de Windows en cada perfil de red' },
    @{ Id = 'EnableFirewall'; Name = 'Reactivar firewall'; Command = 'Repair-CSWSecFirewall'; Risk = 'Medium'; ModifiesSystem = $true
        ConfirmMessage = 'Se activará el Firewall de Windows en los perfiles Dominio, Privado y Público. Algún programa podría pedir permiso de red.'
        Description = 'Activa el Firewall de Windows en todos los perfiles e inicia su servicio' },
    @{ Id = 'ListeningPorts'; Name = 'Puertos en escucha'; Command = 'Get-CSWSecListeningPorts'; Risk = 'Low'
        Description = 'Puertos abiertos en escucha con el proceso, servicio y ruta que los abre'
        Inputs = @(@{ Name = 'IncludeUdp'; Label = 'Incluir UDP'; Type = 'Bool'; Default = $false }) },
    @{ Id = 'Connections'; Name = 'Conexiones activas'; Command = 'Get-CSWSecConnections'; Risk = 'Low'
        Description = 'Conexiones establecidas con IPs remotas y el proceso responsable'
        Inputs = @(@{ Name = 'ResolveNames'; Label = 'Resolver nombres DNS'; Type = 'Bool'; Default = $false }) },
    @{ Id = 'Autoruns'; Name = 'Autoarranques sospechosos'; Command = 'Get-CSWSecAutoruns'; Risk = 'Low'
        Description = 'Revisa claves Run/RunOnce, carpetas de Inicio y tareas programadas de terceros (ruta y firma digital)' },
    @{ Id = 'LocalAdmins'; Name = 'Administradores locales'; Command = 'Get-CSWSecLocalAdmins'; Risk = 'Low'
        Description = 'Miembros del grupo de Administradores (por SID, válido en cualquier idioma)' },
    @{ Id = 'BitLocker'; Name = 'Estado de BitLocker'; Command = 'Get-CSWSecBitLocker'; Risk = 'Low'
        Description = 'Estado de cifrado de cada unidad e indicación de si existe clave de recuperación (nunca la muestra)' },
    @{ Id = 'Posture'; Name = 'Protecciones activas'; Command = 'Get-CSWSecPosture'; Risk = 'Low'
        Description = 'Comprueba si están activos antivirus, firewall, UAC, SmartScreen, Secure Boot, TPM, VBS, BitLocker y parches (sin puntuación; la nota está en Auditoría de ciberseguridad)' },
    @{ Id = 'Hotfixes'; Name = 'Parches recientes'; Command = 'Get-CSWSecHotfixes'; Risk = 'Low'
        Description = 'Últimas 15 actualizaciones instaladas y días desde la última' },
    @{ Id = 'HostsView'; Name = 'Ver archivo hosts'; Command = 'Show-CSWSecHosts'; Risk = 'Low'
        Description = 'Muestra las entradas activas del archivo hosts y marca redirecciones sospechosas (solo lectura)' },
    @{ Id = 'HostsRestore'; Name = 'Restaurar hosts'; Command = 'Reset-CSWSecHosts'; Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'Se reemplazará el archivo hosts por el original de Windows (se guarda copia en Backups). Se perderán bloqueos o redirecciones personalizadas.'
        Description = 'Restaura el archivo hosts por defecto con copia de seguridad previa' }
)

Export-ModuleMember -Function *
