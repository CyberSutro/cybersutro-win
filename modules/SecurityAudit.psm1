#Requires -Version 5.1
<#
    Cybersutro win - Modulo Auditoria de ciberseguridad (SecurityAudit)
    Auditoria DEFENSIVA de cumplimiento tipo checklist: cuentas, UAC, antimalware,
    firewall, actualizaciones, cifrado, red, auditoria de eventos, hardening y software.
    Cada control es un dato del catalogo con su Test (scriptblock). Un fallo en un control
    nunca detiene la auditoria: se registra como 'SinDatos' con el motivo.
    Las remediaciones (Fix*) solo actuan si el control no cumple y registran el valor previo.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
$script:AuditCategories = @(
    'Cuentas y autenticacion',
    'Control de cuentas (UAC)',
    'Proteccion antimalware',
    'Firewall',
    'Actualizaciones',
    'Cifrado y arranque',
    'Red y protocolos',
    'Registro y auditoria',
    'Hardening del sistema',
    'Software'
)
$script:AuditSevWeight  = @{ Critica = 10; Alta = 6; Media = 3; Baja = 1 }
$script:AuditSevOrder   = @{ Critica = 0; Alta = 1; Media = 2; Baja = 3 }
$script:AuditStateOrder = @{ NoCumple = 0; Parcial = 1; SinDatos = 2; Cumple = 3; NoAplica = 4 }

# GUIDs de subcategorias de auditoria avanzada (independientes del idioma)
$script:AuditGuid = @{
    Logon                   = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    Logoff                  = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    AccountLockout          = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    ProcessCreation         = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    AuditPolicyChange       = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    UserAccountManagement   = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    SecurityGroupManagement = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    CredentialValidation    = '{0CCE923F-69AE-11D9-BED3-505054503030}'
}

$script:AuditRegUacPath   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:AuditRegLsaPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:AuditRegWinlogon  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$script:AuditRegWDigest   = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$script:AuditRegDnsClient = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$script:AuditRegExplorer  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$script:AuditRegSbl       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

$script:AuditRemoteToolRegex = '(?i)AnyDesk|TeamViewer|RustDesk|Splashtop|LogMeIn|ScreenConnect|ConnectWise Control|Ammyy|UltraViewer|Chrome Remote Desktop|RealVNC|VNC Server|TightVNC|UltraVNC|TigerVNC|Supremo|DWService|DWAgent|Atera|NinjaRMM|NinjaOne|GoTo Resolve|GoToAssist|Zoho Assist|Remote Utilities|MeshAgent|MeshCentral|Radmin|Parsec|Action1|NoMachine|HopToDesk|Getscreen|AeroAdmin|Bomgar|BeyondTrust Remote'
$script:AuditEolRegex        = '(?i)Adobe Flash|Shockwave Player|Microsoft Silverlight|QuickTime|Java\(TM\) [67]\b|Java [67] Update|J2SE Runtime|Java 2 Runtime'
$script:AuditBackupRegex     = '(?i)Veeam|Acronis|Macrium|EaseUS Todo|AOMEI Backupper|Backblaze|Carbonite|Cobian|Duplicati|Iperius|Paragon Backup|Genie Timeline|NovaBACKUP|Arcserve|Datto|IDrive|SyncBack|CrashPlan|Active Backup for Business|Uranium Backup|Kopia|UrBackup|Areca Backup|FBackup'
$script:AuditBrowserRegex    = '(?i)^(Google Chrome|Microsoft Edge|Mozilla Firefox|Brave|Opera Stable|Opera GX|Opera\b|Vivaldi|Waterfox|LibreWolf|Chromium|Tor Browser)'

# Contexto (cache) de una ejecucion: se reinicia en cada auditoria
$script:AuditCtx = @{}

# ---------------------------------------------------------------------------
# Utilidades seguras con StrictMode
# ---------------------------------------------------------------------------
function Get-CSWAuditReg {
    <# Devuelve el valor de registro o $null si la clave/valor no existe o no es legible. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $k) { return $null }
        return $k.GetValue($Name, $null)
    }
    catch { return $null }
}

function Get-CSWAuditRegInt {
    <# Valor de registro convertido a entero, o $null. #>
    param([string]$Path, [string]$Name)
    $v = Get-CSWAuditReg -Path $Path -Name $Name
    if ($null -eq $v) { return $null }
    $i = 0L
    if ([long]::TryParse(([string]$v).Trim(), [ref]$i)) { return [long]$i }
    return $null
}

function Get-CSWAuditProp {
    <# Lee una propiedad de un objeto sin romper con StrictMode. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable]) { if ($Object.ContainsKey($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function New-CSWAuditOutcome {
    param([string]$Estado, [string]$Valor = '')
    return @{ Estado = $Estado; Valor = $Valor }
}

function Get-CSWAuditCache {
    <# Ejecuta un cargador una sola vez por auditoria; si fallo, relanza el mismo mensaje. #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][scriptblock]$Loader)
    if (-not $script:AuditCtx.ContainsKey($Key)) {
        try { $script:AuditCtx[$Key] = @{ Ok = $true; Data = @(& $Loader); Error = '' } }
        catch { $script:AuditCtx[$Key] = @{ Ok = $false; Data = @(); Error = $_.Exception.Message } }
    }
    $e = $script:AuditCtx[$Key]
    if (-not $e.Ok) { throw $e.Error }
    return $e.Data
}

function Test-CSWAuditIsAdmin {
    if (-not $script:AuditCtx.ContainsKey('IsAdmin')) { $script:AuditCtx['IsAdmin'] = [bool](Test-CSWAdmin) }
    return $script:AuditCtx['IsAdmin']
}

function Assert-CSWAuditAdmin {
    param([string]$What)
    if (-not (Test-CSWAuditIsAdmin)) { throw "Requiere ejecutar como administrador ($What)" }
}

function ConvertTo-CSWAuditDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return [datetime]$Value }
    $s = ([string]$Value).Trim()
    if (-not $s) { return $null }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $d = [datetime]::MinValue
    foreach ($fmt in 'M/d/yyyy', 'MM/dd/yyyy', 'yyyyMMdd', 'yyyy-MM-dd', 'd/M/yyyy') {
        if ([datetime]::TryParseExact($s, $fmt, $inv, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    }
    if ($s -match '^[0-9a-fA-F]{15,16}$') {
        try { return [datetime]::FromFileTime([Convert]::ToInt64($s, 16)) } catch { }
    }
    if ([datetime]::TryParse($s, $inv, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Join-CSWAuditList {
    <# Une una lista limitando el numero de elementos mostrados. #>
    param([object[]]$Items, [int]$Max = 6)
    $arr = @($Items | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    if ($arr.Count -eq 0) { return '' }
    $txt = (@($arr | Select-Object -First $Max) -join ', ')
    if ($arr.Count -gt $Max) { $txt += (' (+{0} mas)' -f ($arr.Count - $Max)) }
    return $txt
}

function Get-CSWAuditSidName {
    param([string]$Sid)
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# ---------------------------------------------------------------------------
# Fuentes de datos (cacheadas por auditoria)
# ---------------------------------------------------------------------------
function Get-CSWAuditOsInfo {
    Get-CSWAuditCache 'Os' {
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $build = 0
        [void][int]::TryParse([string](Get-CSWAuditReg $cv 'CurrentBuildNumber'), [ref]$build)
        $ubr = Get-CSWAuditRegInt $cv 'UBR'
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $aad = $false
        try {
            $ji = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
            if (Test-Path -LiteralPath $ji) { $aad = (@(Get-ChildItem -LiteralPath $ji -ErrorAction SilentlyContinue).Count -gt 0) }
        }
        catch { }
        @{
            Build          = $build
            Ubr            = $ubr
            DisplayVersion = [string](Get-CSWAuditReg $cv 'DisplayVersion')
            Edition        = [string](Get-CSWAuditReg $cv 'EditionID')
            Caption        = [string]$os.Caption
            ProductType    = [int]$os.ProductType
            PartOfDomain   = [bool]$cs.PartOfDomain
            AzureAdJoined  = $aad
        }
    }
}

function Get-CSWAuditLocalUser {
    Get-CSWAuditCache 'Users' {
        foreach ($u in @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)) {
            [pscustomobject]@{
                Name             = [string]$u.Name
                Sid              = [string]$u.SID
                Disabled         = [bool]$u.Disabled
                PasswordRequired = [bool]$u.PasswordRequired
                PasswordExpires  = [bool]$u.PasswordExpires
            }
        }
    }
}

function Get-CSWAuditMachineSidPrefix {
    $adm = @(Get-CSWAuditLocalUser | Where-Object { $_.Sid -match '-500$' }) | Select-Object -First 1
    if ($adm) { return ($adm.Sid -replace '-500$', '') }
    return ''
}

function Get-CSWAuditAdminMember {
    <# Miembros del grupo Administradores (S-1-5-32-544), independiente del idioma. #>
    Get-CSWAuditCache 'Admins' {
        $list = @()
        $ok = $false
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            try {
                foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
                    $list += [pscustomobject]@{ Name = [string]$m.Name; Sid = [string]$m.SID; Class = [string]$m.ObjectClass }
                }
                $ok = $true
            }
            catch { $list = @() }
        }
        if (-not $ok) {
            $gname = (Get-CSWAuditSidName 'S-1-5-32-544').Split('\')[-1]
            $grp = [ADSI]("WinNT://$env:COMPUTERNAME/$gname,group")
            foreach ($m in @($grp.Invoke('Members'))) {
                $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $cls = [string]$m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                $sid = ''
                try {
                    $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                    $sid = (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
                }
                catch { }
                $list += [pscustomobject]@{ Name = ($path -replace '^WinNT://', '' -replace '/', '\'); Sid = $sid; Class = $cls }
            }
        }
        $list
    }
}

function Get-CSWAuditSecPol {
    <# Exporta la politica de seguridad local con secedit (requiere admin) y la parsea. #>
    Get-CSWAuditCache 'SecPol' {
        Assert-CSWAuditAdmin 'secedit'
        $ErrorActionPreference = 'Continue'
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('csw_secpol_{0}.inf' -f [guid]::NewGuid().ToString('N'))
        try {
            $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet 2>&1
            if (-not (Test-Path -LiteralPath $tmp)) { throw "secedit no genero la exportacion (codigo $LASTEXITCODE)" }
            $h = @{}
            foreach ($line in @(Get-Content -LiteralPath $tmp -ErrorAction Stop)) {
                if ($line -match '^\s*([^=;\[]+?)\s*=\s*(.*?)\s*$') { $h[$Matches[1]] = $Matches[2] }
            }
            if ($h.Count -eq 0) { throw 'La exportacion de secedit esta vacia' }
            $h
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-CSWAuditSecPolInt {
    param([string]$Name)
    $h = Get-CSWAuditSecPol
    if (-not $h.ContainsKey($Name)) { return $null }
    $i = 0L
    if ([long]::TryParse(([string]$h[$Name]).Trim(), [ref]$i)) { return $i }
    return $null
}

function Get-CSWAuditPolicyData {
    <# Configuracion de auditoria avanzada por GUID de subcategoria (auditpol /backup, requiere admin). #>
    Get-CSWAuditCache 'AuditPol' {
        Assert-CSWAuditAdmin 'auditpol'
        $ErrorActionPreference = 'Continue'
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('csw_auditpol_{0}.csv' -f [guid]::NewGuid().ToString('N'))
        try {
            $null = & auditpol.exe /backup "/file:$tmp" 2>&1
            if (-not (Test-Path -LiteralPath $tmp)) { throw "auditpol no genero la copia (codigo $LASTEXITCODE)" }
            $h = @{}
            $lines = @(Get-Content -LiteralPath $tmp -ErrorAction Stop | Select-Object -Skip 1)
            $rows = @($lines | ConvertFrom-Csv -Header 'Machine', 'Target', 'Sub', 'Guid', 'Incl', 'Excl', 'Value')
            foreach ($r in $rows) {
                $g = [string]$r.Guid
                if ($g -match '^\{[0-9A-Fa-f-]{36}\}$') {
                    $iv = 0
                    [void][int]::TryParse([string]$r.Value, [ref]$iv)
                    $h[$g.ToUpperInvariant()] = $iv
                }
            }
            if ($h.Count -eq 0) { throw 'Formato de auditpol no reconocido' }
            $h
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-CSWAuditDefender {
    Get-CSWAuditCache 'Defender' {
        $st = $null; $pref = $null
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { $st = $null }
            try { $pref = Get-MpPreference -ErrorAction Stop } catch { $pref = $null }
        }
        $mode = [string](Get-CSWAuditProp $st 'AMRunningMode')
        $primary = $false
        if ($st) {
            if ($mode) { $primary = ($mode -eq 'Normal') }
            else { $primary = ([bool](Get-CSWAuditProp $st 'AntivirusEnabled') -and [bool](Get-CSWAuditProp $st 'AMServiceEnabled')) }
        }
        @{ Status = $st; Pref = $pref; Primary = $primary; Mode = $mode }
    }
}

function Get-CSWAuditAvProduct {
    <# Antivirus registrados en el Centro de seguridad (no existe en Windows Server). #>
    Get-CSWAuditCache 'AV' {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $state = 0
            [void][int]::TryParse([string](Get-CSWAuditProp $p 'productState'), [ref]$state)
            $name = [string](Get-CSWAuditProp $p 'displayName')
            [pscustomobject]@{
                Name       = $name
                Enabled    = (($state -band 0x1000) -ne 0)
                UpToDate   = (($state -band 0x10) -eq 0)
                IsDefender = ($name -match 'Defender')
            }
        }
    }
}

function Assert-CSWAuditDefenderPrimary {
    <# Devuelve el contexto de Defender o un resultado NoAplica si no es el AV principal. #>
    $d = Get-CSWAuditDefender
    if (-not $d.Status) { return (New-CSWAuditOutcome 'NoAplica' 'Microsoft Defender no disponible en este equipo') }
    if (-not $d.Primary) {
        $m = $d.Mode
        if (-not $m) { $m = 'inactivo' }
        return (New-CSWAuditOutcome 'NoAplica' ("Defender no es el antivirus principal (modo: {0})" -f $m))
    }
    return $null
}

function Get-CSWAuditFwProfile {
    Get-CSWAuditCache 'FwProfiles' {
        $done = $false
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            try {
                $out = @()
                foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
                    $out += [pscustomobject]@{
                        Name       = [string]$p.Name
                        Enabled    = ([string]$p.Enabled -eq 'True')
                        Inbound    = [string]$p.DefaultInboundAction
                        LogBlocked = [string]$p.LogBlocked
                        LogAllowed = [string]$p.LogAllowed
                    }
                }
                if ($out.Count) { $out; $done = $true }
            }
            catch { $done = $false }
        }
        if (-not $done) {
            $fw = New-Object -ComObject HNetCfg.FwPolicy2
            foreach ($pair in @(@(1, 'Domain'), @(2, 'Private'), @(4, 'Public'))) {
                $inb = 'Block'
                if ([int]$fw.DefaultInboundAction($pair[0]) -eq 1) { $inb = 'Allow' }
                [pscustomobject]@{ Name = $pair[1]; Enabled = [bool]$fw.FirewallEnabled($pair[0]); Inbound = $inb; LogBlocked = ''; LogAllowed = '' }
            }
        }
    }
}

function Get-CSWAuditFwRule {
    <# Reglas de entrada habilitadas que PERMITEN trafico (API COM, rapida y sin admin). #>
    Get-CSWAuditCache 'FwRules' {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($r in $fw.Rules) {
            if ([int]$r.Direction -ne 1 -or -not [bool]$r.Enabled -or [int]$r.Action -ne 1) { continue }
            [pscustomobject]@{
                Name     = [string]$r.Name
                Profiles = [int]$r.Profiles
                Remote   = [string]$r.RemoteAddresses
                Ports    = [string]$r.LocalPorts
                Grouping = [string]$r.Grouping
                Protocol = [int]$r.Protocol
                App      = [string]$r.ApplicationName
            }
        }
    }
}

function Test-CSWAuditPortMatch {
    param([string]$Ports, [int]$Port)
    if (-not $Ports) { return $false }
    foreach ($p in ($Ports -split ',')) {
        $p = $p.Trim()
        if ($p -eq [string]$Port) { return $true }
        if ($p -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true } }
    }
    return $false
}

function Get-CSWAuditPublicExposure {
    <# Reglas que exponen un puerto TCP a cualquier origen en el perfil Publico. #>
    param([int]$Port)
    $rules = @(Get-CSWAuditFwRule)
    $hit = @()
    foreach ($r in $rules) {
        if (($r.Profiles -band 4) -eq 0) { continue }
        if ($r.Remote -ne '*' -and $r.Remote -ne '') { continue }
        if ($r.Protocol -ne 6 -and $r.Protocol -ne 256) { continue }
        if (Test-CSWAuditPortMatch $r.Ports $Port) { $hit += $r.Name }
    }
    return $hit
}

function Get-CSWAuditFeature {
    <# InstallState de una caracteristica opcional: 1 habilitada, 2 deshabilitada, 3 ausente; $null si no existe. #>
    param([string]$Name)
    $key = "Feature_$Name"
    $d = @(Get-CSWAuditCache $key {
            $f = @(Get-CimInstance Win32_OptionalFeature -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop) | Select-Object -First 1
            if ($f) { [int]$f.InstallState } else { -1 }
        })
    if ($d.Count -eq 0 -or $d[0] -eq -1) { return $null }
    return [int]$d[0]
}

function Get-CSWAuditSoftware {
    Get-CSWAuditCache 'Software' {
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        $seen = @{}
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $n = [string]$k.GetValue('DisplayName', $null)
                if (-not $n) { continue }
                $v = [string]$k.GetValue('DisplayVersion', $null)
                $id = "$n|$v"
                if ($seen.ContainsKey($id)) { continue }
                $seen[$id] = $true
                [pscustomobject]@{ Name = $n.Trim(); Version = $v.Trim(); Publisher = [string]$k.GetValue('Publisher', $null) }
            }
        }
    }
}

function Get-CSWAuditDeviceGuard {
    Get-CSWAuditCache 'DeviceGuard' {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        @{
            Vbs        = [int](Get-CSWAuditProp $dg 'VirtualizationBasedSecurityStatus')
            Running    = @(Get-CSWAuditProp $dg 'SecurityServicesRunning' | ForEach-Object { [int]$_ })
            Configured = @(Get-CSWAuditProp $dg 'SecurityServicesConfigured' | ForEach-Object { [int]$_ })
        }
    }
}

function Get-CSWAuditRdp {
    $polDeny = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
    $deny = $polDeny
    if ($null -eq $deny) { $deny = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' }
    if ($null -eq $deny) { $deny = 1 }
    $nla = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
    if ($null -eq $nla) { $nla = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' }
    $port = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
    if ($null -eq $port) { $port = 3389 }
    return @{ Enabled = ($deny -eq 0); Nla = ($nla -eq 1); Port = [int]$port }
}

function ConvertTo-CSWAuditSettingText {
    param([int]$Value)
    switch ($Value) { 1 { return 'Correcto' } 2 { return 'Error' } 3 { return 'Correcto y error' } default { return 'Sin auditoria' } }
}

function Test-CSWAuditSubcategory {
    <# $Required: hashtable NombreSubcategoria -> mascara requerida (1 exito, 2 error, 3 ambos). #>
    param([hashtable]$Required)
    $ap = Get-CSWAuditPolicyData
    $full = 0; $none = 0; $parts = @()
    foreach ($k in ($Required.Keys | Sort-Object)) {
        $g = $script:AuditGuid[$k].ToUpperInvariant()
        $v = 0
        if ($ap.ContainsKey($g)) { $v = [int]$ap[$g] }
        $req = [int]$Required[$k]
        $parts += ('{0}: {1}' -f $k, (ConvertTo-CSWAuditSettingText $v))
        if (($v -band $req) -eq $req) { $full++ }
        elseif (($v -band $req) -eq 0) { $none++ }
    }
    $txt = $parts -join '; '
    if ($full -eq $Required.Count) { return (New-CSWAuditOutcome 'Cumple' $txt) }
    if ($none -eq $Required.Count) { return (New-CSWAuditOutcome 'NoCumple' $txt) }
    return (New-CSWAuditOutcome 'Parcial' $txt)
}

# ---------------------------------------------------------------------------
# Catalogo de controles
# ---------------------------------------------------------------------------
$script:AuditCatalog = @(

    # ======================= CUENTAS Y AUTENTICACION =======================
    @{ Id = 'ACC-01'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Cuentas)'
        Titulo = 'Cuenta Invitado deshabilitada'
        Recomendacion = 'Deshabilitar la cuenta Invitado (accion FixGuestAccount o: net user <Invitado> /active:no).'
        Test = {
            $g = @(Get-CSWAuditLocalUser | Where-Object { $_.Sid -match '-501$' }) | Select-Object -First 1
            if (-not $g) { return (New-CSWAuditOutcome 'NoAplica' 'No existe cuenta Invitado (RID 501)') }
            if ($g.Disabled) { return (New-CSWAuditOutcome 'Cumple' ("Deshabilitada ({0})" -f $g.Name)) }
            return (New-CSWAuditOutcome 'NoCumple' ("Habilitada ({0})" -f $g.Name))
        }
    }
    @{ Id = 'ACC-02'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Cuentas)'
        Titulo = 'Administrador integrado (RID 500) deshabilitado o renombrado'
        Recomendacion = 'Deshabilitar la cuenta Administrador integrada y usar cuentas administrativas nominales; si debe usarse, renombrarla y darle una contrasena larga y unica.'
        Test = {
            $a = @(Get-CSWAuditLocalUser | Where-Object { $_.Sid -match '-500$' }) | Select-Object -First 1
            if (-not $a) { return (New-CSWAuditOutcome 'NoAplica' 'No se encontro la cuenta RID 500') }
            $defaultNames = @('Administrator', 'Administrador', 'Administrateur', 'Amministratore', 'Administratorem')
            if ($a.Disabled) { return (New-CSWAuditOutcome 'Cumple' ("Deshabilitada ({0})" -f $a.Name)) }
            if ($defaultNames -notcontains $a.Name) { return (New-CSWAuditOutcome 'Parcial' ("Habilitada pero renombrada a '{0}'" -f $a.Name)) }
            return (New-CSWAuditOutcome 'NoCumple' ("Habilitada con el nombre por defecto '{0}'" -f $a.Name))
        }
    }
    @{ Id = 'ACC-03'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (minimo privilegio)'
        Titulo = 'Numero de administradores locales <= 2'
        Recomendacion = 'Dejar como maximo 2 cuentas administradoras; el uso diario debe hacerse con una cuenta estandar.'
        Test = {
            $users = @(Get-CSWAuditLocalUser)
            $m = @(Get-CSWAuditAdminMember)
            $active = @()
            foreach ($x in $m) {
                $lu = @($users | Where-Object { $_.Sid -eq $x.Sid }) | Select-Object -First 1
                if ($lu -and $lu.Disabled) { continue }
                $active += $x.Name
            }
            $n = $active.Count
            $txt = '{0} activos: {1}' -f $n, (Join-CSWAuditList $active 8)
            if ($n -le 2) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if ($n -le 4) { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'NoCumple' $txt)
        }
    }
    @{ Id = 'ACC-04'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Cuentas)'
        Titulo = 'Cuentas locales habilitadas que no requieren contrasena'
        Recomendacion = 'Exigir contrasena en todas las cuentas: net user <cuenta> /passwordreq:yes y asignar una contrasena robusta.'
        Test = {
            $bad = @(Get-CSWAuditLocalUser | Where-Object { -not $_.Disabled -and -not $_.PasswordRequired } | ForEach-Object { $_.Name })
            if ($bad.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Todas las cuentas habilitadas requieren contrasena') }
            return (New-CSWAuditOutcome 'NoCumple' ('Sin contrasena requerida: ' + (Join-CSWAuditList $bad)))
        }
    }
    @{ Id = 'ACC-05'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Politicas de contrasena) / NIST SP 800-63B'
        Titulo = 'Administradores locales con contrasena que nunca expira'
        Recomendacion = 'Revisar: si no hay MFA ni gestion de contrasenas (LAPS), establecer caducidad o rotacion periodica de las cuentas administradoras locales.'
        Test = {
            $prefix = Get-CSWAuditMachineSidPrefix
            $users = @(Get-CSWAuditLocalUser)
            $adm = @(Get-CSWAuditAdminMember | Where-Object { $prefix -and $_.Sid.StartsWith($prefix + '-') })
            $bad = @()
            foreach ($a in $adm) {
                $lu = @($users | Where-Object { $_.Sid -eq $a.Sid }) | Select-Object -First 1
                if ($lu -and -not $lu.Disabled -and -not $lu.PasswordExpires) { $bad += $lu.Name }
            }
            if ($bad.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Ningun administrador local activo con contrasena sin caducidad') }
            return (New-CSWAuditOutcome 'Parcial' ('Nunca expira: ' + (Join-CSWAuditList $bad)))
        }
    }
    @{ Id = 'ACC-06'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Politicas de contrasena)'
        Titulo = 'Longitud minima de contrasena >= 12'
        Recomendacion = 'Configurar "Longitud minima de la contrasena" a 12 o mas caracteres (secpol.msc > Directivas de cuenta).'
        Test = {
            $v = Get-CSWAuditSecPolInt 'MinimumPasswordLength'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'Valor no presente en la politica') }
            if ($v -ge 12) { return (New-CSWAuditOutcome 'Cumple' "$v caracteres") }
            if ($v -ge 8) { return (New-CSWAuditOutcome 'Parcial' "$v caracteres") }
            return (New-CSWAuditOutcome 'NoCumple' "$v caracteres")
        }
    }
    @{ Id = 'ACC-07'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Politicas de contrasena)'
        Titulo = 'Complejidad de contrasena habilitada'
        Recomendacion = 'Habilitar "La contrasena debe cumplir los requisitos de complejidad".'
        Test = {
            $v = Get-CSWAuditSecPolInt 'PasswordComplexity'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Habilitada') }
            return (New-CSWAuditOutcome 'NoCumple' 'Deshabilitada')
        }
    }
    @{ Id = 'ACC-08'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Bloqueo de cuenta)'
        Titulo = 'Umbral de bloqueo de cuenta entre 1 y 10 intentos'
        Recomendacion = 'Configurar "Umbral de bloqueo de cuenta" entre 5 y 10 intentos fallidos.'
        Test = {
            $v = Get-CSWAuditSecPolInt 'LockoutBadCount'
            if ($null -eq $v -or $v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'Sin bloqueo de cuenta (0)') }
            if ($v -le 10) { return (New-CSWAuditOutcome 'Cumple' "$v intentos") }
            return (New-CSWAuditOutcome 'Parcial' "$v intentos (demasiado alto)")
        }
    }
    @{ Id = 'ACC-09'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Bloqueo de cuenta)'
        Titulo = 'Duracion del bloqueo de cuenta >= 15 minutos'
        Recomendacion = 'Configurar "Duracion del bloqueo de cuenta" en 15 minutos o mas.'
        Test = {
            $t = Get-CSWAuditSecPolInt 'LockoutBadCount'
            if ($null -eq $t -or $t -eq 0) { return (New-CSWAuditOutcome 'NoAplica' 'El bloqueo de cuenta no esta habilitado') }
            $v = Get-CSWAuditSecPolInt 'LockoutDuration'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'Valor no presente en la politica') }
            if ($v -eq -1) { return (New-CSWAuditOutcome 'Cumple' 'Hasta desbloqueo por un administrador') }
            if ($v -ge 15) { return (New-CSWAuditOutcome 'Cumple' "$v minutos") }
            return (New-CSWAuditOutcome 'Parcial' "$v minutos")
        }
    }
    @{ Id = 'ACC-10'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Politicas de contrasena)'
        Titulo = 'Historial de contrasenas'
        Recomendacion = 'Configurar "Exigir historial de contrasenas" en 10 o mas.'
        Test = {
            $v = Get-CSWAuditSecPolInt 'PasswordHistorySize'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'Valor no presente en la politica') }
            if ($v -ge 10) { return (New-CSWAuditOutcome 'Cumple' "$v contrasenas recordadas") }
            if ($v -ge 1) { return (New-CSWAuditOutcome 'Parcial' "$v contrasenas recordadas") }
            return (New-CSWAuditOutcome 'NoCumple' 'Sin historial (0)')
        }
    }
    @{ Id = 'ACC-11'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Politicas de contrasena)'
        Titulo = 'Contrasenas sin cifrado reversible'
        Recomendacion = 'Deshabilitar "Almacenar contrasenas usando cifrado reversible".'
        Test = {
            $v = Get-CSWAuditSecPolInt 'ClearTextPassword'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'Cifrado reversible HABILITADO') }
            return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado')
        }
    }
    @{ Id = 'ACC-12'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline'
        Titulo = 'Inicio de sesion automatico deshabilitado'
        Recomendacion = 'Quitar el inicio de sesion automatico (accion FixAutoLogon): AutoAdminLogon=0.'
        Test = {
            $v = [string](Get-CSWAuditReg $script:AuditRegWinlogon 'AutoAdminLogon')
            $u = [string](Get-CSWAuditReg $script:AuditRegWinlogon 'DefaultUserName')
            if ($v.Trim() -eq '1') { return (New-CSWAuditOutcome 'NoCumple' ("Habilitado para el usuario '{0}'" -f $u)) }
            return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado')
        }
    }
    @{ Id = 'ACC-13'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Critica'; Referencia = 'Microsoft Security Baseline'
        Titulo = 'Sin contrasena en texto plano en Winlogon (DefaultPassword)'
        Recomendacion = 'Eliminar el valor Winlogon\DefaultPassword (accion FixAutoLogon) y cambiar la contrasena de esa cuenta, ya que ha estado expuesta.'
        Test = {
            $v = Get-CSWAuditReg $script:AuditRegWinlogon 'DefaultPassword'
            if ($null -ne $v -and [string]$v -ne '') { return (New-CSWAuditOutcome 'NoCumple' 'DefaultPassword presente en el registro (contenido no mostrado)') }
            return (New-CSWAuditOutcome 'Cumple' 'No hay contrasena almacenada')
        }
    }
    @{ Id = 'ACC-14'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'Microsoft Windows LAPS'
        Titulo = 'LAPS / Windows LAPS configurado'
        Recomendacion = 'Configurar Windows LAPS (GPO o Intune) para rotar la contrasena del administrador local.'
        Test = {
            $os = Get-CSWAuditOsInfo
            if (-not $os.PartOfDomain -and -not $os.AzureAdJoined) { return (New-CSWAuditOutcome 'NoAplica' 'Equipo no unido a dominio ni a Entra ID') }
            $found = @()
            foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS')) {
                $b = Get-CSWAuditRegInt $p 'BackupDirectory'
                if ($null -ne $b -and $b -gt 0) { $found += ('Windows LAPS (BackupDirectory={0})' -f $b) }
            }
            $legacy = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
            if ($legacy -eq 1) { $found += 'LAPS heredado (AdmPwd)' }
            if ($found.Count) { return (New-CSWAuditOutcome 'Cumple' ($found -join '; ')) }
            return (New-CSWAuditOutcome 'NoCumple' 'No se detecta politica LAPS')
        }
    }
    @{ Id = 'ACC-15'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Baja'; Referencia = 'Microsoft (Windows Hello)'
        Titulo = 'Windows Hello / PIN configurado (usuario actual)'
        Recomendacion = 'Opcional: configurar Windows Hello (PIN, huella o rostro) para evitar teclear la contrasena.'
        Test = {
            $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
            $m = @()
            if (Test-Path -LiteralPath "$base\NgcPin\Credentials\$sid") { $m += 'PIN' }
            if (Test-Path -LiteralPath "$base\FaceLogonEnrolledUsers\$sid") { $m += 'Rostro' }
            if ($null -ne (Get-CSWAuditReg "$base\FaceLogonEnrolledUsers" $sid)) { $m += 'Rostro' }
            if (Test-Path -LiteralPath "$base\FingerprintLogon\$sid") { $m += 'Huella' }
            $pol = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' 'Enabled'
            if ($m.Count) { return (New-CSWAuditOutcome 'Cumple' ('Metodos: ' + (@($m | Select-Object -Unique) -join ', '))) }
            if ($pol -eq 0) { return (New-CSWAuditOutcome 'Parcial' 'Windows Hello deshabilitado por politica') }
            return (New-CSWAuditOutcome 'Parcial' 'No se detecta Windows Hello para el usuario actual')
        }
    }
    @{ Id = 'ACC-16'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Opciones de seguridad)'
        Titulo = 'Traduccion anonima SID/nombre deshabilitada'
        Recomendacion = 'Deshabilitar "Acceso de red: permitir traduccion anonima de SID/nombre".'
        Test = {
            $v = Get-CSWAuditSecPolInt 'LSAAnonymousNameLookup'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'Habilitada') }
            return (New-CSWAuditOutcome 'Cumple' 'Deshabilitada')
        }
    }
    @{ Id = 'ACC-17'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Opciones de seguridad)'
        Titulo = 'Enumeracion anonima de cuentas y recursos restringida'
        Recomendacion = 'Configurar Lsa\RestrictAnonymousSAM=1 y Lsa\RestrictAnonymous=1.'
        Test = {
            $sam = Get-CSWAuditRegInt $script:AuditRegLsaPath 'RestrictAnonymousSAM'
            $ra = Get-CSWAuditRegInt $script:AuditRegLsaPath 'RestrictAnonymous'
            if ($null -eq $sam) { $sam = 1 }
            if ($null -eq $ra) { $ra = 0 }
            $txt = "RestrictAnonymousSAM=$sam; RestrictAnonymous=$ra"
            if ($sam -ge 1 -and $ra -ge 1) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if ($sam -ge 1) { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'NoCumple' $txt)
        }
    }
    @{ Id = 'ACC-18'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Opciones de seguridad)'
        Titulo = 'Nivel de autenticacion LAN Manager (solo NTLMv2)'
        Recomendacion = 'Configurar LmCompatibilityLevel=5 (enviar solo NTLMv2, rechazar LM y NTLM). Verificar antes compatibilidad con NAS/equipos antiguos.'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegLsaPath 'LmCompatibilityLevel'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'Parcial' 'No configurado (por defecto 3: envia solo NTLMv2 pero acepta LM/NTLM)') }
            if ($v -ge 5) { return (New-CSWAuditOutcome 'Cumple' "Nivel $v") }
            if ($v -ge 3) { return (New-CSWAuditOutcome 'Parcial' "Nivel $v") }
            return (New-CSWAuditOutcome 'NoCumple' "Nivel $v (permite LM/NTLMv1)")
        }
    }
    @{ Id = 'ACC-19'; Categoria = 'Cuentas y autenticacion'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Opciones de seguridad)'
        Titulo = 'No almacenar hash LM'
        Recomendacion = 'Configurar Lsa\NoLMHash=1 y cambiar las contrasenas afectadas.'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegLsaPath 'NoLMHash'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'NoLMHash=0 (se almacenan hashes LM)') }
            return (New-CSWAuditOutcome 'Cumple' 'No se almacenan hashes LM')
        }
    }

    # ======================= UAC =======================
    @{ Id = 'UAC-01'; Categoria = 'Control de cuentas (UAC)'; Severidad = 'Critica'; Referencia = 'Microsoft Security Baseline (UAC)'
        Titulo = 'UAC habilitado (EnableLUA)'
        Recomendacion = 'Activar UAC: EnableLUA=1 (accion FixUac). Requiere reinicio.'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegUacPath 'EnableLUA'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'UAC DESACTIVADO (EnableLUA=0)') }
            return (New-CSWAuditOutcome 'Cumple' 'Activado')
        }
    }
    @{ Id = 'UAC-02'; Categoria = 'Control de cuentas (UAC)'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline (UAC)'
        Titulo = 'Solicitud de elevacion para administradores'
        Recomendacion = 'ConsentPromptBehaviorAdmin=5 (pedir consentimiento) o 2 (escritorio seguro). Nunca 0 (elevar sin preguntar).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegUacPath 'ConsentPromptBehaviorAdmin'
            if ($null -eq $v) { $v = 5 }
            $txt = @{ 0 = 'Elevar sin preguntar'; 1 = 'Pedir credenciales en escritorio seguro'; 2 = 'Pedir consentimiento en escritorio seguro'; 3 = 'Pedir credenciales'; 4 = 'Pedir consentimiento'; 5 = 'Pedir consentimiento para binarios no Windows' }
            $d = "Valor $v"
            if ($txt.ContainsKey([int]$v)) { $d = "{0} ({1})" -f $txt[[int]$v], $v }
            if ($v -eq 2 -or $v -eq 5 -or $v -eq 1) { return (New-CSWAuditOutcome 'Cumple' $d) }
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' $d) }
            return (New-CSWAuditOutcome 'Parcial' $d)
        }
    }
    @{ Id = 'UAC-03'; Categoria = 'Control de cuentas (UAC)'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (UAC)'
        Titulo = 'Solicitudes de UAC en escritorio seguro'
        Recomendacion = 'PromptOnSecureDesktop=1 (accion FixUac).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegUacPath 'PromptOnSecureDesktop'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'Deshabilitado (0)') }
            return (New-CSWAuditOutcome 'Cumple' 'Habilitado')
        }
    }
    @{ Id = 'UAC-04'; Categoria = 'Control de cuentas (UAC)'; Severidad = 'Media'; Referencia = 'CIS Benchmark (UAC)'
        Titulo = 'Modo de aprobacion de administrador para la cuenta integrada'
        Recomendacion = 'FilterAdministratorToken=1, o mantener deshabilitada la cuenta Administrador integrada.'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegUacPath 'FilterAdministratorToken'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Habilitado (1)') }
            $a = @(Get-CSWAuditLocalUser | Where-Object { $_.Sid -match '-500$' }) | Select-Object -First 1
            if ($a -and $a.Disabled) { return (New-CSWAuditOutcome 'Cumple' 'No habilitado, pero el Administrador integrado esta deshabilitado') }
            return (New-CSWAuditOutcome 'NoCumple' 'No habilitado y el Administrador integrado esta activo')
        }
    }

    # ======================= ANTIMALWARE =======================
    @{ Id = 'MAL-01'; Categoria = 'Proteccion antimalware'; Severidad = 'Critica'; Referencia = 'CIS Controls (Defensa antimalware)'
        Titulo = 'Antivirus activo'
        Recomendacion = 'Activar Microsoft Defender o un antivirus de terceros con licencia vigente.'
        Test = {
            $avs = $null
            try { $avs = @(Get-CSWAuditAvProduct) } catch { $avs = $null }
            if ($null -ne $avs) {
                $en = @($avs | Where-Object { $_.Enabled } | ForEach-Object { $_.Name } | Select-Object -Unique)
                if ($en.Count) { return (New-CSWAuditOutcome 'Cumple' ('Activo: ' + (Join-CSWAuditList $en))) }
                if ($avs.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Instalado pero inactivo: ' + (Join-CSWAuditList @($avs | ForEach-Object { $_.Name } | Select-Object -Unique)))) }
            }
            $d = Get-CSWAuditDefender
            if ($d.Status -and [bool](Get-CSWAuditProp $d.Status 'AntivirusEnabled')) { return (New-CSWAuditOutcome 'Cumple' 'Microsoft Defender activo') }
            return (New-CSWAuditOutcome 'NoCumple' 'No se detecta ningun antivirus activo')
        }
    }
    @{ Id = 'MAL-02'; Categoria = 'Proteccion antimalware'; Severidad = 'Critica'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Proteccion en tiempo real activa'
        Recomendacion = 'Activar la proteccion en tiempo real del antivirus.'
        Test = {
            $d = Get-CSWAuditDefender
            if ($d.Primary) {
                $rt = Get-CSWAuditProp $d.Status 'RealTimeProtectionEnabled'
                if ([bool]$rt) { return (New-CSWAuditOutcome 'Cumple' 'Defender: tiempo real activo') }
                return (New-CSWAuditOutcome 'NoCumple' 'Defender: tiempo real DESACTIVADO')
            }
            $avs = @()
            try { $avs = @(Get-CSWAuditAvProduct | Where-Object { -not $_.IsDefender }) } catch { $avs = @() }
            $on = @($avs | Where-Object { $_.Enabled } | ForEach-Object { $_.Name } | Select-Object -Unique)
            if ($on.Count) { return (New-CSWAuditOutcome 'Cumple' ('Gestionado por ' + (Join-CSWAuditList $on) + ' (activo)')) }
            return (New-CSWAuditOutcome 'NoCumple' 'Ningun motor con proteccion en tiempo real activa')
        }
    }
    @{ Id = 'MAL-03'; Categoria = 'Proteccion antimalware'; Severidad = 'Alta'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Firmas antivirus actualizadas (< 3 dias)'
        Recomendacion = 'Actualizar las firmas del antivirus y verificar que Windows Update / el servidor de actualizaciones del AV funciona.'
        Test = {
            $d = Get-CSWAuditDefender
            if ($d.Primary) {
                $age = Get-CSWAuditProp $d.Status 'AntivirusSignatureAge'
                $last = Get-CSWAuditProp $d.Status 'AntivirusSignatureLastUpdated'
                if ($null -eq $age) { return (New-CSWAuditOutcome 'SinDatos' 'Defender no informa la antiguedad de las firmas') }
                $age = [int]$age
                $txt = "Antiguedad: $age dias"
                if ($last) { $txt += (' (ultima: {0:dd\/MM\/yyyy})' -f [datetime]$last) }
                if ($age -le 2) { return (New-CSWAuditOutcome 'Cumple' $txt) }
                if ($age -le 7) { return (New-CSWAuditOutcome 'Parcial' $txt) }
                return (New-CSWAuditOutcome 'NoCumple' $txt)
            }
            $avs = @(Get-CSWAuditAvProduct | Where-Object { $_.Enabled -and -not $_.IsDefender })
            if (-not $avs.Count) { return (New-CSWAuditOutcome 'NoCumple' 'Sin antivirus activo') }
            $old = @($avs | Where-Object { -not $_.UpToDate } | ForEach-Object { $_.Name } | Select-Object -Unique)
            if ($old.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Firmas desactualizadas: ' + (Join-CSWAuditList $old))) }
            return (New-CSWAuditOutcome 'Cumple' ('Al dia segun el Centro de seguridad: ' + (Join-CSWAuditList @($avs | ForEach-Object { $_.Name } | Select-Object -Unique))))
        }
    }
    @{ Id = 'MAL-04'; Categoria = 'Proteccion antimalware'; Severidad = 'Media'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Proteccion basada en la nube (MAPS)'
        Recomendacion = 'Activar la proteccion en la nube de Defender (Set-MpPreference -MAPSReporting Advanced).'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            $v = Get-CSWAuditProp $d.Pref 'MAPSReporting'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de Defender') }
            if ([int]$v -ge 1) { return (New-CSWAuditOutcome 'Cumple' ("Activa (MAPSReporting={0})" -f [int]$v)) }
            return (New-CSWAuditOutcome 'NoCumple' 'Desactivada (MAPSReporting=0)')
        }
    }
    @{ Id = 'MAL-05'; Categoria = 'Proteccion antimalware'; Severidad = 'Alta'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Proteccion contra alteraciones (Tamper Protection)'
        Recomendacion = 'Activar "Proteccion contra alteraciones" en Seguridad de Windows > Proteccion antivirus.'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            $v = Get-CSWAuditProp $d.Status 'IsTamperProtected'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'Esta version de Defender no informa Tamper Protection') }
            if ([bool]$v) { return (New-CSWAuditOutcome 'Cumple' 'Activa') }
            return (New-CSWAuditOutcome 'NoCumple' 'Desactivada')
        }
    }
    @{ Id = 'MAL-06'; Categoria = 'Proteccion antimalware'; Severidad = 'Media'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Bloqueo de aplicaciones potencialmente no deseadas (PUA)'
        Recomendacion = 'Set-MpPreference -PUAProtection Enabled.'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            $v = Get-CSWAuditProp $d.Pref 'PUAProtection'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de Defender') }
            switch ([int]$v) {
                1 { return (New-CSWAuditOutcome 'Cumple' 'Bloqueo activo') }
                2 { return (New-CSWAuditOutcome 'Parcial' 'Solo auditoria') }
                default { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado') }
            }
        }
    }
    @{ Id = 'MAL-07'; Categoria = 'Proteccion antimalware'; Severidad = 'Media'; Referencia = 'Microsoft Defender (Reglas ASR)'
        Titulo = 'Reglas de reduccion de superficie de ataque (ASR)'
        Recomendacion = 'Configurar las reglas ASR estandar de Microsoft (primero en auditoria, luego en bloqueo) via GPO/Intune o Set-MpPreference.'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            if ($null -eq $d.Pref) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de Defender') }
            $ids = @(Get-CSWAuditProp $d.Pref 'AttackSurfaceReductionRules_Ids' | Where-Object { $_ })
            $acts = @(Get-CSWAuditProp $d.Pref 'AttackSurfaceReductionRules_Actions' | Where-Object { $null -ne $_ })
            $block = @($acts | Where-Object { [int]$_ -eq 1 }).Count
            $audit = @($acts | Where-Object { [int]$_ -eq 2 }).Count
            $warn = @($acts | Where-Object { [int]$_ -eq 6 }).Count
            $txt = '{0} reglas: {1} bloqueo, {2} auditoria, {3} advertencia' -f $ids.Count, $block, $audit, $warn
            if ($block -ge 5) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if (($block + $audit + $warn) -gt 0) { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'NoCumple' 'Ninguna regla ASR configurada')
        }
    }
    @{ Id = 'MAL-08'; Categoria = 'Proteccion antimalware'; Severidad = 'Baja'; Referencia = 'Microsoft Defender (Acceso controlado a carpetas)'
        Titulo = 'Acceso controlado a carpetas (anti-ransomware)'
        Recomendacion = 'Valorar activar "Acceso controlado a carpetas" (puede requerir permitir aplicaciones legitimas).'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            $v = Get-CSWAuditProp $d.Pref 'EnableControlledFolderAccess'
            if ($null -eq $v) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de Defender') }
            switch ([int]$v) {
                1 { return (New-CSWAuditOutcome 'Cumple' 'Activado') }
                0 { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado') }
                default { return (New-CSWAuditOutcome 'Parcial' ("Modo auditoria/parcial ({0})" -f [int]$v)) }
            }
        }
    }
    @{ Id = 'MAL-09'; Categoria = 'Proteccion antimalware'; Severidad = 'Alta'; Referencia = 'Microsoft Defender - buenas practicas'
        Titulo = 'Exclusiones de Defender no peligrosas'
        Recomendacion = 'Eliminar exclusiones de unidades completas, carpetas temporales/usuario, extensiones ejecutables o interpretes (Remove-MpPreference).'
        Test = {
            $na = Assert-CSWAuditDefenderPrimary; if ($na) { return $na }
            $d = Get-CSWAuditDefender
            if ($null -eq $d.Pref) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de Defender') }
            $paths = @(Get-CSWAuditProp $d.Pref 'ExclusionPath' | Where-Object { $_ })
            $exts = @(Get-CSWAuditProp $d.Pref 'ExclusionExtension' | Where-Object { $_ })
            $procs = @(Get-CSWAuditProp $d.Pref 'ExclusionProcess' | Where-Object { $_ })
            $all = @($paths + $exts + $procs)
            if (@($all | Where-Object { [string]$_ -match '^N/A' }).Count) { throw 'Requiere ejecutar como administrador (ver exclusiones de Defender)' }
            $sus = @()
            foreach ($p in $paths) {
                $s = [string]$p
                if ($s -match '^[A-Za-z]:\\?$' -or $s -match '(?i)%TEMP%|%TMP%|\\Temp\\?$|\\AppData\\Local\\Temp|^[A-Za-z]:\\Users\\?$|\\Downloads\\?$|\\Descargas\\?$|^[A-Za-z]:\\Windows\\?$|^[A-Za-z]:\\Program Files( \(x86\))?\\?$|^[A-Za-z]:\\ProgramData\\?$|\\Users\\Public|^\*') { $sus += $s }
            }
            foreach ($e in $exts) { if ([string]$e -match '(?i)^\.?(exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|scr|msi|hta|com|lnk|wsf)$') { $sus += ('ext ' + [string]$e) } }
            foreach ($p in $procs) { if ([string]$p -match '(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec)(\.exe)?$') { $sus += ('proceso ' + [string]$p) } }
            if ($sus.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Exclusiones peligrosas: ' + (Join-CSWAuditList $sus))) }
            if ($all.Count) { return (New-CSWAuditOutcome 'Parcial' ('{0} exclusiones a revisar: {1}' -f $all.Count, (Join-CSWAuditList $all 4))) }
            return (New-CSWAuditOutcome 'Cumple' 'Sin exclusiones')
        }
    }

    # ======================= FIREWALL =======================
    @{ Id = 'FW-01'; Categoria = 'Firewall'; Severidad = 'Critica'; Referencia = 'CIS Benchmark (Firewall de Windows)'
        Titulo = 'Firewall activo en los 3 perfiles (Dominio, Privado, Publico)'
        Recomendacion = 'Activar el firewall en todos los perfiles (accion FixFirewallProfiles).'
        Test = {
            $p = @(Get-CSWAuditFwProfile)
            if (-not $p.Count) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudieron leer los perfiles') }
            $off = @($p | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
            if ($off.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Activo en todos los perfiles') }
            return (New-CSWAuditOutcome 'NoCumple' ('Desactivado en: ' + ($off -join ', ')))
        }
    }
    @{ Id = 'FW-02'; Categoria = 'Firewall'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Firewall de Windows)'
        Titulo = 'Accion de entrada por defecto: Bloquear'
        Recomendacion = 'Set-NetFirewallProfile -All -DefaultInboundAction Block.'
        Test = {
            $p = @(Get-CSWAuditFwProfile)
            if (-not $p.Count) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudieron leer los perfiles') }
            $allow = @($p | Where-Object { $_.Inbound -eq 'Allow' } | ForEach-Object { $_.Name })
            if ($allow.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Bloquear en todos los perfiles') }
            return (New-CSWAuditOutcome 'NoCumple' ('Permite entrada por defecto en: ' + ($allow -join ', ')))
        }
    }
    @{ Id = 'FW-03'; Categoria = 'Firewall'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Firewall de Windows)'
        Titulo = 'Reglas de entrada abiertas a cualquier origen en perfil Publico'
        Recomendacion = 'Revisar reglas de terceros que permiten entrada desde cualquier IP en redes publicas y restringirlas a Privado o a IPs concretas.'
        Test = {
            $rules = @(Get-CSWAuditFwRule | Where-Object { ($_.Profiles -band 4) -ne 0 -and ($_.Remote -eq '*' -or $_.Remote -eq '') -and -not $_.Grouping.StartsWith('@') })
            if ($rules.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Ninguna regla de terceros abierta a Any en Publico') }
            $names = @($rules | ForEach-Object { $_.Name } | Select-Object -Unique)
            return (New-CSWAuditOutcome 'Parcial' ('{0} reglas de {1} programas/apps (revisar): {2}' -f $rules.Count, $names.Count, (Join-CSWAuditList $names 5)))
        }
    }
    @{ Id = 'FW-04'; Categoria = 'Firewall'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Firewall de Windows)'
        Titulo = 'Registro de conexiones bloqueadas del firewall'
        Recomendacion = 'Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384.'
        Test = {
            $p = @(Get-CSWAuditFwProfile)
            if (-not $p.Count -or -not $p[0].LogBlocked) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo leer la configuracion de registro') }
            $on = @($p | Where-Object { $_.LogBlocked -eq 'True' } | ForEach-Object { $_.Name })
            if ($on.Count -eq $p.Count) { return (New-CSWAuditOutcome 'Cumple' 'Habilitado en todos los perfiles') }
            if ($on.Count) { return (New-CSWAuditOutcome 'Parcial' ('Solo en: ' + ($on -join ', '))) }
            return (New-CSWAuditOutcome 'NoCumple' 'Deshabilitado')
        }
    }

    # ======================= ACTUALIZACIONES =======================
    @{ Id = 'UPD-01'; Categoria = 'Actualizaciones'; Severidad = 'Alta'; Referencia = 'CIS Controls (Gestion de vulnerabilidades)'
        Titulo = 'Ultimo parche de Windows instalado hace < 30 dias'
        Recomendacion = 'Ejecutar Windows Update e instalar la ultima actualizacion acumulativa.'
        Test = {
            $dates = @()
            try {
                foreach ($q in @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop)) {
                    $d = ConvertTo-CSWAuditDate (Get-CSWAuditProp $q 'InstalledOn')
                    if ($d) { $dates += $d }
                }
            }
            catch { }
            try {
                $sess = New-Object -ComObject Microsoft.Update.Session
                $srch = $sess.CreateUpdateSearcher()
                $n = [int]$srch.GetTotalHistoryCount()
                if ($n -gt 0) {
                    foreach ($h in $srch.QueryHistory(0, [math]::Min($n, 150))) {
                        $t = [string]$h.Title
                        if ([int]$h.ResultCode -eq 2 -and [int]$h.Operation -eq 1 -and $t -match '(?i)cumulative|acumulativa|security update|seguridad' -and $t -notmatch '(?i)Defender|Intelligence|inteligencia|NET Framework') {
                            $dates += ([datetime]$h.Date).ToLocalTime()
                        }
                    }
                }
            }
            catch { }
            $dates = @($dates | Where-Object { $_ -le (Get-Date).AddDays(1) })
            if (-not $dates.Count) { return (New-CSWAuditOutcome 'SinDatos' 'No se encontro historial de actualizaciones') }
            $last = ($dates | Sort-Object -Descending | Select-Object -First 1)
            $age = [int]((Get-Date) - $last).TotalDays
            $txt = 'Ultimo parche: {0:dd\/MM\/yyyy} (hace {1} dias)' -f $last, $age
            if ($age -lt 30) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if ($age -lt 60) { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'NoCumple' $txt)
        }
    }
    @{ Id = 'UPD-02'; Categoria = 'Actualizaciones'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline'
        Titulo = 'Servicio Windows Update no deshabilitado'
        Recomendacion = 'Restablecer el servicio wuauserv a inicio Manual (desencadenado): sc config wuauserv start= demand.'
        Test = {
            $s = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
            if (-not $s) { return (New-CSWAuditOutcome 'NoCumple' 'Servicio wuauserv no encontrado') }
            $start = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' 'Start'
            if ($start -eq 4) { return (New-CSWAuditOutcome 'NoCumple' 'Deshabilitado') }
            return (New-CSWAuditOutcome 'Cumple' ('Estado: {0}' -f [string]$s.Status))
        }
    }
    @{ Id = 'UPD-03'; Categoria = 'Actualizaciones'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline'
        Titulo = 'Actualizaciones no pausadas ni bloqueadas por politica'
        Recomendacion = 'Reanudar Windows Update (Configuracion > Windows Update) y eliminar la politica NoAutoUpdate si existe.'
        Test = {
            $issues = @()
            $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            foreach ($n in 'PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime') {
                $v = Get-CSWAuditReg $ux $n
                if ($null -eq $v) { continue }
                $d = [datetime]::MinValue
                if ([datetime]::TryParse([string]$v, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
                    if ($d -gt (Get-Date).ToUniversalTime()) { $issues += ('{0} hasta {1:dd\/MM\/yyyy}' -f $n, $d) }
                }
            }
            $au = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
            if ($au -eq 1) { $issues += 'Politica NoAutoUpdate=1' }
            if ($issues.Count) { return (New-CSWAuditOutcome 'NoCumple' ($issues -join '; ')) }
            return (New-CSWAuditOutcome 'Cumple' 'No pausado')
        }
    }
    @{ Id = 'UPD-04'; Categoria = 'Actualizaciones'; Severidad = 'Alta'; Referencia = 'Ciclo de vida de Microsoft'
        Titulo = 'Version de Windows con soporte'
        Recomendacion = 'Actualizar a una version de Windows 11 con soporte (24H2 o posterior) o a una edicion LTSC vigente.'
        Test = {
            $os = Get-CSWAuditOsInfo
            $b = $os.Build
            $txt = '{0} {1} (build {2}.{3})' -f $os.Caption, $os.DisplayVersion, $b, $os.Ubr
            if ($os.ProductType -ne 1) { return (New-CSWAuditOutcome 'NoAplica' ($txt + ' - Windows Server: verificar ciclo de vida manualmente')) }
            $ltsc = ($os.Edition -match '(?i)EnterpriseS|IoTEnterpriseS')
            if ($b -ge 26100) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if ($b -ge 22000) { return (New-CSWAuditOutcome 'Parcial' ($txt + ' - version de Windows 11 anterior a 24H2, fuera del ciclo de soporte conocido para Home/Pro')) }
            if ($ltsc -and $b -ge 17763) { return (New-CSWAuditOutcome 'Cumple' ($txt + ' - edicion LTSC')) }
            if ($b -eq 19045) { return (New-CSWAuditOutcome 'Parcial' ($txt + ' - Windows 10 sin soporte general (solo con ESU)')) }
            return (New-CSWAuditOutcome 'NoCumple' ($txt + ' - version sin soporte'))
        }
    }

    # ======================= CIFRADO Y ARRANQUE =======================
    @{ Id = 'CIF-01'; Categoria = 'Cifrado y arranque'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (BitLocker)'
        Titulo = 'BitLocker activo en la unidad del sistema'
        Recomendacion = 'Activar BitLocker (o Cifrado de dispositivo) en la unidad del sistema y guardar la clave de recuperacion en lugar seguro.'
        Test = {
            $drv = $env:SystemDrive
            if ((Test-CSWAuditIsAdmin) -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
                $v = Get-BitLockerVolume -MountPoint $drv -ErrorAction Stop
                $ps = [string]$v.ProtectionStatus; $vs = [string]$v.VolumeStatus
                $txt = 'Proteccion: {0}; Estado: {1}; Cifrado: {2}%' -f $ps, $vs, $v.EncryptionPercentage
                if ($ps -eq 'On') { return (New-CSWAuditOutcome 'Cumple' $txt) }
                if ($vs -ne 'FullyDecrypted') { return (New-CSWAuditOutcome 'Parcial' $txt) }
                return (New-CSWAuditOutcome 'NoCumple' $txt)
            }
            $sh = New-Object -ComObject Shell.Application
            $val = $sh.NameSpace($drv + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
            if ($null -eq $val) { throw 'Requiere ejecutar como administrador (estado de BitLocker)' }
            switch ([int]$val) {
                1 { return (New-CSWAuditOutcome 'Cumple' 'Proteccion activada') }
                3 { return (New-CSWAuditOutcome 'Parcial' 'Cifrando') }
                5 { return (New-CSWAuditOutcome 'Parcial' 'Proteccion suspendida') }
                4 { return (New-CSWAuditOutcome 'NoCumple' 'Descifrando') }
                default { return (New-CSWAuditOutcome 'NoCumple' ("Sin proteccion (codigo {0})" -f [int]$val)) }
            }
        }
    }
    @{ Id = 'CIF-02'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft (requisitos de Windows 11)'
        Titulo = 'TPM presente y listo'
        Recomendacion = 'Habilitar el TPM (fTPM/PTT) en la BIOS/UEFI e inicializarlo (tpm.msc).'
        Test = {
            if ((Test-CSWAuditIsAdmin) -and (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
                $t = Get-Tpm -ErrorAction Stop
                $ver = ''
                try {
                    $w = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
                    $ver = ([string]$w.SpecVersion).Split(',')[0].Trim()
                }
                catch { }
                $txt = 'Presente: {0}; Listo: {1}' -f $t.TpmPresent, $t.TpmReady
                if ($ver) { $txt += "; Version $ver" }
                if (-not $t.TpmPresent) { return (New-CSWAuditOutcome 'NoCumple' 'No se detecta TPM') }
                if ($t.TpmReady -and ($ver -eq '' -or $ver -like '2*')) { return (New-CSWAuditOutcome 'Cumple' $txt) }
                return (New-CSWAuditOutcome 'Parcial' $txt)
            }
            $dev = @(Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction Stop | Where-Object { [string]$_.PNPDeviceID -match '(?i)^ACPI\\(MSFT0101|PNP0C31)' -or [string]$_.Name -match '(?i)TPM|Trusted Platform' })
            if ($dev.Count) { return (New-CSWAuditOutcome 'Cumple' ([string]$dev[0].Name + ' (estado "listo" verificable solo como administrador)')) }
            return (New-CSWAuditOutcome 'NoCumple' 'No se detecta dispositivo TPM')
        }
    }
    @{ Id = 'CIF-03'; Categoria = 'Cifrado y arranque'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline'
        Titulo = 'Arranque seguro (Secure Boot) activo'
        Recomendacion = 'Activar Secure Boot en la configuracion UEFI del equipo.'
        Test = {
            $v = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Activo') }
            $fw = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType'
            if ($fw -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'No disponible: el equipo arranca en BIOS legado') }
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado') }
            return (New-CSWAuditOutcome 'NoCumple' 'No se pudo confirmar (sin datos de Secure Boot)')
        }
    }
    @{ Id = 'CIF-04'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft (requisitos de Windows 11)'
        Titulo = 'Firmware en modo UEFI (no BIOS legado)'
        Recomendacion = 'Convertir el disco a GPT (mbr2gpt) y arrancar en modo UEFI.'
        Test = {
            $fw = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType'
            if ($fw -eq 2) { return (New-CSWAuditOutcome 'Cumple' 'UEFI') }
            if ($fw -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'BIOS legado') }
            $e = [string]$env:firmware_type
            if ($e -eq 'UEFI') { return (New-CSWAuditOutcome 'Cumple' 'UEFI') }
            if ($e -eq 'Legacy') { return (New-CSWAuditOutcome 'NoCumple' 'BIOS legado') }
            return (New-CSWAuditOutcome 'SinDatos' 'Tipo de firmware no determinado')
        }
    }
    @{ Id = 'CIF-05'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (VBS)'
        Titulo = 'Seguridad basada en virtualizacion (VBS) en ejecucion'
        Recomendacion = 'Activar virtualizacion en la UEFI y la Integridad de memoria / VBS en Seguridad de Windows.'
        Test = {
            $dg = Get-CSWAuditDeviceGuard
            switch ($dg.Vbs) {
                2 { return (New-CSWAuditOutcome 'Cumple' 'En ejecucion') }
                1 { return (New-CSWAuditOutcome 'Parcial' 'Configurada pero no en ejecucion') }
                default { return (New-CSWAuditOutcome 'NoCumple' 'No habilitada') }
            }
        }
    }
    @{ Id = 'CIF-06'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (HVCI)'
        Titulo = 'Integridad de memoria (HVCI)'
        Recomendacion = 'Activar Seguridad de Windows > Seguridad del dispositivo > Aislamiento del nucleo > Integridad de memoria (revisar drivers incompatibles).'
        Test = {
            $dg = Get-CSWAuditDeviceGuard
            if ($dg.Running -contains 2) { return (New-CSWAuditOutcome 'Cumple' 'En ejecucion') }
            if ($dg.Configured -contains 2) { return (New-CSWAuditOutcome 'Parcial' 'Configurada, pendiente de reinicio o bloqueada') }
            return (New-CSWAuditOutcome 'NoCumple' 'Desactivada')
        }
    }
    @{ Id = 'CIF-07'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (Credential Guard)'
        Titulo = 'Credential Guard'
        Recomendacion = 'Activar Credential Guard por GPO/Intune en equipos corporativos (Enterprise/Education).'
        Test = {
            $os = Get-CSWAuditOsInfo
            if ($os.Edition -match '(?i)^Core') { return (New-CSWAuditOutcome 'NoAplica' 'No disponible en Windows Home') }
            $dg = Get-CSWAuditDeviceGuard
            if ($dg.Running -contains 1) { return (New-CSWAuditOutcome 'Cumple' 'En ejecucion') }
            if (-not $os.PartOfDomain -and -not $os.AzureAdJoined) { return (New-CSWAuditOutcome 'NoAplica' 'Equipo no corporativo (sin dominio ni Entra ID)') }
            if ($dg.Configured -contains 1) { return (New-CSWAuditOutcome 'Parcial' 'Configurado, no en ejecucion') }
            return (New-CSWAuditOutcome 'NoCumple' 'Desactivado')
        }
    }
    @{ Id = 'CIF-08'; Categoria = 'Cifrado y arranque'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (LSA)'
        Titulo = 'Proteccion de LSA (RunAsPPL)'
        Recomendacion = 'Activar "Proteccion de la autoridad de seguridad local" en Seguridad de Windows o Lsa\RunAsPPL=1 (verificar drivers/plugins LSA de terceros).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegLsaPath 'RunAsPPL'
            $vb = Get-CSWAuditRegInt $script:AuditRegLsaPath 'RunAsPPLBoot'
            if ($v -eq 1 -or $v -eq 2 -or $vb -eq 1 -or $vb -eq 2) { return (New-CSWAuditOutcome 'Cumple' ("RunAsPPL={0}" -f $v)) }
            if ($null -eq $v) {
                $os = Get-CSWAuditOsInfo
                if ($os.Build -ge 22621) { return (New-CSWAuditOutcome 'Parcial' 'No configurado explicitamente (en Windows 11 22H2+ puede estar activo por defecto en instalaciones nuevas)') }
                return (New-CSWAuditOutcome 'NoCumple' 'No configurado')
            }
            return (New-CSWAuditOutcome 'NoCumple' ("Desactivado (RunAsPPL={0})" -f $v))
        }
    }
    @{ Id = 'CIF-09'; Categoria = 'Cifrado y arranque'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline (WDigest)'
        Titulo = 'WDigest sin credenciales en texto claro'
        Recomendacion = 'Configurar WDigest\UseLogonCredential=0 (accion FixWDigest).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegWDigest 'UseLogonCredential'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'UseLogonCredential=1 (contrasenas en memoria en texto claro)') }
            if ($null -eq $v) { return (New-CSWAuditOutcome 'Cumple' 'No configurado (deshabilitado por defecto)') }
            return (New-CSWAuditOutcome 'Cumple' "UseLogonCredential=$v")
        }
    }

    # ======================= RED Y PROTOCOLOS =======================
    @{ Id = 'NET-01'; Categoria = 'Red y protocolos'; Severidad = 'Alta'; Referencia = 'Microsoft Security Baseline (SMBv1)'
        Titulo = 'SMBv1 deshabilitado'
        Recomendacion = 'Deshabilitar SMBv1 (accion FixSmbV1). Requiere reinicio.'
        Test = {
            $parts = @(); $bad = $false; $known = $false
            $f = $null
            try { $f = Get-CSWAuditFeature 'SMB1Protocol'; $known = $true } catch { }
            if ($null -ne $f) {
                if ($f -eq 1) { $parts += 'Caracteristica SMB1Protocol instalada'; $bad = $true } else { $parts += 'Caracteristica SMB1 no instalada' }
            }
            $srv = $null
            if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
                try { $srv = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol; $known = $true } catch { $srv = $null }
            }
            if ($null -eq $srv) {
                $r = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
                if ($null -ne $r) { $srv = ($r -ne 0); $known = $true }
            }
            if ($srv -eq $true) { $parts += 'Servidor SMB1 habilitado'; $bad = $true } elseif ($srv -eq $false) { $parts += 'Servidor SMB1 deshabilitado' }
            if (-not $known) { return (New-CSWAuditOutcome 'SinDatos' 'No se pudo determinar el estado de SMBv1') }
            if ($bad) { return (New-CSWAuditOutcome 'NoCumple' ($parts -join '; ')) }
            return (New-CSWAuditOutcome 'Cumple' ($parts -join '; '))
        }
    }
    @{ Id = 'NET-02'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Firma SMB)'
        Titulo = 'Firma SMB obligatoria (servidor y cliente)'
        Recomendacion = 'Requerir firma SMB: Set-SmbServerConfiguration -RequireSecuritySignature $true y Set-SmbClientConfiguration -RequireSecuritySignature $true.'
        Test = {
            $srv = $null; $cli = $null
            try { $srv = [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { $srv = $null }
            try { $cli = [bool](Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { $cli = $null }
            if ($null -eq $srv) { $srv = ((Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') -eq 1) }
            if ($null -eq $cli) { $cli = ((Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') -eq 1) }
            $txt = 'Servidor: {0}; Cliente: {1}' -f $(if ($srv) { 'obligatoria' } else { 'no obligatoria' }), $(if ($cli) { 'obligatoria' } else { 'no obligatoria' })
            if ($srv -and $cli) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            if ($srv -or $cli) { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'NoCumple' $txt)
        }
    }
    @{ Id = 'NET-03'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'CIS Benchmark (DNS Client)'
        Titulo = 'LLMNR deshabilitado'
        Recomendacion = 'Directiva "Desactivar resolucion de nombres de multidifusion" (EnableMulticast=0) - accion FixLlmnr.'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegDnsClient 'EnableMulticast'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado por politica') }
            return (New-CSWAuditOutcome 'NoCumple' 'Habilitado (por defecto)')
        }
    }
    @{ Id = 'NET-04'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'CIS Benchmark (NetBIOS)'
        Titulo = 'NetBIOS sobre TCP/IP deshabilitado en los adaptadores'
        Recomendacion = 'Deshabilitar NetBIOS sobre TCP/IP en cada adaptador (Propiedades IPv4 > Avanzado > WINS) salvo que se necesite en la red local.'
        Test = {
            $ad = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
            if (-not $ad.Count) { return (New-CSWAuditOutcome 'NoAplica' 'Sin adaptadores IP activos') }
            $on = @($ad | Where-Object { [int](Get-CSWAuditProp $_ 'TcpipNetbiosOptions') -ne 2 } | ForEach-Object { [string]$_.Description })
            if ($on.Count -eq 0) { return (New-CSWAuditOutcome 'Cumple' ('Deshabilitado en {0} adaptadores' -f $ad.Count)) }
            return (New-CSWAuditOutcome 'Parcial' ('Activo en {0}/{1}: {2}' -f $on.Count, $ad.Count, (Join-CSWAuditList $on 3)))
        }
    }
    @{ Id = 'NET-05'; Categoria = 'Red y protocolos'; Severidad = 'Baja'; Referencia = 'Microsoft (WPAD)'
        Titulo = 'Deteccion automatica de proxy (WPAD) deshabilitada'
        Recomendacion = 'Si no se usa proxy automatico: WinHttp\DisableWpad=1 y desactivar "Detectar la configuracion automaticamente".'
        Test = {
            $dis = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad'
            $svc = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' 'Start'
            $auto = Get-CSWAuditRegInt 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoDetect'
            if ($dis -eq 1 -or $svc -eq 4) { return (New-CSWAuditOutcome 'Cumple' 'WPAD deshabilitado') }
            if ($auto -eq 0) { return (New-CSWAuditOutcome 'Parcial' 'Autodeteccion desactivada para el usuario; WPAD de sistema activo') }
            return (New-CSWAuditOutcome 'Parcial' 'WPAD activo (por defecto)')
        }
    }
    @{ Id = 'NET-06'; Categoria = 'Red y protocolos'; Severidad = 'Alta'; Referencia = 'CIS Benchmark (Servicios de Escritorio remoto)'
        Titulo = 'Escritorio remoto con autenticacion a nivel de red (NLA)'
        Recomendacion = 'Si RDP esta habilitado, exigir NLA (UserAuthentication=1); deshabilitar RDP si no se usa.'
        Test = {
            $r = Get-CSWAuditRdp
            if (-not $r.Enabled) { return (New-CSWAuditOutcome 'NoAplica' 'Escritorio remoto deshabilitado') }
            $txt = 'RDP habilitado en puerto {0}' -f $r.Port
            if ($r.Nla) { return (New-CSWAuditOutcome 'Cumple' ($txt + ', NLA activa')) }
            return (New-CSWAuditOutcome 'NoCumple' ($txt + ', SIN NLA'))
        }
    }
    @{ Id = 'NET-07'; Categoria = 'Red y protocolos'; Severidad = 'Alta'; Referencia = 'CIS Controls (Exposicion de servicios)'
        Titulo = 'Escritorio remoto no expuesto en redes publicas'
        Recomendacion = 'Restringir las reglas de Escritorio remoto al perfil Privado/Dominio o a IPs concretas; usar VPN para acceso externo.'
        Test = {
            $r = Get-CSWAuditRdp
            if (-not $r.Enabled) { return (New-CSWAuditOutcome 'Cumple' 'Escritorio remoto deshabilitado') }
            $hit = @(Get-CSWAuditPublicExposure -Port $r.Port)
            if ($hit.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Puerto {0} abierto a cualquier origen en Publico: {1}' -f $r.Port, (Join-CSWAuditList @($hit | Select-Object -Unique) 3))) }
            return (New-CSWAuditOutcome 'Cumple' ('RDP habilitado (puerto {0}) pero no abierto en perfil Publico' -f $r.Port))
        }
    }
    @{ Id = 'NET-08'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Servicios del sistema)'
        Titulo = 'Registro remoto (RemoteRegistry) deshabilitado'
        Recomendacion = 'Deshabilitar el servicio Registro remoto si no se usa: Set-Service RemoteRegistry -StartupType Disabled.'
        Test = {
            $s = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
            if (-not $s) { return (New-CSWAuditOutcome 'Cumple' 'Servicio no presente') }
            $start = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' 'Start'
            $st = [string]$s.Status
            if ($st -eq 'Running') { return (New-CSWAuditOutcome 'NoCumple' 'En ejecucion') }
            if ($start -eq 4) { return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado') }
            return (New-CSWAuditOutcome 'Parcial' ('Detenido pero no deshabilitado (inicio={0})' -f $start))
        }
    }
    @{ Id = 'NET-09'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'CIS Benchmark (WinRM)'
        Titulo = 'WinRM no accesible desde redes publicas'
        Recomendacion = 'Si no se administra remotamente, detener WinRM; si se usa, limitar las reglas 5985/5986 a la subred local o IPs de gestion.'
        Test = {
            $s = Get-Service -Name WinRM -ErrorAction SilentlyContinue
            if (-not $s -or [string]$s.Status -ne 'Running') { return (New-CSWAuditOutcome 'Cumple' 'Servicio WinRM detenido') }
            $hit = @(Get-CSWAuditPublicExposure -Port 5985) + @(Get-CSWAuditPublicExposure -Port 5986)
            if ($hit.Count) { return (New-CSWAuditOutcome 'NoCumple' ('WinRM en ejecucion y abierto en Publico: ' + (Join-CSWAuditList @($hit | Select-Object -Unique) 3))) }
            return (New-CSWAuditOutcome 'Cumple' 'WinRM en ejecucion, no expuesto a cualquier origen en Publico')
        }
    }
    @{ Id = 'NET-10'; Categoria = 'Red y protocolos'; Severidad = 'Alta'; Referencia = 'CIS Controls (Control de acceso a datos)'
        Titulo = 'Carpetas compartidas sin permisos para Todos (Everyone)'
        Recomendacion = 'Quitar el grupo Todos de los permisos de recurso compartido y conceder acceso solo a usuarios/grupos concretos.'
        Test = {
            if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { return (New-CSWAuditOutcome 'SinDatos' 'Cmdlets SMB no disponibles') }
            $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not [bool]$_.Special -and [string]$_.Name -notmatch '\$$' })
            $auto = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
            $admTxt = 'compartidos administrativos activos (por defecto)'
            if ($auto -eq 0) { $admTxt = 'compartidos administrativos desactivados' }
            if (-not $shares.Count) { return (New-CSWAuditOutcome 'Cumple' ('Sin carpetas compartidas; ' + $admTxt)) }
            $ev = Get-CSWAuditSidName 'S-1-1-0'
            $write = @(); $read = @()
            foreach ($s in $shares) {
                $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop | Where-Object { ([string]$_.AccountName -eq $ev -or [string]$_.AccountName -eq 'Everyone') -and [string]$_.AccessControlType -eq 'Allow' })
                foreach ($a in $acc) {
                    if ([string]$a.AccessRight -eq 'Read') { $read += $s.Name } else { $write += ('{0} ({1})' -f $s.Name, [string]$a.AccessRight) }
                }
            }
            $names = @($shares | ForEach-Object { $_.Name })
            if ($write.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Todos con escritura: ' + (Join-CSWAuditList $write))) }
            if ($read.Count) { return (New-CSWAuditOutcome 'Parcial' ('Todos con lectura: ' + (Join-CSWAuditList $read))) }
            return (New-CSWAuditOutcome 'Cumple' ('Compartidos: {0}; {1}' -f (Join-CSWAuditList $names), $admTxt))
        }
    }
    @{ Id = 'NET-11'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (PowerShell v2)'
        Titulo = 'Windows PowerShell 2.0 deshabilitado'
        Recomendacion = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (evita eludir el registro de PowerShell).'
        Test = {
            $a = Get-CSWAuditFeature 'MicrosoftWindowsPowerShellV2Root'
            $b = Get-CSWAuditFeature 'MicrosoftWindowsPowerShellV2'
            if ($a -eq 1 -or $b -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'PowerShell 2.0 instalado') }
            if ($null -eq $a -and $null -eq $b) { return (New-CSWAuditOutcome 'Cumple' 'No disponible en esta version de Windows') }
            return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado')
        }
    }
    @{ Id = 'NET-12'; Categoria = 'Red y protocolos'; Severidad = 'Media'; Referencia = 'Microsoft (SCHANNEL / TLS)'
        Titulo = 'TLS 1.0 y 1.1 deshabilitados (SCHANNEL)'
        Recomendacion = 'Deshabilitar TLS 1.0/1.1 en SCHANNEL (Server y Client: Enabled=0, DisabledByDefault=1) tras verificar compatibilidad de aplicaciones.'
        Test = {
            $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
            $en = @(); $dis = 0; $unset = 0
            foreach ($p in 'TLS 1.0', 'TLS 1.1') {
                foreach ($side in 'Server', 'Client') {
                    $v = Get-CSWAuditRegInt "$base\$p\$side" 'Enabled'
                    if ($null -eq $v) { $unset++ } elseif ($v -eq 0) { $dis++ } else { $en += "$p $side" }
                }
            }
            if ($en.Count) { return (New-CSWAuditOutcome 'NoCumple' ('Habilitado explicitamente: ' + ($en -join ', '))) }
            if ($unset -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Deshabilitados explicitamente') }
            $os = Get-CSWAuditOsInfo
            return (New-CSWAuditOutcome 'Parcial' ('No configurado explicitamente ({0} de 4 valores); se aplica el valor por defecto de la build {1}' -f $unset, $os.Build))
        }
    }

    # ======================= REGISTRO Y AUDITORIA =======================
    @{ Id = 'LOG-01'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de inicio/cierre de sesion'
        Recomendacion = 'Auditar Inicio de sesion (correcto y error) y Cierre de sesion (correcto) - accion FixAuditPolicy.'
        Test = { Test-CSWAuditSubcategory @{ Logon = 3; Logoff = 1 } }
    }
    @{ Id = 'LOG-02'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de bloqueo de cuenta'
        Recomendacion = 'Auditar Bloqueo de cuenta (error como minimo) - accion FixAuditPolicy.'
        Test = { Test-CSWAuditSubcategory @{ AccountLockout = 2 } }
    }
    @{ Id = 'LOG-03'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de creacion de procesos'
        Recomendacion = 'Auditar Creacion de procesos (correcto) - accion FixAuditPolicy.'
        Test = { Test-CSWAuditSubcategory @{ ProcessCreation = 1 } }
    }
    @{ Id = 'LOG-04'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de administracion de grupos de seguridad'
        Recomendacion = 'Auditar Administracion de grupos de seguridad (correcto) - accion FixAuditPolicy.'
        Test = { Test-CSWAuditSubcategory @{ SecurityGroupManagement = 1 } }
    }
    @{ Id = 'LOG-05'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de validacion de credenciales'
        Recomendacion = 'auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'
        Test = { Test-CSWAuditSubcategory @{ CredentialValidation = 3 } }
    }
    @{ Id = 'LOG-06'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de administracion de cuentas de usuario'
        Recomendacion = 'auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'
        Test = { Test-CSWAuditSubcategory @{ UserAccountManagement = 3 } }
    }
    @{ Id = 'LOG-07'; Categoria = 'Registro y auditoria'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Auditoria avanzada)'
        Titulo = 'Auditoria de cambios en la directiva de auditoria'
        Recomendacion = 'auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable'
        Test = { Test-CSWAuditSubcategory @{ AuditPolicyChange = 1 } }
    }
    @{ Id = 'LOG-08'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'CIS Benchmark (Registro de eventos)'
        Titulo = 'Tamano del registro de Seguridad >= 192 MB'
        Recomendacion = 'Ampliar el registro de Seguridad a 196608 KB o mas: wevtutil sl Security /ms:201326592'
        Test = {
            $kb = $null; $src = ''
            $pol = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize'
            if ($null -ne $pol) { $kb = $pol; $src = ' (politica)' }
            else {
                $b = Get-CSWAuditRegInt 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize'
                if ($null -ne $b) { $kb = [long]($b / 1024) }
                else {
                    try { $kb = [long]((Get-WinEvent -ListLog Security -ErrorAction Stop).MaximumSizeInBytes / 1024) } catch { $kb = $null }
                }
            }
            if ($null -eq $kb) { throw 'Requiere ejecutar como administrador (tamano del registro de Seguridad)' }
            $txt = '{0:N0} KB{1}' -f $kb, $src
            if ($kb -ge 196608) { return (New-CSWAuditOutcome 'Cumple' $txt) }
            return (New-CSWAuditOutcome 'Parcial' $txt)
        }
    }
    @{ Id = 'LOG-09'; Categoria = 'Registro y auditoria'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (PowerShell)'
        Titulo = 'Registro de bloques de script de PowerShell'
        Recomendacion = 'Habilitar Script Block Logging (accion FixPowerShellLogging).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegSbl 'EnableScriptBlockLogging'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Habilitado') }
            return (New-CSWAuditOutcome 'NoCumple' 'No habilitado')
        }
    }
    @{ Id = 'LOG-10'; Categoria = 'Registro y auditoria'; Severidad = 'Baja'; Referencia = 'CIS Benchmark (Auditoria de procesos)'
        Titulo = 'Linea de comandos incluida en eventos 4688'
        Recomendacion = 'Habilitar "Incluir linea de comandos en eventos de creacion de procesos" (ProcessCreationIncludeCmdLine_Enabled=1).'
        Test = {
            $v = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Habilitado') }
            return (New-CSWAuditOutcome 'NoCumple' 'No habilitado')
        }
    }

    # ======================= HARDENING =======================
    @{ Id = 'HAR-01'; Categoria = 'Hardening del sistema'; Severidad = 'Media'; Referencia = 'CIS Benchmark (AutoPlay)'
        Titulo = 'AutoRun/AutoPlay deshabilitado en todas las unidades'
        Recomendacion = 'NoDriveTypeAutoRun=255 en HKLM (accion FixAutorun).'
        Test = {
            $v = Get-CSWAuditRegInt $script:AuditRegExplorer 'NoDriveTypeAutoRun'
            if ($null -eq $v) { $v = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoDriveTypeAutoRun' }
            if ($null -eq $v) { return (New-CSWAuditOutcome 'Parcial' 'No configurado (por defecto 0x91: solo protege algunas unidades)') }
            if (($v -band 0xFF) -eq 0xFF) { return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado en todas las unidades (0xFF)') }
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'AutoRun habilitado en todas las unidades (0)') }
            return (New-CSWAuditOutcome 'Parcial' ('Valor 0x{0:X2}' -f $v))
        }
    }
    @{ Id = 'HAR-02'; Categoria = 'Hardening del sistema'; Severidad = 'Media'; Referencia = 'Microsoft Security Baseline (SmartScreen)'
        Titulo = 'SmartScreen de Windows (Explorador) activo'
        Recomendacion = 'Activar "Comprobar aplicaciones y archivos" en Seguridad de Windows > Control de aplicaciones y navegador.'
        Test = {
            $pol = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
            if ($pol -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado por politica') }
            if ($pol -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Activado por politica') }
            $v = [string](Get-CSWAuditReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
            if ($v -eq 'Off') { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado') }
            if ($v) { return (New-CSWAuditOutcome 'Cumple' "Activado ($v)") }
            return (New-CSWAuditOutcome 'Cumple' 'Activado (por defecto)')
        }
    }
    @{ Id = 'HAR-03'; Categoria = 'Hardening del sistema'; Severidad = 'Baja'; Referencia = 'Microsoft Security Baseline (Edge)'
        Titulo = 'SmartScreen de Microsoft Edge'
        Recomendacion = 'No desactivar SmartScreen en Edge por politica (SmartScreenEnabled=1).'
        Test = {
            $edge = @(Get-CSWAuditSoftware | Where-Object { $_.Name -eq 'Microsoft Edge' })
            if (-not $edge.Count) { return (New-CSWAuditOutcome 'NoAplica' 'Microsoft Edge no detectado') }
            $v = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
            if ($null -eq $v) { $v = Get-CSWAuditRegInt 'HKCU:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' }
            if ($v -eq 0) { return (New-CSWAuditOutcome 'NoCumple' 'Desactivado por politica') }
            if ($v -eq 1) { return (New-CSWAuditOutcome 'Cumple' 'Activado por politica') }
            return (New-CSWAuditOutcome 'Cumple' 'Sin politica (activado por defecto)')
        }
    }
    @{ Id = 'HAR-04'; Categoria = 'Hardening del sistema'; Severidad = 'Baja'; Referencia = 'Buenas practicas (concienciacion)'
        Titulo = 'Mostrar extensiones de archivo (usuario actual)'
        Recomendacion = 'Explorador > Ver > Mostrar extensiones de nombre de archivo (HideFileExt=0) para detectar archivos tipo factura.pdf.exe.'
        Test = {
            $v = Get-CSWAuditRegInt 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Extensiones visibles') }
            return (New-CSWAuditOutcome 'NoCumple' 'Extensiones ocultas')
        }
    }
    @{ Id = 'HAR-05'; Categoria = 'Hardening del sistema'; Severidad = 'Baja'; Referencia = 'ACSC/NCSC (hardening de scripts)'
        Titulo = 'Windows Script Host (informativo)'
        Recomendacion = 'Valorar deshabilitar Windows Script Host (Settings\Enabled=0) si no se usan scripts .vbs/.js.'
        Test = {
            $v = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
            if ($v -eq 0) { return (New-CSWAuditOutcome 'Cumple' 'Deshabilitado') }
            return (New-CSWAuditOutcome 'Parcial' 'Habilitado (por defecto)')
        }
    }
    @{ Id = 'HAR-06'; Categoria = 'Hardening del sistema'; Severidad = 'Media'; Referencia = 'Buenas practicas (recuperacion)'
        Titulo = 'Proteccion del sistema (puntos de restauracion) en la unidad del sistema'
        Recomendacion = 'Activar Proteccion del sistema en la unidad del sistema (Enable-ComputerRestore) con 5-10% de espacio.'
        Test = {
            $dis = Get-CSWAuditRegInt 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' 'DisableSR'
            if ($dis -eq 1) { return (New-CSWAuditOutcome 'NoCumple' 'Deshabilitada por politica') }
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients'
            $k = $null
            try { $k = Get-Item -LiteralPath $key -ErrorAction Stop } catch { $k = $null }
            if ($null -eq $k) {
                if (-not (Test-CSWAuditIsAdmin)) { throw 'Requiere ejecutar como administrador (configuracion de Proteccion del sistema)' }
                return (New-CSWAuditOutcome 'NoCumple' 'Proteccion del sistema no configurada')
            }
            $val = @($k.GetValue('{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}', $null))
            $letter = ($env:SystemDrive).TrimEnd(':')
            if (@($val | Where-Object { [string]$_ -match ('\(' + [regex]::Escape($letter) + '%3A\)') }).Count) { return (New-CSWAuditOutcome 'Cumple' ("Activa en {0}" -f $env:SystemDrive)) }
            return (New-CSWAuditOutcome 'NoCumple' ("Desactivada en {0}" -f $env:SystemDrive))
        }
    }
    @{ Id = 'HAR-07'; Categoria = 'Hardening del sistema'; Severidad = 'Media'; Referencia = 'CIS Controls (Recuperacion de datos)'
        Titulo = 'Copia de seguridad configurada (informativo)'
        Recomendacion = 'Configurar una copia de seguridad automatica (Historial de archivos, Windows Backup o software dedicado) con copia fuera del equipo (regla 3-2-1).'
        Test = {
            $found = @()
            $fh = Join-Path ([string]$env:LOCALAPPDATA) 'Microsoft\Windows\FileHistory\Configuration\Config1.xml'
            if ($env:LOCALAPPDATA -and (Test-Path -LiteralPath $fh)) { $found += 'Historial de archivos' }
            if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup\ScheduleParams') { $found += 'Copia de seguridad de Windows (programada)' }
            $sw = @(Get-CSWAuditSoftware | Where-Object { $_.Name -match $script:AuditBackupRegex } | ForEach-Object { $_.Name } | Select-Object -Unique)
            $found += $sw
            if ($found.Count) { return (New-CSWAuditOutcome 'Cumple' ('Detectado: ' + (Join-CSWAuditList $found 4) + ' (verificar que se ejecuta y se puede restaurar)')) }
            $od = $false
            $acc = 'HKCU:\Software\Microsoft\OneDrive\Accounts'
            if (Test-Path -LiteralPath $acc) {
                foreach ($k in @(Get-ChildItem -LiteralPath $acc -ErrorAction SilentlyContinue)) { if ([string]$k.GetValue('UserEmail', $null)) { $od = $true } }
            }
            if ($od) { return (New-CSWAuditOutcome 'Parcial' 'Solo OneDrive (sincronizacion, no es una copia de seguridad completa)') }
            return (New-CSWAuditOutcome 'NoCumple' 'No se detecta ninguna solucion de copia de seguridad')
        }
    }
    @{ Id = 'HAR-08'; Categoria = 'Hardening del sistema'; Severidad = 'Baja'; Referencia = 'Microsoft (about_Execution_Policies)'
        Titulo = 'Politica de ejecucion de PowerShell (informativo)'
        Recomendacion = 'Usar RemoteSigned o AllSigned a nivel de equipo; evitar Unrestricted/Bypass permanentes.'
        Test = {
            $list = @(Get-ExecutionPolicy -List -ErrorAction Stop)
            $set = @($list | Where-Object { [string]$_.ExecutionPolicy -ne 'Undefined' } | ForEach-Object { '{0}={1}' -f $_.Scope, $_.ExecutionPolicy })
            $lm = [string](Get-CSWAuditProp (@($list | Where-Object { [string]$_.Scope -eq 'LocalMachine' }) | Select-Object -First 1) 'ExecutionPolicy')
            $mp = [string](Get-CSWAuditProp (@($list | Where-Object { [string]$_.Scope -eq 'MachinePolicy' }) | Select-Object -First 1) 'ExecutionPolicy')
            $txt = 'Definidas: ' + $(if ($set.Count) { $set -join ', ' } else { 'ninguna (Restricted/RemoteSigned por defecto)' })
            if ($mp -match 'Unrestricted|Bypass' -or $lm -match 'Unrestricted|Bypass') { return (New-CSWAuditOutcome 'Parcial' $txt) }
            return (New-CSWAuditOutcome 'Cumple' $txt)
        }
    }

    # ======================= SOFTWARE =======================
    @{ Id = 'SW-01'; Categoria = 'Software'; Severidad = 'Baja'; Referencia = 'Inventario (informativo)'
        Titulo = 'Navegadores instalados y version (informativo)'
        Recomendacion = 'Mantener los navegadores actualizados y desinstalar los que no se usen.'
        Test = {
            $b = @(Get-CSWAuditSoftware | Where-Object { $_.Name -match $script:AuditBrowserRegex -and $_.Name -notmatch '(?i)WebView|Update|Helper|Installer' } |
                ForEach-Object { ('{0} {1}' -f $_.Name, $_.Version).Trim() } | Select-Object -Unique)
            if (-not $b.Count) { return (New-CSWAuditOutcome 'Cumple' 'No se detectan navegadores en el registro de programas') }
            return (New-CSWAuditOutcome 'Cumple' (Join-CSWAuditList $b 6))
        }
    }
    @{ Id = 'SW-02'; Categoria = 'Software'; Severidad = 'Alta'; Referencia = 'CIS Controls (Inventario de software)'
        Titulo = 'Software sin soporte (EOL) instalado'
        Recomendacion = 'Desinstalar software sin soporte (Flash, Java 6/7, Silverlight, QuickTime para Windows...).'
        Test = {
            $eol = @(Get-CSWAuditSoftware | Where-Object { $_.Name -match $script:AuditEolRegex } | ForEach-Object { ('{0} {1}' -f $_.Name, $_.Version).Trim() } | Select-Object -Unique)
            if ($eol.Count) { return (New-CSWAuditOutcome 'NoCumple' (Join-CSWAuditList $eol)) }
            return (New-CSWAuditOutcome 'Cumple' 'No se detecta software EOL conocido')
        }
    }
    @{ Id = 'SW-03'; Categoria = 'Software'; Severidad = 'Media'; Referencia = 'CIS Controls (Software autorizado)'
        Titulo = 'Herramientas de acceso remoto instaladas'
        Recomendacion = 'Verificar que el cliente autoriza cada herramienta de acceso remoto; desinstalar las que no se usen y proteger las demas con 2FA.'
        Test = {
            $rt = @(Get-CSWAuditSoftware | Where-Object { $_.Name -match $script:AuditRemoteToolRegex } | ForEach-Object { $_.Name } | Select-Object -Unique)
            if ($rt.Count) { return (New-CSWAuditOutcome 'Parcial' ('Verificar que el cliente lo autoriza: ' + (Join-CSWAuditList $rt))) }
            return (New-CSWAuditOutcome 'Cumple' 'No se detectan herramientas de acceso remoto de terceros')
        }
    }
)

# ---------------------------------------------------------------------------
# Motor de auditoria
# ---------------------------------------------------------------------------
function Invoke-CSWAuditControl {
    param([Parameter(Mandatory)][hashtable]$Control)
    $estado = 'SinDatos'; $valor = ''
    $ErrorActionPreference = 'Stop'
    try {
        $r = & $Control.Test
        $o = @($r | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('Estado') }) | Select-Object -Last 1
        if ($o) { $estado = [string]$o.Estado; $valor = [string]$o.Valor }
        else { $valor = 'El control no devolvio resultado' }
        if (-not $script:AuditStateOrder.ContainsKey($estado)) { $valor = "Estado no valido: $estado"; $estado = 'SinDatos' }
    }
    catch {
        $estado = 'SinDatos'
        $msg = [string]$_.Exception.Message
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -match '(?i)acceso denegado|access is denied|access denied|0x80070005') {
            if ($msg -notmatch '^Requiere ejecutar como administrador') { $msg = 'Requiere ejecutar como administrador: ' + $msg }
        }
        $valor = ($msg -replace '\s+', ' ').Trim()
    }
    [pscustomobject]@{
        Id            = $Control.Id
        Categoria     = $Control.Categoria
        Control       = $Control.Titulo
        Severidad     = $Control.Severidad
        Estado        = $estado
        Valor         = $valor
        Referencia    = $Control.Referencia
        Recomendacion = $Control.Recomendacion
    }
}

function Get-CSWAuditGrade {
    param($Score)
    if ($null -eq $Score) { return 'N/D' }
    if ($Score -ge 90) { return 'A' }
    if ($Score -ge 80) { return 'B' }
    if ($Score -ge 65) { return 'C' }
    if ($Score -ge 50) { return 'D' }
    return 'F'
}

function Get-CSWAuditScoreOf {
    param([object[]]$Results)
    $tot = 0.0; $got = 0.0
    $c = @{ Cumple = 0; Parcial = 0; NoCumple = 0; SinDatos = 0; NoAplica = 0 }
    foreach ($r in @($Results)) {
        $w = [double]$script:AuditSevWeight[[string]$r.Severidad]
        $c[[string]$r.Estado]++
        switch ([string]$r.Estado) {
            'Cumple'   { $tot += $w; $got += $w }
            'Parcial'  { $tot += $w; $got += ($w / 2) }
            'NoCumple' { $tot += $w }
        }
    }
    $score = $null
    if ($tot -gt 0) { $score = [int][math]::Round(100 * $got / $tot) }
    return @{ Score = $score; Grade = (Get-CSWAuditGrade $score); Counts = $c; Total = @($Results).Count }
}

function Get-CSWAuditScore {
    param([object[]]$Results)
    $all = Get-CSWAuditScoreOf -Results $Results
    $cats = @()
    foreach ($cat in $script:AuditCategories) {
        $sub = @($Results | Where-Object { $_.Categoria -eq $cat })
        if (-not $sub.Count) { continue }
        $s = Get-CSWAuditScoreOf -Results $sub
        $cats += [pscustomobject]@{
            Categoria = $cat; Puntuacion = $s.Score; Letra = $s.Grade; Controles = $sub.Count
            Cumple = $s.Counts.Cumple; Parcial = $s.Counts.Parcial; NoCumple = $s.Counts.NoCumple
            SinDatos = $s.Counts.SinDatos; NoAplica = $s.Counts.NoAplica
        }
    }
    $all.Categories = $cats
    return $all
}

function Invoke-CSWAuditRun {
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][object[]]$Controls)
    $script:AuditCtx = @{}
    $isAdmin = Test-CSWAuditIsAdmin
    if (-not $isAdmin) { Write-CSWLog 'Sesion SIN privilegios de administrador: los controles de politica local, auditoria y BitLocker quedaran "Sin datos".' -Level Warn }
    Write-CSWLog ('Auditoria de ciberseguridad ({0}): {1} controles' -f $Scope, @($Controls).Count) -Level Step
    $results = New-Object System.Collections.ArrayList
    foreach ($cat in $script:AuditCategories) {
        $cs = @($Controls | Where-Object { $_.Categoria -eq $cat })
        if (-not $cs.Count) { continue }
        Write-CSWLog ('Evaluando: {0} ({1} controles)...' -f $cat, $cs.Count) -Level Info
        $catRes = @()
        foreach ($c in $cs) {
            $r = Invoke-CSWAuditControl -Control $c
            [void]$results.Add($r)
            $catRes += $r
            if ($r.Estado -eq 'NoCumple' -and ($r.Severidad -eq 'Critica' -or $r.Severidad -eq 'Alta')) {
                Write-CSWLog ('  [{0}] {1}: {2}' -f $r.Id, $r.Control, $r.Valor) -Level Warn
            }
        }
        $s = Get-CSWAuditScoreOf -Results $catRes
        $pt = 'N/D'
        if ($null -ne $s.Score) { $pt = "$($s.Score)%" }
        Write-CSWLog ('  {0}: {1} cumple, {2} parcial, {3} no cumple, {4} sin datos -> {5}' -f $cat, $s.Counts.Cumple, $s.Counts.Parcial, $s.Counts.NoCumple, $s.Counts.SinDatos, $pt) -Level Data
    }
    $arr = @($results.ToArray())
    $audit = @{
        Time     = Get-Date
        Scope    = $Scope
        Computer = $env:COMPUTERNAME
        IsAdmin  = $isAdmin
        Results  = $arr
        Score    = (Get-CSWAuditScore -Results $arr)
    }
    $state = Get-CSWState
    $state.LastAudit = $audit
    $script:AuditCtx = @{}
    return $audit
}

function Get-CSWAuditSortedResult {
    param([object[]]$Results)
    return @($Results | Sort-Object @{ Expression = { $script:AuditStateOrder[[string]$_.Estado] } }, @{ Expression = { $script:AuditSevOrder[[string]$_.Severidad] } }, Id)
}

# ---------------------------------------------------------------------------
# HTML / exportacion
# ---------------------------------------------------------------------------
$script:AuditCss = @'
:root{--bg:#eef1f5;--ink:#0f172a;--ink2:#334155;--muted:#64748b;--line:#e2e8f0;--line2:#cbd5e1;--brand:#0b5cad;--soft:#e8f0fa;--ok:#15803d;--warn:#b45309;--err:#b91c1c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 'Segoe UI',system-ui,-apple-system,'Helvetica Neue',Arial,sans-serif;-webkit-text-size-adjust:100%}
.page{max-width:1040px;margin:28px auto;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 6px 28px rgba(15,23,42,.07);overflow:hidden}
.topbar{height:6px;background:linear-gradient(90deg,#0b5cad,#2a86e0 65%,#5cd6ff)}
.doc-head{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:24px 36px 20px}
.brand{display:flex;align-items:center;gap:12px}.brand svg{width:48px;height:48px;flex:none}
.wordmark{font-size:21px;line-height:1.1;color:var(--ink)}.wordmark b{color:var(--brand);font-weight:700}.wordmark span{font-weight:300}
.tagline{font-size:12px;color:var(--muted);margin-top:3px}
.doc-meta{text-align:right}.doc-title{font-size:20px;font-weight:600;margin:0;color:var(--ink)}
.doc-sub{font-size:12px;color:var(--muted);margin-top:3px}
.meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;padding:14px 36px;background:#f8fafc;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.meta-grid label{display:block;font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.meta-grid div div{font-weight:600;color:var(--ink);overflow-wrap:anywhere}
.content{padding:26px 36px 18px}
.card{border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 18px;background:#fff}
h2{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;color:var(--ink);margin:0 0 14px;padding-bottom:10px;border-bottom:1px solid var(--line)}
h2::before{content:"";width:4px;height:16px;border-radius:2px;background:var(--brand);flex:none}
h3{font-size:13.5px;font-weight:600;color:var(--ink2);margin:18px 0 8px}
p{margin:8px 0}.muted{color:var(--muted)}.nowrap{white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0 2px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
th{background:#f1f5f9;color:var(--ink2);font-weight:600;font-size:12px;width:200px;word-break:normal;overflow-wrap:normal}
tbody tr:nth-child(even) td{background:#f8fafc}
table.kv th{background:#fff;color:var(--muted);font-weight:500;font-size:12.5px;width:190px}
table.kv td{background:#fff!important;font-weight:500}
.status{display:inline-flex;align-items:center;gap:7px;padding:4px 12px;border-radius:999px;font-size:12.5px;font-weight:600}
.status::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.st-ok{background:#e8f5ec;color:#166534}.st-warn{background:#fef3e2;color:#92400e}.st-err{background:#fdecec;color:#991b1b}.st-mute{background:#f1f5f9;color:#475569}
.sumhead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px}
.kpi{border:1px solid var(--line);border-top:3px solid var(--line2);border-radius:8px;padding:10px 14px;background:#fff}
.kpi b{display:block;font-size:24px;line-height:1.25;font-weight:700}.kpi span{display:block;color:var(--muted);font-size:12px}
.kpi.k-brand{border-top-color:var(--brand)}.kpi.k-ok{border-top-color:var(--ok)}.kpi.k-warn{border-top-color:var(--warn)}.kpi.k-err{border-top-color:var(--err)}.kpi.k-mute{border-top-color:var(--line2)}
.stack{display:flex;height:10px;border-radius:5px;overflow:hidden;background:#e5e9f0;margin-top:14px}.stack i{display:block}
.s-ok{background:var(--ok)}.s-warn{background:#d97706}.s-err{background:var(--err)}
.legend{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11.5px;font-weight:600;line-height:1.6;white-space:nowrap;border:1px solid transparent}
.badge.ok{background:#e8f5ec;color:#166534;border-color:#bfe3cb}.badge.warn{background:#fef3e2;color:#92400e;border-color:#f6d7a7}
.badge.err{background:#fdecec;color:#991b1b;border-color:#f3c0c0}.badge.crit{background:#b91c1c;color:#fff;border-color:#b91c1c}
.badge.high{background:#fff1e6;color:#9a3412;border-color:#f8cfae}.badge.mute{background:#f1f5f9;color:#475569;border-color:#e2e8f0}
.scorebox{display:flex;align-items:center;gap:24px;flex-wrap:wrap;margin-bottom:16px}
.gauge{--p:0;--c:var(--brand);width:124px;height:124px;border-radius:50%;flex:none;display:grid;place-items:center;background:conic-gradient(var(--c) calc(var(--p) * 1%),#e5e9f0 0)}
.gauge>div{width:98px;height:98px;border-radius:50%;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge b{font-size:32px;line-height:1;font-weight:700;color:var(--c)}.gauge small{font-size:11px;color:var(--muted);margin-top:4px}
.verdict{flex:1;min-width:220px}.verdict .grade{font-size:19px;font-weight:700;margin-bottom:2px}.verdict .vtxt{font-size:15px;font-weight:600;color:var(--ink)}
.bar{display:inline-block;vertical-align:middle;width:110px;height:8px;background:#e5e9f0;border-radius:4px;overflow:hidden;margin-right:8px}.bar>i{display:block;height:100%;border-radius:4px}
.score{font-size:40px;font-weight:700}
.notes{white-space:pre-wrap;margin:0;color:var(--ink2)}
pre.log{background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:8px;overflow:auto;max-height:480px;margin:0;font:11.5px/1.55 'Cascadia Mono',Consolas,monospace}
.sign{display:grid;grid-template-columns:1fr 1fr;gap:56px;padding:40px 6px 4px}
.sign div{border-top:1px solid var(--ink2);padding-top:6px;color:var(--muted);font-size:12px}
.doc-foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px 36px;border-top:1px solid var(--line);background:#f8fafc;color:var(--muted);font-size:11.5px}
@media (max-width:760px){.page{margin:0;border-radius:0;border:0}.doc-head{flex-direction:column;align-items:flex-start}.doc-meta{text-align:left}
.meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.doc-head,.meta-grid,.content,.doc-foot{padding-left:18px;padding-right:18px}th{width:auto}}
@page{size:A4;margin:12mm 11mm 14mm}
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:#fff;font-size:11.5px}.page{max-width:none;margin:0;border:0;border-radius:0;box-shadow:none}
.doc-head{padding:4px 0 12px}.meta-grid{padding:9px 10px}.content{padding:14px 0 0}.doc-foot{padding:9px 10px}
.card{border-color:#d5dbe3;padding:12px 14px;margin-bottom:12px}
h2,h3{break-after:avoid;page-break-after:avoid}
tr,.kpi,.kpis,.scorebox,.sign,.gauge,.stack,.legend{break-inside:avoid;page-break-inside:avoid}
thead{display:table-header-group}table{font-size:10.5px}th,td{padding:5px 7px}
.card.logcard{break-before:page;page-break-before:always}
pre.log{max-height:none;overflow:visible;white-space:pre-wrap;word-break:break-word;background:#fff;color:#1f2937;border:1px solid #d5dbe3;font-size:8.5px}}
'@

function Get-CSWAuditStateBadge {
    param([string]$Estado)
    switch ($Estado) {
        'Cumple'   { return "<span class='badge ok'>Cumple</span>" }
        'Parcial'  { return "<span class='badge warn'>Parcial</span>" }
        'NoCumple' { return "<span class='badge err'>No cumple</span>" }
        'NoAplica' { return "<span class='badge mute'>No aplica</span>" }
        default    { return "<span class='badge mute'>Sin datos</span>" }
    }
}

function Get-CSWAuditSevBadge {
    param([string]$Sev)
    switch ($Sev) {
        'Critica' { return "<span class='badge crit'>Cr&iacute;tica</span>" }
        'Alta'    { return "<span class='badge high'>Alta</span>" }
        'Media'   { return "<span class='badge warn'>Media</span>" }
        default   { return "<span class='badge mute'>Baja</span>" }
    }
}

function Get-CSWAuditScoreColor {
    param($Score)
    if ($null -eq $Score) { return 'var(--muted)' }
    if ($Score -ge 80) { return 'var(--ok)' }
    if ($Score -ge 50) { return 'var(--warn)' }
    return 'var(--err)'
}

function ConvertTo-CSWAuditHtml {
    <# Contenido interno de la tarjeta (sección del informe). #>
    param([Parameter(Mandatory)][hashtable]$Audit, [switch]$IncludeAll)
    $sc = $Audit.Score
    $cnt = $sc.Counts
    $th = "<th style='width:auto'>"
    $sb = New-Object System.Text.StringBuilder
    $scoreTxt = 'N/D'
    if ($null -ne $sc.Score) { $scoreTxt = [string]$sc.Score }
    $col = Get-CSWAuditScoreColor $sc.Score

    $pct = 0
    if ($null -ne $sc.Score) { $pct = [int]$sc.Score }
    [void]$sb.Append("<div class='scorebox'><div class='gauge' style='--p:$pct;--c:$col'><div><b>$(ConvertTo-CSWHtmlText $scoreTxt)</b><small>de 100</small></div></div>")
    [void]$sb.Append("<div class='verdict' style='flex:0 0 auto;min-width:150px'><div class='muted' style='font-size:12px;font-weight:600'>Calificaci&oacute;n</div><div class='grade' style='color:$col;font-size:30px;line-height:1.1'>$(ConvertTo-CSWHtmlText $sc.Grade)</div></div>")
    [void]$sb.Append("<div class='kpis' style='flex:1;min-width:280px'>")
    [void]$sb.Append("<div class='kpi k-ok'><b style='color:var(--ok)'>$($cnt.Cumple)</b><span>Cumple</span></div>")
    [void]$sb.Append("<div class='kpi k-warn'><b style='color:var(--warn)'>$($cnt.Parcial)</b><span>Parcial</span></div>")
    [void]$sb.Append("<div class='kpi k-err'><b style='color:var(--err)'>$($cnt.NoCumple)</b><span>No cumple</span></div>")
    [void]$sb.Append("<div class='kpi k-mute'><b style='color:var(--muted)'>$($cnt.SinDatos)</b><span>Sin datos</span></div>")
    [void]$sb.Append('</div></div>')
    $adm = 'S&iacute;'
    if (-not $Audit.IsAdmin) { $adm = 'No (resultados incompletos)' }
    [void]$sb.Append(("<p class='muted'>Alcance: {0} &middot; {1} controles ({2} no aplican) &middot; {3:dd\/MM\/yyyy HH:mm} &middot; Ejecutado como administrador: {4}. Puntuaci&oacute;n ponderada por severidad (Cr&iacute;tica 10, Alta 6, Media 3, Baja 1; parcial = 50%).</p>" -f (ConvertTo-CSWHtmlText $Audit.Scope), $sc.Total, $cnt.NoAplica, $Audit.Time, $adm))

    # Por categoria
    [void]$sb.Append("<h3>Resultado por categor&iacute;a</h3><table>")
    [void]$sb.Append("<thead><tr>${th}Categor&iacute;a</th>${th}Puntuaci&oacute;n</th>${th}Cumple</th>${th}Parcial</th>${th}No cumple</th>${th}Sin datos</th></tr></thead><tbody>")
    foreach ($c in @($sc.Categories)) {
        $p = $c.Puntuacion
        $pt = 'N/D'; $w = 0
        if ($null -ne $p) { $pt = '{0}% ({1})' -f $p, $c.Letra; $w = [int]$p }
        $cc = Get-CSWAuditScoreColor $p
        $bar = "<span class='bar'><i style='width:$w%;background:$cc'></i></span>"
        [void]$sb.Append(("<tr><td>{0}</td><td style='white-space:nowrap'>{1}{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f (ConvertTo-CSWHtmlText $c.Categoria), $bar, (ConvertTo-CSWHtmlText $pt), $c.Cumple, $c.Parcial, $c.NoCumple, $c.SinDatos))
    }
    [void]$sb.Append('</tbody></table>')

    # Hallazgos
    $find = @(Get-CSWAuditSortedResult @($Audit.Results | Where-Object { $_.Estado -eq 'NoCumple' -or $_.Estado -eq 'Parcial' }))
    [void]$sb.Append(("<h3>Hallazgos ({0})</h3>" -f $find.Count))
    if ($find.Count) {
        [void]$sb.Append("<table><thead><tr>${th}Id</th>${th}Control</th>${th}Severidad</th>${th}Estado</th>${th}Valor encontrado</th>${th}Recomendaci&oacute;n</th></tr></thead><tbody>")
        foreach ($r in $find) {
            [void]$sb.Append(("<tr><td style='white-space:nowrap'>{0}</td><td>{1}<br><span class='muted' style='font-size:12px'>{2}</span></td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f (ConvertTo-CSWHtmlText $r.Id), (ConvertTo-CSWHtmlText $r.Control), (ConvertTo-CSWHtmlText $r.Categoria), (Get-CSWAuditSevBadge $r.Severidad), (Get-CSWAuditStateBadge $r.Estado), (ConvertTo-CSWHtmlText $r.Valor), (ConvertTo-CSWHtmlText $r.Recomendacion)))
        }
        [void]$sb.Append('</tbody></table>')
    }
    else { [void]$sb.Append("<p><span class='badge ok'>OK</span> No se encontraron incumplimientos.</p>") }

    # Sin datos
    $nd = @($Audit.Results | Where-Object { $_.Estado -eq 'SinDatos' })
    if ($nd.Count) {
        [void]$sb.Append(("<p class='muted' style='margin-top:14px'><b>Controles sin datos ({0}):</b> " -f $nd.Count))
        [void]$sb.Append((@($nd | ForEach-Object { '{0} ({1})' -f (ConvertTo-CSWHtmlText $_.Id), (ConvertTo-CSWHtmlText $_.Valor) }) -join '; '))
        [void]$sb.Append('</p>')
    }

    if ($IncludeAll) {
        [void]$sb.Append("<h3>Detalle de todos los controles</h3>")
        [void]$sb.Append("<table><thead><tr>${th}Id</th>${th}Categor&iacute;a</th>${th}Control</th>${th}Severidad</th>${th}Estado</th>${th}Valor</th>${th}Referencia</th></tr></thead><tbody>")
        foreach ($r in @($Audit.Results | Sort-Object Id)) {
            [void]$sb.Append(("<tr><td style='white-space:nowrap'>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td class='muted'>{6}</td></tr>" -f (ConvertTo-CSWHtmlText $r.Id), (ConvertTo-CSWHtmlText $r.Categoria), (ConvertTo-CSWHtmlText $r.Control), (Get-CSWAuditSevBadge $r.Severidad), (Get-CSWAuditStateBadge $r.Estado), (ConvertTo-CSWHtmlText $r.Valor), (ConvertTo-CSWHtmlText $r.Referencia)))
        }
        [void]$sb.Append('</tbody></table>')
    }
    return $sb.ToString()
}

function ConvertTo-CSWAuditHtmlDocument {
    param([Parameter(Mandatory)][hashtable]$Audit)
    $s = Get-CSWState
    $inner = ConvertTo-CSWAuditHtml -Audit $Audit -IncludeAll
    $os = ''
    try { $os = ConvertTo-CSWHtmlText ([string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption) } catch { }
    $client = '&mdash;'
    if ($s.ContainsKey('ClientName') -and $s.ClientName) { $client = ConvertTo-CSWHtmlText ([string]$s.ClientName) }
    $tech = '&mdash;'
    if ($s.ContainsKey('TechName') -and $s.TechName) { $tech = ConvertTo-CSWHtmlText ([string]$s.TechName) }
    $ver = ''
    if ($s.ContainsKey('Version')) { $ver = [string]$s.Version }
    if (-not $os) { $os = '&mdash;' }
    $comp = ConvertTo-CSWHtmlText $Audit.Computer
    $when = ConvertTo-CSWHtmlText ('{0:dd\/MM\/yyyy HH:mm}' -f $Audit.Time)
    $verTxt = ConvertTo-CSWHtmlText $ver
    $logo = @'
<svg viewBox="0 0 64 64" role="img" aria-label="Cybersutro win"><defs><linearGradient id="cswg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2A86E0"/><stop offset=".55" stop-color="#0B5CAD"/><stop offset="1" stop-color="#073F78"/></linearGradient></defs><path d="M32 3 56 11.5V30c0 15.5-10.4 26.6-24 31C18.4 56.6 8 45.5 8 30V11.5Z" fill="url(#cswg)"/><path d="M32 3 8 11.5V30c0 15.5 10.4 26.6 24 31Z" fill="#fff" opacity=".13"/><path d="M13 32h8.5L26 21l6.5 22L37 32h7.5" fill="none" stroke="#fff" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="49.5" cy="32" r="3.7" fill="#5CD6FF"/></svg>
'@
    return @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditor&iacute;a de ciberseguridad - $comp</title>
<style>
$script:AuditCss
</style></head><body>
<div class="page">
<div class="topbar"></div>
<header class="doc-head">
  <div class="brand">$logo<div><div class="wordmark"><b>Cybersutro</b><span> win</span></div><div class="tagline">Soporte t&eacute;cnico para Windows</div></div></div>
  <div class="doc-meta"><h1 class="doc-title">Auditor&iacute;a de ciberseguridad</h1><div class="doc-sub">$when &middot; Cybersutro win $verTxt</div></div>
</header>
<div class="meta-grid">
  <div><label>Equipo</label><div>$comp</div></div>
  <div><label>Sistema</label><div>$os</div></div>
  <div><label>Cliente</label><div>$client</div></div>
  <div><label>T&eacute;cnico</label><div>$tech</div></div>
</div>
<main class="content">
<section class="card"><h2>Resumen de la auditor&iacute;a</h2>
$inner
</section>
<p class="muted" style="font-size:12px">Referencias gen&eacute;ricas a CIS Benchmarks, Microsoft Security Baselines y buenas pr&aacute;cticas. Este informe refleja el estado del equipo en el momento de la auditor&iacute;a.</p>
</main>
<footer class="doc-foot"><span>Generado por Cybersutro win $verTxt &middot; $when</span><span>$comp</span></footer>
</div>
</body></html>
"@
}

function Get-CSWAuditFileBase {
    param([hashtable]$Audit)
    $name = ([string]$Audit.Computer) -replace '[^A-Za-z0-9_-]', '_'
    return (Join-Path (Get-CSWDataPath Reports) ('Auditoria_{0}_{1:yyyyMMdd_HHmmss}' -f $name, $Audit.Time))
}

function Export-CSWAuditCsv {
    param([hashtable]$Audit)
    $path = (Get-CSWAuditFileBase $Audit) + '.csv'
    $Audit.Results | Select-Object Id, Categoria, Control, Severidad, Estado, Valor, Referencia, Recomendacion |
        Export-Csv -LiteralPath $path -NoTypeInformation -Delimiter ';' -Encoding UTF8 -ErrorAction Stop
    return $path
}

function Export-CSWAuditJson {
    param([hashtable]$Audit)
    $path = (Get-CSWAuditFileBase $Audit) + '.json'
    $sc = $Audit.Score
    $obj = [ordered]@{
        Equipo        = $Audit.Computer
        Fecha         = ([datetime]$Audit.Time).ToString('s')
        Alcance       = $Audit.Scope
        Administrador = $Audit.IsAdmin
        Puntuacion    = $sc.Score
        Calificacion  = $sc.Grade
        Recuento      = $sc.Counts
        Categorias    = @($sc.Categories)
        Controles     = @($Audit.Results | Select-Object Id, Categoria, Control, Severidad, Estado, Valor, Referencia, Recomendacion)
    }
    $json = $obj | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($true)))
    return $path
}

function Export-CSWAuditHtml {
    param([hashtable]$Audit)
    $path = (Get-CSWAuditFileBase $Audit) + '.html'
    $doc = ConvertTo-CSWAuditHtmlDocument -Audit $Audit
    [System.IO.File]::WriteAllText($path, $doc, (New-Object System.Text.UTF8Encoding($true)))
    return $path
}

function Get-CSWAuditSummaryText {
    param([hashtable]$Audit)
    $sc = $Audit.Score
    $nc = @($Audit.Results | Where-Object { $_.Estado -eq 'NoCumple' })
    $crit = @($nc | Where-Object { $_.Severidad -eq 'Critica' }).Count
    $st = 'N/D'
    if ($null -ne $sc.Score) { $st = "$($sc.Score)/100" }
    $t = 'Puntuacion {0} ({1}) - {2} controles no cumplen ({3} criticos)' -f $st, $sc.Grade, $nc.Count, $crit
    if ($sc.Counts.SinDatos -gt 0) {
        $t += ('; {0} sin datos' -f $sc.Counts.SinDatos)
        if (-not $Audit.IsAdmin) { $t += ' (ejecutar como administrador)' }
    }
    return $t
}

function Get-CSWAuditResultStatus {
    param([hashtable]$Audit)
    $sc = $Audit.Score
    if (($sc.Counts.Cumple + $sc.Counts.Parcial + $sc.Counts.NoCumple) -eq 0) { return 'Error' }
    $hi = @($Audit.Results | Where-Object { $_.Estado -eq 'NoCumple' -and ($_.Severidad -eq 'Critica' -or $_.Severidad -eq 'Alta') }).Count
    if ($hi -gt 0) { return 'Warn' }
    return 'OK'
}

function Write-CSWAuditTable {
    <# Devuelve la tabla resumida (NoCumple primero, por severidad). #>
    param([hashtable]$Audit)
    foreach ($r in (Get-CSWAuditSortedResult $Audit.Results)) {
        $v = [string]$r.Valor
        if ($v.Length -gt 90) { $v = $v.Substring(0, 87) + '...' }
        [pscustomobject]@{ Id = $r.Id; Categoria = $r.Categoria; Control = $r.Control; Severidad = $r.Severidad; Estado = $r.Estado; Valor = $v }
    }
}

# ---------------------------------------------------------------------------
# Acciones de auditoria
# ---------------------------------------------------------------------------
function Invoke-CSWAuditFull {
    $audit = Invoke-CSWAuditRun -Scope 'Completa' -Controls $script:AuditCatalog
    try {
        Add-CSWReportSection -Id 'SecurityAudit' -Title 'Auditoría de ciberseguridad' -Html (ConvertTo-CSWAuditHtml -Audit $audit) -Order 30
    }
    catch { Write-CSWLog "No se pudo agregar la seccion al informe: $($_.Exception.Message)" -Level Warn }
    try {
        $csv = Export-CSWAuditCsv -Audit $audit
        $htm = Export-CSWAuditHtml -Audit $audit
        Write-CSWLog "CSV: $csv" -Level Ok
        Write-CSWLog "Informe HTML de auditoria: $htm" -Level Ok
    }
    catch { Write-CSWLog "No se pudieron exportar los archivos: $($_.Exception.Message)" -Level Warn }
    Write-CSWAuditTable -Audit $audit
    New-CSWResult -Summary (Get-CSWAuditSummaryText $audit) -Status (Get-CSWAuditResultStatus $audit)
}

function Invoke-CSWAuditCategory {
    param([string]$Category = 'Cuentas y autenticacion')
    $cat = @($script:AuditCategories | Where-Object { $_ -eq $Category }) | Select-Object -First 1
    if (-not $cat) {
        Write-CSWLog ("Categoria no valida: '{0}'. Disponibles: {1}" -f $Category, ($script:AuditCategories -join ', ')) -Level Error
        return (New-CSWResult -Summary "Categoria no valida: $Category" -Status Error)
    }
    $ctl = @($script:AuditCatalog | Where-Object { $_.Categoria -eq $cat })
    $audit = Invoke-CSWAuditRun -Scope ("Categoria: $cat") -Controls $ctl
    try { Add-CSWReportSection -Id 'SecurityAuditPartial' -Title ("Auditoría de ciberseguridad · $cat") -Html (ConvertTo-CSWAuditHtml -Audit $audit) -Order 31 } catch { }
    Write-CSWAuditTable -Audit $audit
    New-CSWResult -Summary ("{0}: {1}" -f $cat, (Get-CSWAuditSummaryText $audit)) -Status (Get-CSWAuditResultStatus $audit)
}

function Invoke-CSWAuditQuickPosture {
    $ctl = @($script:AuditCatalog | Where-Object { $_.Severidad -eq 'Critica' -or $_.Severidad -eq 'Alta' })
    $audit = Invoke-CSWAuditRun -Scope 'Postura rapida (Critica y Alta)' -Controls $ctl
    try { Add-CSWReportSection -Id 'SecurityAuditPartial' -Title 'Auditoría de ciberseguridad · postura rápida' -Html (ConvertTo-CSWAuditHtml -Audit $audit) -Order 31 } catch { }
    Write-CSWAuditTable -Audit $audit
    New-CSWResult -Summary ('Postura rapida: ' + (Get-CSWAuditSummaryText $audit)) -Status (Get-CSWAuditResultStatus $audit)
}

function Get-CSWAuditControlList {
    foreach ($c in $script:AuditCatalog) {
        [pscustomobject]@{ Id = $c.Id; Categoria = $c.Categoria; Severidad = $c.Severidad; Titulo = $c.Titulo }
    }
    $n = @($script:AuditCatalog).Count
    $parts = foreach ($cat in $script:AuditCategories) { '{0}: {1}' -f $cat, @($script:AuditCatalog | Where-Object { $_.Categoria -eq $cat }).Count }
    Write-CSWLog ($parts -join ' | ') -Level Info
    New-CSWResult -Summary ('Catalogo: {0} controles en {1} categorias' -f $n, $script:AuditCategories.Count)
}

function Export-CSWAuditLast {
    $s = Get-CSWState
    if (-not $s.ContainsKey('LastAudit') -or $null -eq $s.LastAudit) {
        Write-CSWLog 'No hay ninguna auditoria en esta sesion. Ejecute primero "Auditoria completa".' -Level Warn
        return (New-CSWResult -Summary 'No hay auditoria previa para exportar' -Status Warn)
    }
    $audit = $s.LastAudit
    try {
        $csv = Export-CSWAuditCsv -Audit $audit
        $json = Export-CSWAuditJson -Audit $audit
        Write-CSWLog "CSV: $csv" -Level Ok
        Write-CSWLog "JSON: $json" -Level Ok
        New-CSWResult -Summary ('Auditoria exportada ({0}) a CSV y JSON en {1}' -f $audit.Scope, (Split-Path $csv -Parent))
    }
    catch {
        Write-CSWLog "Error al exportar: $($_.Exception.Message)" -Level Error
        New-CSWResult -Summary 'No se pudo exportar la auditoria' -Status Error
    }
}

# ---------------------------------------------------------------------------
# Remediaciones seguras
# ---------------------------------------------------------------------------
function Set-CSWAuditRegValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value, [string]$Type = 'DWord')
    $prev = Get-CSWAuditReg -Path $Path -Name $Name
    $prevText = '(no existe)'
    if ($null -ne $prev) { $prevText = [string]$prev }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    Write-CSWLog ('{0}\{1}: valor previo {2} -> {3}' -f $Path, $Name, $prevText, $Value) -Level Info
}

$script:AuditFixes = @(
    @{ Id = 'FixSmbV1'; Label = 'SMBv1'; Controls = @('NET-01'); Reboot = $true
        Apply = {
            if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
                $prev = $null
                try { $prev = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
                Write-CSWLog "Servidor SMB1 valor previo: $prev" -Level Info
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
            }
            $f = Get-CSWAuditFeature 'SMB1Protocol'
            Write-CSWLog "Caracteristica SMB1Protocol estado previo: $f (1=instalada)" -Level Info
            if ($f -eq 1) { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null }
        }
    }
    @{ Id = 'FixAutorun'; Label = 'AutoRun'; Controls = @('HAR-01'); Reboot = $false
        Apply = { Set-CSWAuditRegValue -Path $script:AuditRegExplorer -Name 'NoDriveTypeAutoRun' -Value 255 }
    }
    @{ Id = 'FixLlmnr'; Label = 'LLMNR'; Controls = @('NET-03'); Reboot = $false
        Apply = { Set-CSWAuditRegValue -Path $script:AuditRegDnsClient -Name 'EnableMulticast' -Value 0 }
    }
    @{ Id = 'FixWDigest'; Label = 'WDigest'; Controls = @('CIF-09'); Reboot = $true
        Apply = { Set-CSWAuditRegValue -Path $script:AuditRegWDigest -Name 'UseLogonCredential' -Value 0 }
    }
    @{ Id = 'FixGuestAccount'; Label = 'Cuenta Invitado'; Controls = @('ACC-01'); Reboot = $false
        Apply = {
            $g = @(Get-CSWAuditLocalUser | Where-Object { $_.Sid -match '-501$' }) | Select-Object -First 1
            if (-not $g) { throw 'No se encontro la cuenta Invitado' }
            Write-CSWLog ("Cuenta '{0}' ({1}) deshabilitada previamente: {2}" -f $g.Name, $g.Sid, $g.Disabled) -Level Info
            $done = $false
            if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
                try { Disable-LocalUser -SID $g.Sid -ErrorAction Stop; $done = $true } catch { $done = $false }
            }
            if (-not $done) {
                $code = Invoke-CSWExternal -FilePath 'net.exe' -Arguments ('user "{0}" /active:no' -f $g.Name)
                if ($code -ne 0) { throw "net user devolvio $code" }
            }
        }
    }
    @{ Id = 'FixFirewallProfiles'; Label = 'Firewall (3 perfiles)'; Controls = @('FW-01'); Reboot = $false
        Apply = {
            foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) { Write-CSWLog ('Perfil {0}: Enabled previo {1}' -f $p.Name, $p.Enabled) -Level Info }
            Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
            $still = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
            if ($still.Count) { Write-CSWLog ('Siguen desactivados (posible GPO): ' + ($still -join ', ')) -Level Warn }
        }
    }
    @{ Id = 'FixUac'; Label = 'UAC'; Controls = @('UAC-01', 'UAC-02', 'UAC-03'); Reboot = $true
        Apply = {
            Set-CSWAuditRegValue -Path $script:AuditRegUacPath -Name 'EnableLUA' -Value 1
            Set-CSWAuditRegValue -Path $script:AuditRegUacPath -Name 'ConsentPromptBehaviorAdmin' -Value 5
            Set-CSWAuditRegValue -Path $script:AuditRegUacPath -Name 'PromptOnSecureDesktop' -Value 1
        }
    }
    @{ Id = 'FixAuditPolicy'; Label = 'Politica de auditoria'; Controls = @('LOG-01', 'LOG-02', 'LOG-03', 'LOG-04'); Reboot = $false
        Apply = {
            $prev = $null
            try { $prev = Get-CSWAuditPolicyData } catch { $prev = $null }
            foreach ($k in 'Logon', 'Logoff', 'AccountLockout', 'ProcessCreation', 'SecurityGroupManagement') {
                $g = $script:AuditGuid[$k]
                $pv = 'desconocido'
                if ($prev -and $prev.ContainsKey($g.ToUpperInvariant())) { $pv = ConvertTo-CSWAuditSettingText ([int]$prev[$g.ToUpperInvariant()]) }
                Write-CSWLog ('{0} {1}: valor previo {2}' -f $k, $g, $pv) -Level Info
                $code = Invoke-CSWExternal -FilePath 'auditpol.exe' -Arguments ('/set /subcategory:{0} /success:enable /failure:enable' -f $g)
                if ($code -ne 0) { throw "auditpol devolvio $code para $k" }
            }
        }
    }
    @{ Id = 'FixPowerShellLogging'; Label = 'Registro de PowerShell'; Controls = @('LOG-09'); Reboot = $false
        Apply = { Set-CSWAuditRegValue -Path $script:AuditRegSbl -Name 'EnableScriptBlockLogging' -Value 1 }
    }
    @{ Id = 'FixAutoLogon'; Label = 'Inicio de sesion automatico'; Controls = @('ACC-12', 'ACC-13'); Reboot = $false
        Apply = {
            $al = [string](Get-CSWAuditReg $script:AuditRegWinlogon 'AutoAdminLogon')
            if ($al -eq '1') { Set-CSWAuditRegValue -Path $script:AuditRegWinlogon -Name 'AutoAdminLogon' -Value '0' -Type 'String' }
            if ($null -ne (Get-CSWAuditReg $script:AuditRegWinlogon 'DefaultPassword')) {
                Write-CSWLog 'Winlogon\DefaultPassword: valor previo presente (contenido no registrado) -> eliminado' -Level Info
                Remove-ItemProperty -LiteralPath $script:AuditRegWinlogon -Name 'DefaultPassword' -Force -ErrorAction Stop
            }
        }
    }
)

function Invoke-CSWAuditFixCore {
    <# Evalua los controles del fix; solo aplica si alguno no cumple. Devuelve un hashtable de estado. #>
    param([Parameter(Mandatory)][hashtable]$Fix)
    $script:AuditCtx = @{}
    $pending = @()
    foreach ($id in $Fix.Controls) {
        $c = @($script:AuditCatalog | Where-Object { $_.Id -eq $id }) | Select-Object -First 1
        $r = Invoke-CSWAuditControl -Control $c
        Write-CSWLog ('Estado actual {0} ({1}): {2} - {3}' -f $r.Id, $r.Control, $r.Estado, $r.Valor) -Level Info
        if ($r.Estado -ne 'Cumple' -and $r.Estado -ne 'NoAplica') { $pending += $r.Id }
    }
    if (-not $pending.Count) {
        Write-CSWLog ('{0}: ya cumple, no se modifica nada.' -f $Fix.Label) -Level Ok
        return @{ Status = 'AlreadyOk'; Message = "$($Fix.Label): ya cumple" }
    }
    try {
        $ErrorActionPreference = 'Stop'
        & $Fix.Apply
    }
    catch {
        Write-CSWLog ('{0}: error al aplicar - {1}' -f $Fix.Label, $_.Exception.Message) -Level Error
        $script:AuditCtx = @{}
        return @{ Status = 'Error'; Message = "$($Fix.Label): $($_.Exception.Message)" }
    }
    $script:AuditCtx = @{}
    $after = @()
    foreach ($id in $Fix.Controls) {
        $c = @($script:AuditCatalog | Where-Object { $_.Id -eq $id }) | Select-Object -First 1
        $r = Invoke-CSWAuditControl -Control $c
        $after += ('{0}={1}' -f $r.Id, $r.Estado)
    }
    $script:AuditCtx = @{}
    $msg = '{0}: aplicado ({1})' -f $Fix.Label, ($after -join ', ')
    if ($Fix.Reboot) { $msg += ' - requiere reinicio' }
    Write-CSWLog $msg -Level Ok
    return @{ Status = 'Applied'; Message = $msg }
}

function Invoke-CSWAuditFixById {
    param([Parameter(Mandatory)][string]$Id)
    if (-not (Test-CSWAdmin)) {
        return (New-CSWAdminRequiredResult 'no se aplico ningun cambio')
    }
    $fix = @($script:AuditFixes | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    $res = Invoke-CSWAuditFixCore -Fix $fix
    switch ($res.Status) {
        'AlreadyOk' { return (New-CSWResult -Summary $res.Message) }
        'Applied'   { return (New-CSWResult -Summary $res.Message) }
        default     { return (New-CSWResult -Summary $res.Message -Status Error) }
    }
}

function Repair-CSWAuditSmbV1           { Invoke-CSWAuditFixById -Id 'FixSmbV1' }
function Repair-CSWAuditAutorun         { Invoke-CSWAuditFixById -Id 'FixAutorun' }
function Repair-CSWAuditLlmnr           { Invoke-CSWAuditFixById -Id 'FixLlmnr' }
function Repair-CSWAuditWDigest         { Invoke-CSWAuditFixById -Id 'FixWDigest' }
function Repair-CSWAuditGuestAccount    { Invoke-CSWAuditFixById -Id 'FixGuestAccount' }
function Repair-CSWAuditFirewallProfile { Invoke-CSWAuditFixById -Id 'FixFirewallProfiles' }
function Repair-CSWAuditUac             { Invoke-CSWAuditFixById -Id 'FixUac' }
function Repair-CSWAuditAuditPolicy     { Invoke-CSWAuditFixById -Id 'FixAuditPolicy' }
function Repair-CSWAuditPowerShellLog   { Invoke-CSWAuditFixById -Id 'FixPowerShellLogging' }
function Repair-CSWAuditAutoLogon       { Invoke-CSWAuditFixById -Id 'FixAutoLogon' }

function Invoke-CSWAuditBaseline {
    if (-not (Test-CSWAdmin)) {
        return (New-CSWAdminRequiredResult 'no se aplico ningun cambio')
    }
    Write-CSWLog 'Aplicando linea base recomendada (solo controles que no cumplen)...' -Level Step
    $applied = @(); $ok = @(); $err = @(); $reboot = @()
    foreach ($fix in $script:AuditFixes) {
        Write-CSWLog ('--- {0} ---' -f $fix.Label) -Level Step
        $r = Invoke-CSWAuditFixCore -Fix $fix
        switch ($r.Status) {
            'Applied'   { $applied += $fix.Label; if ($fix.Reboot) { $reboot += $fix.Label } }
            'AlreadyOk' { $ok += $fix.Label }
            default     { $err += $fix.Label }
        }
    }
    [pscustomobject]@{ Resultado = 'Aplicadas'; Elementos = $(if ($applied.Count) { $applied -join ', ' } else { '-' }) }
    [pscustomobject]@{ Resultado = 'Ya cumplian'; Elementos = $(if ($ok.Count) { $ok -join ', ' } else { '-' }) }
    [pscustomobject]@{ Resultado = 'Con error'; Elementos = $(if ($err.Count) { $err -join ', ' } else { '-' }) }
    [pscustomobject]@{ Resultado = 'Requieren reinicio'; Elementos = $(if ($reboot.Count) { $reboot -join ', ' } else { '-' }) }
    $sum = 'Linea base: {0} correcciones aplicadas, {1} ya cumplian, {2} con error' -f $applied.Count, $ok.Count, $err.Count
    if ($reboot.Count) { $sum += ('. Reiniciar para completar: ' + ($reboot -join ', ')) }
    $st = 'OK'
    if ($err.Count) { $st = 'Warn' }
    if ($err.Count -and -not $applied.Count -and -not $ok.Count) { $st = 'Error' }
    New-CSWResult -Summary $sum -Status $st
}

# ---------------------------------------------------------------------------
# Registro del modulo
# ---------------------------------------------------------------------------
$script:AuditFixCommon = ' Solo se aplica si el control no cumple; el valor previo queda en el registro de la sesion.'

Register-CSWModule -Id 'SecurityAudit' -Name 'Auditoría de ciberseguridad' -Order 55 -Icon 'audit' `
    -Description 'Checklist de buenas prácticas de ciberseguridad con puntuación, informe y remediaciones seguras' -Actions @(
    @{ Id = 'FullAudit'; Name = 'Auditoría completa'; Command = 'Invoke-CSWAuditFull'; LongRunning = $true
        Description = 'Evalúa todos los controles, calcula la puntuación y genera informe HTML y CSV' }
    @{ Id = 'AuditCategory'; Name = 'Auditar una categoría'; Command = 'Invoke-CSWAuditCategory'
        Description = 'Evalúa solo los controles de la categoría elegida'
        Inputs = @(@{ Name = 'Category'; Label = 'Categoría'; Type = 'Choice'; Choices = $script:AuditCategories; Default = $script:AuditCategories[0] }) }
    @{ Id = 'QuickPosture'; Name = 'Postura rápida'; Command = 'Invoke-CSWAuditQuickPosture'
        Description = 'Evalúa solo los controles de severidad Crítica y Alta' }
    @{ Id = 'ListControls'; Name = 'Ver catálogo de controles'; Command = 'Get-CSWAuditControlList'
        Description = 'Lista los controles del checklist sin ejecutarlos' }
    @{ Id = 'ExportAudit'; Name = 'Exportar última auditoría'; Command = 'Export-CSWAuditLast'
        Description = 'Exporta el último resultado de auditoría a CSV y JSON' }
    @{ Id = 'FixSmbV1'; Name = 'Corregir: deshabilitar SMBv1'; Command = 'Repair-CSWAuditSmbV1'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Deshabilita el protocolo SMBv1 (servidor y característica)'
        ConfirmMessage = ('Deshabilita SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false y quita la característica SMB1Protocol. Impacto: NAS, impresoras/escáneres o equipos muy antiguos (XP/2003) que solo hablan SMBv1 dejarán de acceder a carpetas compartidas. Requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixAutorun'; Name = 'Corregir: deshabilitar AutoRun'; Command = 'Repair-CSWAuditAutorun'; Risk = 'High'; ModifiesSystem = $true
        Description = 'NoDriveTypeAutoRun=255 en HKLM'
        ConfirmMessage = ('Establece HKLM\...\Policies\Explorer\NoDriveTypeAutoRun=255: AutoRun/AutoPlay deja de ejecutarse en todas las unidades (USB, CD, red). Impacto: al insertar un USB o CD no se abrirá nada automáticamente. Efectivo en el siguiente inicio de sesión.' + $script:AuditFixCommon) }
    @{ Id = 'FixLlmnr'; Name = 'Corregir: deshabilitar LLMNR'; Command = 'Repair-CSWAuditLlmnr'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Política DNSClient EnableMulticast=0'
        ConfirmMessage = ('Establece HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0. Impacto: los nombres de equipos de la red local ya no se resolverán por LLMNR (se usará DNS/NetBIOS); en redes sin DNS local algún recurso podría necesitar IP. No requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixWDigest'; Name = 'Corregir: WDigest sin texto claro'; Command = 'Repair-CSWAuditWDigest'; Risk = 'High'; ModifiesSystem = $true
        Description = 'WDigest UseLogonCredential=0'
        ConfirmMessage = ('Establece HKLM\SYSTEM\...\SecurityProviders\WDigest\UseLogonCredential=0 para que Windows no guarde contraseñas en memoria en texto claro. Impacto: solo afecta a aplicaciones muy antiguas que usen autenticación Digest. Efectivo tras reinicio/nuevo inicio de sesión.' + $script:AuditFixCommon) }
    @{ Id = 'FixGuestAccount'; Name = 'Corregir: deshabilitar Invitado'; Command = 'Repair-CSWAuditGuestAccount'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Deshabilita la cuenta Invitado (SID terminado en -501)'
        ConfirmMessage = ('Deshabilita la cuenta local Invitado (identificada por SID -501). Impacto: nadie podrá iniciar sesión ni acceder a recursos compartidos como Invitado. No requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixFirewallProfiles'; Name = 'Corregir: activar firewall'; Command = 'Repair-CSWAuditFirewallProfile'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Activa el firewall en los perfiles Dominio, Privado y Público'
        ConfirmMessage = ('Activa el Firewall de Windows en los perfiles Dominio, Privado y Público (Set-NetFirewallProfile -Enabled True). Impacto: servicios que dependan de puertos abiertos sin regla podrían dejar de ser accesibles desde la red. Si una GPO lo desactiva, prevalecerá la GPO. No requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixUac'; Name = 'Corregir: configurar UAC'; Command = 'Repair-CSWAuditUac'; Risk = 'High'; ModifiesSystem = $true
        Description = 'EnableLUA=1, ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1'
        ConfirmMessage = ('Establece en HKLM\...\Policies\System: EnableLUA=1, ConsentPromptBehaviorAdmin=5 y PromptOnSecureDesktop=1 (valores por defecto seguros de Windows). Impacto: volverán a aparecer las solicitudes de elevación de UAC. Si UAC estaba desactivado, requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixAuditPolicy'; Name = 'Corregir: política de auditoría'; Command = 'Repair-CSWAuditAuditPolicy'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Habilita éxito/error en Logon, Logoff, Account Lockout, Process Creation y Security Group Management'
        ConfirmMessage = ('Ejecuta auditpol /set /subcategory:{GUID} /success:enable /failure:enable para Inicio/cierre de sesión, Bloqueo de cuenta, Creación de procesos y Administración de grupos de seguridad. Impacto: el registro de Seguridad crecerá más rápido (se recomienda ampliarlo). Una GPO de dominio puede sobrescribirlo. No requiere reinicio.' + $script:AuditFixCommon) }
    @{ Id = 'FixPowerShellLogging'; Name = 'Corregir: registro de PowerShell'; Command = 'Repair-CSWAuditPowerShellLog'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Habilita Script Block Logging'
        ConfirmMessage = ('Establece HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1. Impacto: el contenido de los scripts de PowerShell ejecutados se registrará en el visor de eventos (Microsoft-Windows-PowerShell/Operational). Efectivo en nuevas sesiones de PowerShell.' + $script:AuditFixCommon) }
    @{ Id = 'FixAutoLogon'; Name = 'Corregir: quitar inicio automático'; Command = 'Repair-CSWAuditAutoLogon'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Quita AutoAdminLogon y la contraseña DefaultPassword en texto plano'
        ConfirmMessage = ('Establece Winlogon\AutoAdminLogon=0 y elimina Winlogon\DefaultPassword (contraseña en texto plano). Impacto: el equipo pedirá usuario y contraseña al iniciar; asegúrese de que el cliente conoce su contraseña. Se recomienda cambiar la contraseña expuesta.' + $script:AuditFixCommon) }
    @{ Id = 'ApplyRecommendedBaseline'; Name = 'Aplicar línea base recomendada'; Command = 'Invoke-CSWAuditBaseline'; Risk = 'High'; ModifiesSystem = $true; LongRunning = $true
        Description = 'Aplica en secuencia solo las correcciones cuyos controles no cumplen'
        ConfirmMessage = 'Evalúa y aplica SOLO las correcciones necesarias: SMBv1, AutoRun, LLMNR, WDigest, cuenta Invitado, firewall (3 perfiles), UAC, política de auditoría, registro de PowerShell e inicio de sesión automático. Impacto: ver cada corrección individual (dispositivos SMBv1 antiguos, resolución LLMNR, inicio automático). SMBv1, WDigest y UAC pueden requerir reinicio. Cada valor previo queda en el registro de la sesión.' }
)

Export-ModuleMember -Function *
