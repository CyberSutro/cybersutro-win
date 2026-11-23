#Requires -Version 5.1
<#
    Cybersutro win - Modulo UsersBackup (Usuarios y backup)
    Cuentas locales, perfiles, copia/restauracion de datos de usuario, drivers y clave de producto.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
    IMPORTANTE: las contrasenas recibidas como parametro NUNCA se escriben en el log.
#>

Set-StrictMode -Version 2.0

$script:UsersSidAdmins = 'S-1-5-32-544'
$script:UsersSidUsers  = 'S-1-5-32-545'

# Carpetas conocidas: nombre en el backup -> valor en "User Shell Folders" y carpeta por defecto
$script:UsersKnownFolders = @(
    @{ Name = 'Desktop';   Reg = 'Desktop';                                Default = 'Desktop' },
    @{ Name = 'Documents'; Reg = 'Personal';                               Default = 'Documents' },
    @{ Name = 'Downloads'; Reg = '{374DE290-123F-4565-9164-39C4925E467B}'; Default = 'Downloads' },
    @{ Name = 'Pictures';  Reg = 'My Pictures';                            Default = 'Pictures' },
    @{ Name = 'Music';     Reg = 'My Music';                               Default = 'Music' },
    @{ Name = 'Videos';    Reg = 'My Video';                               Default = 'Videos' },
    @{ Name = 'Favorites'; Reg = 'Favorites';                              Default = 'Favorites' }
)

$script:UsersBrowsers = @(
    @{ Name = 'Chrome'; Root = 'AppData\Local\Google\Chrome\User Data';  Process = 'chrome' },
    @{ Name = 'Edge';   Root = 'AppData\Local\Microsoft\Edge\User Data'; Process = 'msedge' }
)

$script:UsersRoboOpts = '/E /R:1 /W:1 /XJ /MT:8 /NP /NFL /NDL'

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

function ConvertTo-CSWUsersBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int]) { return ($Value -ne 0) }
    return ([string]$Value).Trim() -match '^(true|1|s|si|y|yes|\$true)$'
}

function ConvertTo-CSWUsersSecure {
    param($Password)
    if ($Password -is [System.Security.SecureString]) { return $Password }
    return (ConvertTo-SecureString -String ([string]$Password) -AsPlainText -Force)
}

function Test-CSWUsersPasswordEmpty {
    param($Password)
    if ($null -eq $Password) { return $true }
    if ($Password -is [System.Security.SecureString]) { return ($Password.Length -eq 0) }
    return ([string]$Password).Length -eq 0
}

function Get-CSWUsersProp {
    # Lectura segura de propiedades (StrictMode lanza si no existen); admite hashtables
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-CSWUsersLocalCmdlets {
    return [bool](Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)
}

function Get-CSWUsersGroupName {
    param([Parameter(Mandatory)][string]$Sid)
    try {
        $n = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        return ($n -split '\\')[-1]
    }
    catch { return $null }
}

function Get-CSWUsersAdminSids {
    <# SIDs de los miembros del grupo Administradores (S-1-5-32-544), independiente del idioma. #>
    $sids = New-Object System.Collections.ArrayList
    $done = $false
    if (Get-Command -Name Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            Get-LocalGroupMember -SID $script:UsersSidAdmins -ErrorAction Stop | ForEach-Object { if ($_.SID) { [void]$sids.Add($_.SID.Value) } }
            $done = $true
        }
        catch { }   # Falla conocida con miembros huerfanos o de Azure AD: se usa ADSI
    }
    if (-not $done) {
        $gname = Get-CSWUsersGroupName -Sid $script:UsersSidAdmins
        if ($gname) {
            try {
                $g = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $gname)
                foreach ($m in @($g.psbase.Invoke('Members'))) {
                    try {
                        $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                        [void]$sids.Add((New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value)
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
    return @($sids)
}

function Get-CSWUsersSidName {
    param([string]$Sid)
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return '' }
}

function Get-CSWUsersLocalUserObj {
    param([Parameter(Mandatory)][string]$UserName)
    if (-not (Test-CSWUsersLocalCmdlets)) { return $null }
    return (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)
}

function Add-CSWUsersToGroup {
    <# Agrega un usuario local a un grupo identificado por SID (Get-LocalGroupMember/ADSI). #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$GroupSid)
    try {
        Add-LocalGroupMember -SID $GroupSid -Member $UserName -ErrorAction Stop
        return $true
    }
    catch {
        if ($_.Exception.Message -match 'already|ya es miembro') { return $true }
        $gname = Get-CSWUsersGroupName -Sid $GroupSid
        if (-not $gname) { return $false }
        try {
            $g = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $gname)
            $g.psbase.Invoke('Add', ("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $UserName))
            return $true
        }
        catch {
            if ($_.Exception.ToString() -match '0x80070562|already|ya es miembro') { return $true }
            return $false
        }
    }
}

function Test-CSWUsersValidName {
    param([string]$UserName)
    if (-not $UserName -or $UserName.Length -gt 20) { return $false }
    if ($UserName -match '["/\\\[\]:;|=,+*?<>@]') { return $false }
    if ($UserName.Trim('. ') -eq '') { return $false }
    return $true
}

function Get-CSWUsersProfileInfo {
    <# Localiza el perfil (ruta, SID, cargado) de un usuario local, de dominio o de cuenta Microsoft. #>
    param([Parameter(Mandatory)][string]$UserName)
    $sid = $null
    try { $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=FALSE' -ErrorAction Stop)
    $p = $null
    if ($sid) { $p = @($profiles | Where-Object { $_.SID -eq $sid }) | Select-Object -First 1 }
    if (-not $p) {
        $leaf = ($UserName -split '\\')[-1]
        $p = @($profiles | Where-Object { $_.LocalPath -and ((Split-Path -Leaf $_.LocalPath) -eq $leaf) }) | Select-Object -First 1
        if (-not $p) { $p = @($profiles | Where-Object { $_.LocalPath -and ((Split-Path -Leaf $_.LocalPath) -like "$leaf.*") }) | Select-Object -First 1 }
    }
    if (-not $p) { return $null }
    return [pscustomobject]@{ Sid = $p.SID; Path = $p.LocalPath; Loaded = [bool]$p.Loaded; Name = (Get-CSWUsersSidName $p.SID) }
}

function Get-CSWUsersShellFolders {
    <#
        Devuelve un hashtable Nombre -> ruta real de las carpetas conocidas del usuario,
        leyendo "User Shell Folders" de su colmena (cargada o montada temporalmente).
    #>
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$ProfilePath)
    $result = @{}
    foreach ($kf in $script:UsersKnownFolders) { $result[$kf.Name] = Join-Path $ProfilePath $kf.Default }

    $sub = 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $hiveName = $null
    $root = $Sid
    $hku = [Microsoft.Win32.Registry]::Users
    $test = $hku.OpenSubKey($Sid)
    if ($test) { $test.Close() }
    else {
        $ntuser = Join-Path $ProfilePath 'NTUSER.DAT'
        if ((Test-CSWAdmin) -and (Test-Path -LiteralPath $ntuser)) {
            $hiveName = 'CSW_TMP_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
            $code = Invoke-CSWExternal -FilePath 'reg.exe' -Arguments ("load HKU\{0} `"{1}`"" -f $hiveName, $ntuser)
            if ($code -ne 0) { $hiveName = $null; Write-CSWLog 'No se pudo leer la configuracion de carpetas del usuario; se asumen rutas por defecto.' -Level Warn; return $result }
            $root = $hiveName
        }
        else { return $result }
    }
    try {
        $key = $hku.OpenSubKey("$root\$sub")
        if ($key) {
            foreach ($kf in $script:UsersKnownFolders) {
                $raw = $key.GetValue($kf.Reg, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($raw) {
                    $path = ([string]$raw) -replace '(?i)%USERPROFILE%', $ProfilePath
                    if ($path -notmatch '%USERPROFILE%') { $path = [Environment]::ExpandEnvironmentVariables($path) }
                    $result[$kf.Name] = $path.TrimEnd('\')
                }
            }
            $key.Close()
        }
    }
    finally {
        if ($hiveName) {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $u = Invoke-CSWExternal -FilePath 'reg.exe' -Arguments "unload HKU\$hiveName"
            if ($u -ne 0) { Write-CSWLog "No se pudo desmontar la colmena temporal HKU\$hiveName (se liberara al reiniciar)." -Level Warn }
        }
    }
    return $result
}

function Test-CSWUsersFolderHasContent {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
        $e = [System.IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
        while ($e.MoveNext()) { if ((Split-Path -Leaf $e.Current) -ne 'desktop.ini') { return $true } }
    }
    catch { }
    return $false
}

function Get-CSWUsersFolderSize {
    <# Tamano en bytes recorriendo el arbol sin seguir uniones/enlaces (evita bucles). #>
    param([string]$Path)
    [long]$total = 0
    $stack = New-Object System.Collections.Stack
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        try {
            $di = New-Object System.IO.DirectoryInfo($dir)
            foreach ($f in $di.GetFiles()) { $total += $f.Length }
            foreach ($d in $di.GetDirectories()) {
                if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($d.FullName) }
            }
        }
        catch { }
    }
    return $total
}

function Invoke-CSWUsersRobocopy {
    <# Ejecuta robocopy y devuelve el codigo de salida (0-7 correcto, >=8 error). #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination, [string]$LogFile, [string]$Extra = '')
    $src = $Source.TrimEnd('\'); $dst = $Destination.TrimEnd('\')
    if ($src -match '^[A-Za-z]:$') { $src += '\.' }
    $robocopyArgs = ('"{0}" "{1}" {2} {3}' -f $src, $dst, $script:UsersRoboOpts, $Extra).Trim()
    if ($LogFile) { $robocopyArgs += (' /TEE /LOG+:"{0}"' -f $LogFile) }
    return (Invoke-CSWExternal -FilePath 'robocopy.exe' -Arguments $robocopyArgs)
}

function Get-CSWUsersRobocopyText {
    param([int]$Code)
    if ($Code -ge 16) { return 'error grave (no se copio nada)' }
    if ($Code -ge 8) { return 'algunos archivos no se pudieron copiar' }
    if ($Code -eq 0) { return 'sin cambios' }
    $t = @()
    if ($Code -band 1) { $t += 'archivos copiados' }
    if ($Code -band 2) { $t += 'archivos extra en destino' }
    if ($Code -band 4) { $t += 'diferencias detectadas' }
    return ($t -join ', ')
}

function ConvertFrom-CSWUsersDigitalProductId {
    <# Decodifica la clave instalada a partir de DigitalProductId (Windows 8 y posteriores). #>
    param([byte[]]$DigitalProductId)
    if (-not $DigitalProductId -or $DigitalProductId.Length -lt 67) { return $null }
    $chars = 'BCDFGHJKMPQRTVWXY2346789'
    $key = New-Object 'int[]' 15
    for ($i = 0; $i -lt 15; $i++) { $key[$i] = [int]$DigitalProductId[52 + $i] }
    $isWin8 = [int]([math]::Floor($DigitalProductId[66] / 6)) -band 1
    $key[14] = ($key[14] -band 0xF7)
    $out = ''
    $last = 0
    for ($j = 24; $j -ge 0; $j--) {
        $cur = 0
        for ($y = 14; $y -ge 0; $y--) {
            $cur = $cur * 256 + $key[$y]
            $key[$y] = [int][math]::Floor($cur / 24)
            $cur = $cur % 24
        }
        $out = $chars[$cur] + $out
        $last = $cur
    }
    if ($isWin8 -eq 1) {
        $s = $out.Substring(1)
        $out = $s.Substring(0, $last) + 'N' + $s.Substring($last)
    }
    return ('{0}-{1}-{2}-{3}-{4}' -f $out.Substring(0, 5), $out.Substring(5, 5), $out.Substring(10, 5), $out.Substring(15, 5), $out.Substring(20, 5))
}

function Get-CSWUsersMaskedKey {
    param([string]$Key)
    if (-not $Key -or $Key.Length -lt 5) { return '(vacia)' }
    return ('XXXXX-XXXXX-XXXXX-XXXXX-' + $Key.Substring($Key.Length - 5))
}

# ---------------------------------------------------------------------------
# Usuarios locales
# ---------------------------------------------------------------------------

function Get-CSWUsersLocal {
    Write-CSWLog 'Consultando cuentas locales...' -Level Info
    $adminSids = Get-CSWUsersAdminSids
    $cimUsers = @()
    try { $cimUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=TRUE' -ErrorAction Stop) } catch { }
    $rows = New-Object System.Collections.ArrayList

    if (Test-CSWUsersLocalCmdlets) {
        foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
            $sid = $u.SID.Value
            $cim = @($cimUsers | Where-Object { $_.SID -eq $sid }) | Select-Object -First 1
            $expires = 'Nunca'
            if ($u.PasswordExpires) { $expires = $u.PasswordExpires.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
            $last = 'Nunca'
            if ($u.LastLogon) { $last = $u.LastLogon.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
            [void]$rows.Add([pscustomobject]@{
                    Usuario      = $u.Name
                    Habilitado   = $(if ($u.Enabled) { 'Si' } else { 'No' })
                    Admin        = $(if ($adminSids -contains $sid) { 'Si' } else { 'No' })
                    UltimoInicio = $last
                    PwdExpira    = $expires
                    Bloqueada    = $(if ($cim -and $cim.Lockout) { 'Si' } else { 'No' })
                    Origen       = [string]$u.PrincipalSource
                    Descripcion  = $u.Description
                })
        }
    }
    else {
        Write-CSWLog 'Cmdlets LocalAccounts no disponibles; se usa WMI (Win32_UserAccount).' -Level Warn
        foreach ($c in $cimUsers) {
            [void]$rows.Add([pscustomobject]@{
                    Usuario      = $c.Name
                    Habilitado   = $(if ($c.Disabled) { 'No' } else { 'Si' })
                    Admin        = $(if ($adminSids -contains $c.SID) { 'Si' } else { 'No' })
                    UltimoInicio = '?'
                    PwdExpira    = $(if ($c.PasswordExpires) { 'Si' } else { 'No' })
                    Bloqueada    = $(if ($c.Lockout) { 'Si' } else { 'No' })
                    Origen       = 'Local'
                    Descripcion  = $c.Description
                })
        }
    }
    if ($rows.Count -eq 0) { return (New-CSWResult -Summary 'No se encontraron cuentas locales.' -Status Warn) }
    $rows | Write-CSWOutput

    # Miembros administradores que no son cuentas locales (dominio, Azure AD, huerfanos)
    $localSids = @($cimUsers | ForEach-Object { $_.SID })
    $others = @($adminSids | Where-Object { $localSids -notcontains $_ })
    if ($others.Count) {
        $names = foreach ($s in $others) { $n = Get-CSWUsersSidName $s; if ($n) { $n } else { "$s (huerfano)" } }
        Write-CSWLog ("Otros miembros de Administradores: {0}" -f ($names -join ', ')) -Level Info
    }

    $enabled = @($rows | Where-Object { $_.Habilitado -eq 'Si' })
    $admins = @($enabled | Where-Object { $_.Admin -eq 'Si' })
    $locked = @($rows | Where-Object { $_.Bloqueada -eq 'Si' })
    $summary = "{0} cuenta(s) local(es), {1} habilitada(s), {2} administrador(es) habilitado(s)" -f $rows.Count, $enabled.Count, $admins.Count
    $status = 'OK'
    if ($locked.Count) { $summary += "; bloqueada(s): $(($locked | ForEach-Object { $_.Usuario }) -join ', ')"; $status = 'Warn' }
    return (New-CSWResult -Summary $summary -Status $status)
}

function Get-CSWUsersProfiles {
    param([object]$IncludeSize = $false)
    $withSize = ConvertTo-CSWUsersBool $IncludeSize
    Write-CSWLog 'Consultando perfiles de usuario...' -Level Info
    try { $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=FALSE' -ErrorAction Stop) }
    catch { return (New-CSWResult -Summary "No se pudo consultar los perfiles: $($_.Exception.Message)" -Status Error) }

    # Entradas del registro: claves .bak (perfil danado) y perfiles TEMP
    $plRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $bakSids = @()
    $regInfo = @{}
    foreach ($k in @(Get-ChildItem -Path $plRoot -ErrorAction SilentlyContinue)) {
        $name = $k.PSChildName
        $img = $null; $state = $null
        try { $img = $k.GetValue('ProfileImagePath'); $state = $k.GetValue('State') } catch { }
        if ($name -like '*.bak') { $bakSids += ($name -replace '\.bak$', '') }
        $regInfo[$name] = @{ Path = $img; State = $state }
    }

    $problems = 0
    $rows = foreach ($p in $profiles) {
        $flags = @()
        $st = [int]$p.Status
        if ($st -band 1) { $flags += 'TEMPORAL' }
        if ($st -band 2) { $flags += 'Movil' }
        if ($st -band 4) { $flags += 'Obligatorio' }
        if ($st -band 8) { $flags += 'CORRUPTO' }
        if ($bakSids -contains $p.SID) { $flags += 'CLAVE .BAK (perfil danado)' }
        if ($p.LocalPath -match '\\TEMP(\.|$)') { $flags += 'RUTA TEMP' }
        if (-not (Test-Path -LiteralPath $p.LocalPath)) { $flags += 'CARPETA NO EXISTE' }
        if (-not $regInfo.ContainsKey($p.SID)) { $flags += 'SIN CLAVE EN ProfileList' }
        $isBad = @($flags | Where-Object { @('Movil', 'Obligatorio') -notcontains $_ }).Count -gt 0
        if ($isBad) { $problems++ }
        $owner = Get-CSWUsersSidName $p.SID
        if (-not $owner) { $owner = '(SID huerfano)' }
        $last = ''
        if ($p.LastUseTime) { $last = $p.LastUseTime.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
        $o = [ordered]@{
            Usuario  = $owner
            Ruta     = $p.LocalPath
            UltimoUso = $last
            Cargado  = $(if ($p.Loaded) { 'Si' } else { 'No' })
            Estado   = $(if ($flags.Count) { $flags -join '; ' } else { 'Normal' })
        }
        if ($withSize) {
            Write-CSWLog "Calculando tamano de $($p.LocalPath)..." -Level Info
            $o['TamanoGB'] = [math]::Round((Get-CSWUsersFolderSize -Path $p.LocalPath) / 1GB, 2)
        }
        [pscustomobject]$o
    }

    # Claves .bak cuyo SID no tiene perfil en WMI
    foreach ($b in $bakSids) {
        if (-not (@($profiles | Where-Object { $_.SID -eq $b }))) {
            Write-CSWLog ("Clave de perfil .bak sin perfil activo: {0} -> {1}" -f $b, $regInfo["$b.bak"].Path) -Level Warn
            $problems++
        }
    }
    @($rows) | Sort-Object Usuario | Write-CSWOutput
    if ($bakSids.Count) {
        Write-CSWLog 'Se detectaron claves .bak en ProfileList: Windows suele iniciar con un perfil TEMPORAL cuando ocurre esto.' -Level Warn
    }
    $summary = "{0} perfil(es) de usuario" -f @($rows).Count
    if ($problems -gt 0) { return (New-CSWResult -Summary "$summary; $problems con problemas (temporal/corrupto/.bak)." -Status Warn) }
    return (New-CSWResult -Summary "$summary, sin problemas detectados.")
}

function New-CSWUsersLocal {
    param([string]$UserName = '', [object]$Password = '', [object]$IsAdmin = $false)
    $UserName = ([string]$UserName).Trim()
    $admin = ConvertTo-CSWUsersBool $IsAdmin
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    if (-not (Test-CSWUsersLocalCmdlets)) { return (New-CSWResult -Summary 'Los cmdlets de cuentas locales no estan disponibles en este Windows.' -Status Warn) }
    if (-not (Test-CSWUsersValidName $UserName)) { return (New-CSWResult -Summary "Nombre de usuario '$UserName' no valido (max. 20 caracteres, sin \ / [ ] : ; | = , + * ? < > @ `")." -Status Error) }
    if (Test-CSWUsersPasswordEmpty $Password) { return (New-CSWResult -Summary 'Debe indicar una contrasena para el nuevo usuario.' -Status Error) }
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) { return (New-CSWResult -Summary "El usuario '$UserName' ya existe." -Status Error) }

    Write-CSWLog "Creando usuario local '$UserName' (administrador: $(if ($admin) { 'si' } else { 'no' }))..." -Level Step
    try {
        $sec = ConvertTo-CSWUsersSecure $Password
        [void](New-LocalUser -Name $UserName -Password $sec -AccountNeverExpires -Description 'Creado con Cybersutro win' -ErrorAction Stop)
    }
    catch {
        # El mensaje de error nunca contiene la contrasena
        return (New-CSWResult -Summary "No se pudo crear el usuario: $($_.Exception.Message)" -Status Error)
    }
    Write-CSWLog 'Usuario creado (la contrasena no se registra en el log).' -Level Ok
    $warn = $false
    if (Add-CSWUsersToGroup -UserName $UserName -GroupSid $script:UsersSidUsers) { Write-CSWLog "Agregado al grupo $(Get-CSWUsersGroupName $script:UsersSidUsers)." -Level Info }
    else { $warn = $true; Write-CSWLog 'No se pudo agregar al grupo Usuarios.' -Level Warn }
    if ($admin) {
        if (Add-CSWUsersToGroup -UserName $UserName -GroupSid $script:UsersSidAdmins) { Write-CSWLog "Agregado al grupo $(Get-CSWUsersGroupName $script:UsersSidAdmins)." -Level Info }
        else { $warn = $true; Write-CSWLog 'No se pudo agregar al grupo Administradores.' -Level Warn }
    }
    $kind = 'estandar'
    if ($admin) { $kind = 'administrador' }
    if ($warn) { return (New-CSWResult -Summary "Usuario '$UserName' creado, pero hubo problemas con los grupos." -Status Warn) }
    return (New-CSWResult -Summary "Usuario local '$UserName' ($kind) creado. El perfil se generara en el primer inicio de sesion.")
}

function Reset-CSWUsersPassword {
    param([string]$UserName = '', [object]$Password = '')
    $UserName = ([string]$UserName).Trim()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    if (-not (Test-CSWUsersLocalCmdlets)) { return (New-CSWResult -Summary 'Los cmdlets de cuentas locales no estan disponibles en este Windows.' -Status Warn) }
    if (-not $UserName) { return (New-CSWResult -Summary 'Debe indicar el usuario.' -Status Error) }
    $u = Get-CSWUsersLocalUserObj -UserName $UserName
    if (-not $u) { return (New-CSWResult -Summary "No existe el usuario local '$UserName'." -Status Error) }
    if ([string]$u.PrincipalSource -eq 'MicrosoftAccount') {
        return (New-CSWResult -Summary "'$UserName' es una cuenta Microsoft: la contrasena se restablece en account.live.com, no localmente." -Status Warn)
    }
    if (Test-CSWUsersPasswordEmpty $Password) { return (New-CSWResult -Summary 'Debe indicar la nueva contrasena.' -Status Error) }
    Write-CSWLog "Restableciendo la contrasena de '$UserName' (la contrasena no se registra)..." -Level Step
    try {
        Set-LocalUser -Name $UserName -Password (ConvertTo-CSWUsersSecure $Password) -ErrorAction Stop
    }
    catch { return (New-CSWResult -Summary "No se pudo restablecer la contrasena: $($_.Exception.Message)" -Status Error) }
    Write-CSWLog 'Aviso: archivos cifrados con EFS y credenciales guardadas del usuario pueden quedar inaccesibles.' -Level Warn
    try {
        $cim = Get-CimInstance -ClassName Win32_UserAccount -Filter ("LocalAccount=TRUE AND Name='{0}'" -f $UserName.Replace("'", "''")) -ErrorAction Stop
        if ($cim -and $cim.Lockout) { Write-CSWLog 'La cuenta esta BLOQUEADA; use "Desbloquear cuenta".' -Level Warn }
    }
    catch { }
    if (-not $u.Enabled) { Write-CSWLog 'La cuenta esta deshabilitada.' -Level Warn }
    return (New-CSWResult -Summary "Contrasena del usuario '$UserName' restablecida.")
}

function Set-CSWUsersEnabled {
    param([string]$UserName = '', [object]$Enable = $true)
    $UserName = ([string]$UserName).Trim()
    $en = ConvertTo-CSWUsersBool $Enable
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    if (-not (Test-CSWUsersLocalCmdlets)) { return (New-CSWResult -Summary 'Los cmdlets de cuentas locales no estan disponibles en este Windows.' -Status Warn) }
    $u = Get-CSWUsersLocalUserObj -UserName $UserName
    if (-not $u) { return (New-CSWResult -Summary "No existe el usuario local '$UserName'." -Status Error) }
    if ($u.Enabled -eq $en) {
        return (New-CSWResult -Summary ("El usuario '{0}' ya estaba {1}." -f $UserName, $(if ($en) { 'habilitado' } else { 'deshabilitado' })))
    }
    if (-not $en) {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($u.SID.Value -eq $me) { return (New-CSWResult -Summary 'No se puede deshabilitar la cuenta con la que se esta trabajando.' -Status Error) }
        $adminSids = Get-CSWUsersAdminSids
        if ($adminSids -contains $u.SID.Value) {
            $enabledAdmins = @(Get-LocalUser | Where-Object { $_.Enabled -and ($adminSids -contains $_.SID.Value) })
            if ($enabledAdmins.Count -le 1) { return (New-CSWResult -Summary "'$UserName' es el unico administrador local habilitado; no se deshabilita." -Status Error) }
        }
    }
    try {
        if ($en) { Enable-LocalUser -Name $UserName -ErrorAction Stop } else { Disable-LocalUser -Name $UserName -ErrorAction Stop }
    }
    catch { return (New-CSWResult -Summary "No se pudo cambiar el estado de '$UserName': $($_.Exception.Message)" -Status Error) }
    return (New-CSWResult -Summary ("Usuario '{0}' {1}." -f $UserName, $(if ($en) { 'habilitado' } else { 'deshabilitado' })))
}

function Unlock-CSWUsersAccount {
    param([string]$UserName = '')
    $UserName = ([string]$UserName).Trim()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    if (-not $UserName) { return (New-CSWResult -Summary 'Debe indicar el usuario.' -Status Error) }
    # El nombre forma parte de una ruta ADSI: se valida para no poder apuntar a otro objeto
    if (-not (Test-CSWUsersValidName $UserName)) { return (New-CSWResult -Summary "Nombre de usuario '$UserName' no valido." -Status Error) }
    try {
        $u = [ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $UserName)
        [void]$u.psbase.RefreshCache()
        $locked = [bool]$u.psbase.InvokeGet('IsAccountLocked')
        if (-not $locked) { return (New-CSWResult -Summary "La cuenta '$UserName' no estaba bloqueada.") }
        $u.psbase.InvokeSet('IsAccountLocked', $false)
        $u.psbase.CommitChanges()
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        return (New-CSWResult -Summary "No se pudo desbloquear '$UserName': $msg" -Status Error)
    }
    Write-CSWLog 'Revise la directiva de bloqueo (net accounts) si la cuenta se bloquea de nuevo.' -Level Info
    return (New-CSWResult -Summary "Cuenta '$UserName' desbloqueada.")
}

# ---------------------------------------------------------------------------
# Backup / restauracion de perfil
# ---------------------------------------------------------------------------

function Backup-CSWUsersProfile {
    param([string]$UserName = '', [string]$Destination = '')
    $UserName = ([string]$UserName).Trim()
    if (-not $UserName) { return (New-CSWResult -Summary 'Debe indicar el usuario a respaldar.' -Status Error) }
    if (-not ([string]$Destination).Trim()) { $Destination = Get-CSWDataPath Backups }
    if (-not (Test-CSWAdmin)) { Write-CSWLog 'Sin permisos de administrador: puede que no se lean todos los archivos de otro usuario.' -Level Warn }

    try { $prof = Get-CSWUsersProfileInfo -UserName $UserName }
    catch { return (New-CSWResult -Summary "No se pudo consultar los perfiles: $($_.Exception.Message)" -Status Error) }
    if (-not $prof -or -not (Test-Path -LiteralPath $prof.Path)) { return (New-CSWResult -Summary "No se encontro el perfil del usuario '$UserName'." -Status Error) }
    Write-CSWLog "Perfil: $($prof.Path) (SID $($prof.Sid))" -Level Info
    if ($prof.Loaded) { Write-CSWLog 'El usuario tiene la sesion iniciada: los archivos abiertos (ej. PST de Outlook) podrian no copiarse.' -Level Warn }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $leaf = Split-Path -Leaf $prof.Path
    $target = Join-Path $Destination ("Perfil_{0}_{1}_{2}" -f $leaf, $env:COMPUTERNAME, $stamp)
    if ($target.StartsWith($prof.Path.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        return (New-CSWResult -Summary 'El destino no puede estar dentro del perfil que se respalda.' -Status Error)
    }
    try { New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null }
    catch { return (New-CSWResult -Summary "No se pudo crear la carpeta de destino: $($_.Exception.Message)" -Status Error) }
    $log = Join-Path $target 'robocopy.log'
    Write-CSWLog "Destino del backup: $target" -Level Info

    $folders = Get-CSWUsersShellFolders -Sid $prof.Sid -ProfilePath $prof.Path
    $items = New-Object System.Collections.ArrayList
    $results = New-Object System.Collections.ArrayList
    $oneDrive = @()
    $worst = 0

    foreach ($kf in $script:UsersKnownFolders) {
        $src = $folders[$kf.Name]
        $default = Join-Path $prof.Path $kf.Default
        $list = @(@{ Name = $kf.Name; Path = $src })
        if ($src -match '\\OneDrive') {
            $oneDrive += $kf.Name
            Write-CSWLog "$($kf.Name) esta redirigida a OneDrive: $src. Los archivos 'solo en la nube' no estan en el disco y no se copiaran salvo que se descarguen." -Level Warn
        }
        if ($src.TrimEnd('\') -ne $default -and (Test-CSWUsersFolderHasContent $default)) {
            $list += @{ Name = "$($kf.Name)_local"; Path = $default }
        }
        foreach ($entry in $list) {
            if (-not (Test-Path -LiteralPath $entry.Path -PathType Container)) {
                Write-CSWLog "$($entry.Name): no existe ($($entry.Path)), se omite." -Level Info
                continue
            }
            Write-CSWLog "Copiando $($entry.Name) desde $($entry.Path)..." -Level Step
            $rel = "Carpetas\$($entry.Name)"
            $code = Invoke-CSWUsersRobocopy -Source $entry.Path -Destination (Join-Path $target $rel) -LogFile $log
            if ($code -gt $worst) { $worst = $code }
            [void]$results.Add([pscustomobject]@{ Elemento = $entry.Name; Origen = $entry.Path; Codigo = $code; Resultado = (Get-CSWUsersRobocopyText $code) })
            [void]$items.Add(@{ Type = 'Folder'; Name = $entry.Name; Folder = $kf.Name; Source = $entry.Path; Relative = $rel; Code = $code })
        }
    }

    # Marcadores de navegadores (todos los perfiles del navegador)
    foreach ($b in $script:UsersBrowsers) {
        $root = Join-Path $prof.Path $b.Root
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
            $bm = Join-Path $d.FullName 'Bookmarks'
            if (-not (Test-Path -LiteralPath $bm)) { continue }
            $rel = "Navegadores\$($b.Name)\$($d.Name)"
            try {
                $dst = Join-Path $target $rel
                New-Item -ItemType Directory -Path $dst -Force | Out-Null
                Copy-Item -LiteralPath $bm -Destination $dst -Force -ErrorAction Stop
                Write-CSWLog "Marcadores de $($b.Name) ($($d.Name)) copiados." -Level Ok
                [void]$results.Add([pscustomobject]@{ Elemento = "$($b.Name) marcadores"; Origen = $bm; Codigo = 1; Resultado = 'copiado' })
                [void]$items.Add(@{ Type = 'Bookmarks'; Name = $b.Name; Profile = $d.Name; Source = $bm; Relative = "$rel\Bookmarks"; Code = 1 })
            }
            catch {
                $worst = [math]::Max($worst, 8)
                Write-CSWLog "No se pudieron copiar los marcadores de $($b.Name): $($_.Exception.Message)" -Level Warn
            }
        }
    }

    # Firmas de Outlook
    $sig = Join-Path $prof.Path 'AppData\Roaming\Microsoft\Signatures'
    if (Test-Path -LiteralPath $sig) {
        Write-CSWLog 'Copiando firmas de Outlook...' -Level Step
        $code = Invoke-CSWUsersRobocopy -Source $sig -Destination (Join-Path $target 'Outlook\Signatures') -LogFile $log
        if ($code -gt $worst) { $worst = $code }
        [void]$results.Add([pscustomobject]@{ Elemento = 'Firmas Outlook'; Origen = $sig; Codigo = $code; Resultado = (Get-CSWUsersRobocopyText $code) })
        [void]$items.Add(@{ Type = 'Signatures'; Name = 'Signatures'; Source = $sig; Relative = 'Outlook\Signatures'; Code = $code })
    }
    $pst = @(Get-ChildItem -LiteralPath (Join-Path $prof.Path 'Documents\Outlook Files') -Filter '*.pst' -ErrorAction SilentlyContinue)
    $pst += @(Get-ChildItem -LiteralPath (Join-Path $prof.Path 'AppData\Local\Microsoft\Outlook') -Filter '*.pst' -ErrorAction SilentlyContinue)
    if ($pst.Count) { Write-CSWLog ("Hay {0} archivo(s) PST de Outlook; los de AppData no se incluyen en este backup, copielos con Outlook cerrado." -f $pst.Count) -Level Info }

    $manifest = [ordered]@{
        Tool = 'Cybersutro win'; Version = '1'; Computer = $env:COMPUTERNAME; User = $UserName; Sid = $prof.Sid
        ProfilePath = $prof.Path; Date = (Get-Date).ToString('s'); OneDrive = $oneDrive; Items = @($items)
    }
    try { ($manifest | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $target 'manifest.json') -Encoding UTF8 }
    catch { Write-CSWLog "No se pudo escribir manifest.json: $($_.Exception.Message)" -Level Warn }

    @($results) | Write-CSWOutput
    $size = [math]::Round((Get-CSWUsersFolderSize -Path $target) / 1GB, 2)
    Write-CSWLog "Tamano total del backup: $size GB. Log de robocopy: $log" -Level Info

    if ($items.Count -eq 0) { return (New-CSWResult -Summary "No se encontraron datos para respaldar del usuario '$UserName'." -Status Warn) }
    $summary = "Backup del perfil '$UserName' ($size GB) en $target"
    if ($worst -ge 8) { return (New-CSWResult -Summary "$summary; algunos archivos NO se copiaron (ver robocopy.log)." -Status Warn) }
    if ($oneDrive.Count) { return (New-CSWResult -Summary "$summary. Atencion: $($oneDrive -join ', ') en OneDrive (archivos solo en la nube no incluidos)." -Status Warn) }
    return (New-CSWResult -Summary "$summary.")
}

function Restore-CSWUsersProfileBackup {
    param([string]$Source = '', [string]$UserName = '')
    $Source = ([string]$Source).Trim().Trim('"')
    $UserName = ([string]$UserName).Trim()
    if (-not $Source -or -not (Test-Path -LiteralPath $Source -PathType Container)) { return (New-CSWResult -Summary "La carpeta de backup '$Source' no existe." -Status Error) }
    if (-not $UserName) { return (New-CSWResult -Summary 'Debe indicar el usuario destino.' -Status Error) }
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }

    try { $prof = Get-CSWUsersProfileInfo -UserName $UserName }
    catch { return (New-CSWResult -Summary "No se pudo consultar los perfiles: $($_.Exception.Message)" -Status Error) }
    if (-not $prof -or -not (Test-Path -LiteralPath $prof.Path)) {
        return (New-CSWResult -Summary "El usuario '$UserName' no tiene perfil en este equipo; debe iniciar sesion una vez antes de restaurar." -Status Error)
    }
    Write-CSWLog "Restaurando en el perfil $($prof.Path)" -Level Info
    if ($prof.Loaded) { Write-CSWLog 'El usuario tiene la sesion iniciada; se recomienda cerrarla para evitar archivos en uso.' -Level Warn }

    # Elementos a restaurar: manifest.json o deteccion por estructura de carpetas
    $items = @()
    $mf = Join-Path $Source 'manifest.json'
    if (Test-Path -LiteralPath $mf) {
        try {
            $m = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json
            $items = @($m.Items)
            Write-CSWLog "Backup de $($m.User) en $($m.Computer) del $($m.Date)." -Level Info
        }
        catch { Write-CSWLog "manifest.json ilegible; se detecta la estructura: $($_.Exception.Message)" -Level Warn }
    }
    if ($items.Count -eq 0) {
        foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $Source 'Carpetas') -Directory -ErrorAction SilentlyContinue)) {
            $items += [pscustomobject]@{ Type = 'Folder'; Name = $d.Name; Folder = ($d.Name -replace '_local$', ''); Relative = "Carpetas\$($d.Name)" }
        }
        foreach ($b in @(Get-ChildItem -LiteralPath (Join-Path $Source 'Navegadores') -Directory -ErrorAction SilentlyContinue)) {
            foreach ($p in @(Get-ChildItem -LiteralPath $b.FullName -Directory -ErrorAction SilentlyContinue)) {
                $items += [pscustomobject]@{ Type = 'Bookmarks'; Name = $b.Name; Profile = $p.Name; Relative = "Navegadores\$($b.Name)\$($p.Name)\Bookmarks" }
            }
        }
        if (Test-Path -LiteralPath (Join-Path $Source 'Outlook\Signatures')) {
            $items += [pscustomobject]@{ Type = 'Signatures'; Name = 'Signatures'; Relative = 'Outlook\Signatures' }
        }
    }
    if ($items.Count -eq 0) { return (New-CSWResult -Summary 'La carpeta indicada no contiene un backup de perfil reconocible.' -Status Error) }

    $folders = Get-CSWUsersShellFolders -Sid $prof.Sid -ProfilePath $prof.Path
    $log = Join-Path $Source ("restore_{0:yyyyMMdd_HHmm}.log" -f (Get-Date))
    $results = New-Object System.Collections.ArrayList
    $worst = 0
    $stamp = Get-Date -Format 'yyyyMMdd_HHmm'

    # manifest.json es un dato externo (la carpeta de backup puede venir de cualquier sitio):
    # solo se aceptan rutas relativas sin '..' y carpetas/perfiles conocidos, para que la
    # restauracion (como administrador) no pueda escribir fuera del perfil destino.
    $knownNames = @($script:UsersKnownFolders | ForEach-Object { $_.Name })
    foreach ($it in $items) {
        $rel = [string](Get-CSWUsersProp $it 'Relative')
        if (-not $rel -or $rel -match '\.\.' -or [System.IO.Path]::IsPathRooted($rel) -or $rel -match '[:*?"<>|]') {
            Write-CSWLog "Elemento del backup ignorado (ruta no valida): $rel" -Level Warn; continue
        }
        $type = [string](Get-CSWUsersProp $it 'Type')
        if ($type -eq 'Folder') {
            $fn = [string](Get-CSWUsersProp $it 'Folder')
            if (-not $fn) { $fn = ([string](Get-CSWUsersProp $it 'Name')) -replace '_local$', '' }
            if ($knownNames -notcontains $fn) { Write-CSWLog "Carpeta del backup ignorada (no reconocida): $fn" -Level Warn; continue }
        }
        if ($type -eq 'Bookmarks' -and ([string](Get-CSWUsersProp $it 'Profile')) -notmatch '^(Default|Profile \d{1,3})$') {
            Write-CSWLog "Perfil de navegador ignorado (nombre no valido): $(Get-CSWUsersProp $it 'Profile')" -Level Warn; continue
        }
        $src = Join-Path $Source $rel
        if (-not (Test-Path -LiteralPath $src)) { Write-CSWLog "No existe en el backup: $rel" -Level Warn; continue }
        switch ([string]$it.Type) {
            'Folder' {
                $fname = [string]$it.Name -replace '_local$', ''
                if ($it.PSObject.Properties['Folder'] -and $it.Folder) { $fname = [string]$it.Folder }
                $dst = Join-Path $prof.Path $fname
                if ($folders.ContainsKey($fname)) { $dst = $folders[$fname] }
                Write-CSWLog "Restaurando $($it.Name) -> $dst" -Level Step
                # /XO: no sobrescribe archivos mas nuevos del destino
                $code = Invoke-CSWUsersRobocopy -Source $src -Destination $dst -LogFile $log -Extra '/XO'
                if ($code -gt $worst) { $worst = $code }
                [void]$results.Add([pscustomobject]@{ Elemento = $it.Name; Destino = $dst; Codigo = $code; Resultado = (Get-CSWUsersRobocopyText $code) })
            }
            'Bookmarks' {
                $br = @($script:UsersBrowsers | Where-Object { $_.Name -eq [string]$it.Name }) | Select-Object -First 1
                if (-not $br) { continue }
                if (Get-Process -Name $br.Process -ErrorAction SilentlyContinue) {
                    Write-CSWLog "$($br.Name) esta abierto: podria sobrescribir los marcadores al cerrarse. Cierrelo y vuelva a restaurar si no aparecen." -Level Warn
                }
                $dstDir = Join-Path (Join-Path $prof.Path $br.Root) ([string]$it.Profile)
                try {
                    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
                    $dstFile = Join-Path $dstDir 'Bookmarks'
                    if (Test-Path -LiteralPath $dstFile) { Copy-Item -LiteralPath $dstFile -Destination "$dstFile.csw_$stamp.bak" -Force }
                    Copy-Item -LiteralPath $src -Destination $dstFile -Force -ErrorAction Stop
                    [void]$results.Add([pscustomobject]@{ Elemento = "$($br.Name) marcadores ($($it.Profile))"; Destino = $dstFile; Codigo = 1; Resultado = 'restaurado' })
                }
                catch {
                    $worst = [math]::Max($worst, 8)
                    Write-CSWLog "No se pudieron restaurar los marcadores de $($br.Name): $($_.Exception.Message)" -Level Warn
                }
            }
            'Signatures' {
                $dst = Join-Path $prof.Path 'AppData\Roaming\Microsoft\Signatures'
                Write-CSWLog 'Restaurando firmas de Outlook...' -Level Step
                $code = Invoke-CSWUsersRobocopy -Source $src -Destination $dst -LogFile $log -Extra '/XO'
                if ($code -gt $worst) { $worst = $code }
                [void]$results.Add([pscustomobject]@{ Elemento = 'Firmas Outlook'; Destino = $dst; Codigo = $code; Resultado = (Get-CSWUsersRobocopyText $code) })
            }
        }
    }
    @($results) | Write-CSWOutput
    Write-CSWLog "Log de la restauracion: $log" -Level Info
    if ($results.Count -eq 0) { return (New-CSWResult -Summary 'No se restauro ningun elemento.' -Status Warn) }
    if ($worst -ge 8) { return (New-CSWResult -Summary "Restauracion en '$UserName' con errores: algunos archivos no se copiaron (ver log)." -Status Warn) }
    return (New-CSWResult -Summary "Backup restaurado en el perfil de '$UserName' ($($results.Count) elemento(s))." )
}

# ---------------------------------------------------------------------------
# Drivers y licencia
# ---------------------------------------------------------------------------

function Backup-CSWUsersDrivers {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $dir = Join-Path (Get-CSWDataPath Backups) ("Drivers_{0}_{1:yyyyMMdd_HHmm}" -f $env:COMPUTERNAME, (Get-Date))
    try { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    catch { return (New-CSWResult -Summary "No se pudo crear la carpeta de destino: $($_.Exception.Message)" -Status Error) }
    Write-CSWLog "Exportando drivers de terceros a $dir (puede tardar varios minutos)..." -Level Step

    $count = -1
    if (Get-Command -Name Export-WindowsDriver -ErrorAction SilentlyContinue) {
        try {
            $exp = @(Export-WindowsDriver -Online -Destination $dir -ErrorAction Stop)
            $count = $exp.Count
            $exp | ForEach-Object {
                [pscustomobject]@{ Inf = $_.OriginalFileName | Split-Path -Leaf; Clase = $_.ClassName; Proveedor = $_.ProviderName; Version = $_.Version; Fecha = $_.Date }
            } | Sort-Object Clase, Proveedor | Write-CSWOutput
        }
        catch { Write-CSWLog "Export-WindowsDriver fallo: $($_.Exception.Message). Se usa pnputil." -Level Warn }
    }
    if ($count -lt 0) {
        $pnputil = Join-Path $env:SystemRoot 'System32\pnputil.exe'
        $sysnative = Join-Path $env:SystemRoot 'Sysnative\pnputil.exe'
        if ((-not [Environment]::Is64BitProcess) -and (Test-Path $sysnative)) { $pnputil = $sysnative }
        $code = Invoke-CSWExternal -FilePath $pnputil -Arguments ("/export-driver * `"{0}`"" -f $dir)
        if ($code -ne 0) { return (New-CSWResult -Summary "No se pudieron exportar los drivers (pnputil codigo $code)." -Status Error) }
        $count = @(Get-ChildItem -LiteralPath $dir -Recurse -Filter '*.inf' -ErrorAction SilentlyContinue).Count
    }
    $size = [math]::Round((Get-CSWUsersFolderSize -Path $dir) / 1MB, 0)
    if ($count -eq 0) { return (New-CSWResult -Summary 'No hay drivers de terceros que exportar (solo drivers de Windows).' -Status Warn) }
    Write-CSWLog "Para reinstalarlos: pnputil /add-driver `"$dir\*.inf`" /subdirs /install" -Level Info
    return (New-CSWResult -Summary "Backup de $count driver(s) de terceros ($size MB) en $dir")
}

function Export-CSWUsersDriverList {
    Write-CSWLog 'Consultando drivers de terceros instalados...' -Level Info
    try { $all = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop) }
    catch { return (New-CSWResult -Summary "No se pudo consultar los drivers: $($_.Exception.Message)" -Status Error) }
    $third = @($all | Where-Object { $_.InfName -like 'oem*.inf' })
    if ($third.Count -eq 0) { return (New-CSWResult -Summary 'No hay drivers de terceros instalados.' -Status Warn) }
    $rows = foreach ($d in $third) {
        $date = ''
        if ($d.DriverDate) { try { $date = ([datetime]$d.DriverDate).ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) } catch { $date = [string]$d.DriverDate } }
        [pscustomobject]@{
            Dispositivo = $d.DeviceName
            Clase       = $d.DeviceClass
            Fabricante  = $d.Manufacturer
            Proveedor   = $d.DriverProviderName
            Version     = $d.DriverVersion
            Fecha       = $date
            Inf         = $d.InfName
            Firmado     = $(if ($d.IsSigned) { 'Si' } else { 'No' })
            Firmante    = $d.Signer
            HardwareId  = $d.HardWareID
        }
    }
    $rows = @($rows | Sort-Object Clase, Dispositivo)
    $file = Join-Path (Get-CSWDataPath Reports) ("Drivers_terceros_{0}_{1:yyyyMMdd_HHmm}.csv" -f $env:COMPUTERNAME, (Get-Date))
    try { $rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -UseCulture -ErrorAction Stop }
    catch { return (New-CSWResult -Summary "No se pudo escribir el CSV: $($_.Exception.Message)" -Status Error) }
    $rows | Select-Object Dispositivo, Clase, Proveedor, Version, Fecha, Inf | Write-CSWOutput
    $unsigned = @($rows | Where-Object { $_.Firmado -eq 'No' }).Count
    $summary = "{0} driver(s) de terceros exportados a {1}" -f $rows.Count, $file
    if ($unsigned) { return (New-CSWResult -Summary "$summary ($unsigned sin firma)." -Status Warn) }
    return (New-CSWResult -Summary $summary)
}

function Backup-CSWUsersProductKey {
    Write-CSWLog 'Leyendo la clave de producto de Windows...' -Level Info
    $oem = ''
    try {
        $sls = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        if ($sls.PSObject.Properties['OA3xOriginalProductKey'] -and $sls.OA3xOriginalProductKey) { $oem = [string]$sls.OA3xOriginalProductKey }
    }
    catch { Write-CSWLog "SoftwareLicensingService no disponible: $($_.Exception.Message)" -Level Warn }

    $installed = ''
    try {
        $dpid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId -ErrorAction Stop).DigitalProductId
        $installed = ConvertFrom-CSWUsersDigitalProductId -DigitalProductId $dpid
    }
    catch { }
    $generic = $false
    if ($installed -and $installed -match '^B{5}-B{5}') { $generic = $true }

    $edition = ''; $partial = ''; $channel = ''; $licStatus = ''
    try {
        $p = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop) | Select-Object -First 1
        if ($p) {
            $edition = $p.Name; $partial = $p.PartialProductKey; $channel = $p.ProductKeyChannel
            $licStatus = switch ([int]$p.LicenseStatus) { 0 { 'Sin licencia' } 1 { 'Activado' } 2 { 'Periodo de gracia OOB' } 3 { 'Gracia OOT' } 4 { 'Gracia no original' } 5 { 'Notificacion (no activado)' } 6 { 'Gracia extendida' } default { [string]$p.LicenseStatus } }
        }
    }
    catch { }
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }

    if (-not $oem -and (-not $installed -or $generic)) {
        Write-CSWLog 'No hay clave OEM en el firmware y la clave instalada es generica (licencia digital).' -Level Info
        if (-not $partial) { return (New-CSWResult -Summary 'No se encontro clave de producto: el equipo probablemente usa licencia digital vinculada a la cuenta/hardware.' -Status Warn) }
    }

    $file = Join-Path (Get-CSWDataPath Backups) ("ClaveWindows_{0}_{1:yyyyMMdd_HHmm}.txt" -f $env:COMPUTERNAME, (Get-Date))
    $lines = @(
        'Cybersutro win - Clave de producto de Windows',
        ('Equipo          : {0}' -f $env:COMPUTERNAME),
        ('Fecha           : {0}' -f (Get-Date -Format 'dd\/MM\/yyyy HH:mm')),
        ('Sistema         : {0}' -f $(if ($os) { "$($os.Caption) $($os.Version)" } else { '' })),
        ('Edicion licencia: {0}' -f $edition),
        ('Canal           : {0}' -f $channel),
        ('Estado          : {0}' -f $licStatus),
        ('Clave OEM (BIOS): {0}' -f $(if ($oem) { $oem } else { '(no hay)' })),
        ('Clave instalada : {0}{1}' -f $(if ($installed) { $installed } else { '(no disponible)' }), $(if ($generic) { ' (generica / licencia digital)' } else { '' })),
        ('Ultimos 5       : {0}' -f $partial),
        '',
        'Nota: con licencia digital la activacion se recupera sola al reinstalar la misma edicion.'
    )
    try { Set-Content -LiteralPath $file -Value $lines -Encoding ASCII -ErrorAction Stop }
    catch { return (New-CSWResult -Summary "No se pudo guardar el archivo: $($_.Exception.Message)" -Status Error) }

    # En el log solo los ultimos 5 caracteres
    if ($oem) { Write-CSWLog ("Clave OEM del firmware: {0}" -f (Get-CSWUsersMaskedKey $oem)) -Level Ok }
    if ($installed) { Write-CSWLog ("Clave instalada: {0}{1}" -f (Get-CSWUsersMaskedKey $installed), $(if ($generic) { ' (generica)' } else { '' })) -Level Info }
    if ($edition) { Write-CSWLog "Licencia: $edition | $channel | $licStatus" -Level Info }
    Write-CSWLog "Guardado en $file" -Level Ok
    $shown = $partial
    if ($oem) { $shown = $oem.Substring($oem.Length - 5) }
    elseif ($installed -and -not $generic) { $shown = $installed.Substring($installed.Length - 5) }
    $status = 'OK'
    if ($licStatus -and $licStatus -ne 'Activado') { $status = 'Warn' }
    return (New-CSWResult -Summary ("Clave de Windows respaldada (termina en {0}); estado: {1}." -f $shown, $(if ($licStatus) { $licStatus } else { 'desconocido' })) -Status $status)
}

# ---------------------------------------------------------------------------
# Recursos compartidos
# ---------------------------------------------------------------------------

function Get-CSWUsersShares {
    Write-CSWLog 'Carpetas compartidas por este equipo:' -Level Step
    $shares = @()
    $nonAdmin = 0
    $viaSmb = $false
    if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) {
        try { $shares = @(Get-SmbShare -ErrorAction Stop); $viaSmb = $true } catch { Write-CSWLog "Get-SmbShare: $($_.Exception.Message)" -Level Warn }
    }
    if (-not $viaSmb) {
        try { $shares = @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop) } catch { }
    }
    if ($shares.Count) {
        $rows = foreach ($s in $shares) {
            $special = $s.Name -like '*$'
            if (-not $special) { $nonAdmin++ }
            $access = ''
            if ($viaSmb -and -not $special) {
                try {
                    $access = (@(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop) | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join '; '
                }
                catch { }
            }
            [pscustomobject]@{
                Recurso     = $s.Name
                Ruta        = $s.Path
                Tipo        = $(if ($special) { 'Administrativo' } else { 'Usuario' })
                Descripcion = $s.Description
                Permisos    = $access
            }
        }
        @($rows) | Sort-Object Tipo, Recurso | Write-CSWOutput
    }
    else { Write-CSWLog 'No se pudieron obtener los recursos compartidos (o no hay).' -Level Info }

    Write-CSWLog 'Unidades de red mapeadas:' -Level Step
    $maps = New-Object System.Collections.ArrayList
    try {
        foreach ($m in @(Get-CimInstance -ClassName Win32_MappedLogicalDisk -ErrorAction Stop)) {
            [void]$maps.Add([pscustomobject]@{ Usuario = "$env:USERDOMAIN\$env:USERNAME (sesion actual)"; Unidad = $m.DeviceID; Ruta = $m.ProviderName; Persistente = '?' })
        }
    }
    catch { }
    # Unidades persistentes de cada usuario con sesion iniciada (HKU\<SID>\Network)
    foreach ($k in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $net = "Registry::HKEY_USERS\$sid\Network"
        if (-not (Test-Path -LiteralPath $net)) { continue }
        $user = Get-CSWUsersSidName $sid
        if (-not $user) { $user = $sid }
        foreach ($d in @(Get-ChildItem -LiteralPath $net -ErrorAction SilentlyContinue)) {
            $remote = ''
            try { $remote = $d.GetValue('RemotePath') } catch { }
            $letter = "$($d.PSChildName.ToUpper()):"
            $dup = @($maps | Where-Object { $_.Unidad -eq $letter -and $_.Ruta -eq $remote })
            if ($dup.Count) { foreach ($x in $dup) { $x.Persistente = 'Si'; $x.Usuario = $user }; continue }
            [void]$maps.Add([pscustomobject]@{ Usuario = $user; Unidad = $letter; Ruta = $remote; Persistente = 'Si' })
        }
    }
    if ($maps.Count) { $maps | Write-CSWOutput }
    else { Write-CSWLog 'No hay unidades de red mapeadas en las sesiones abiertas.' -Level Info }
    Write-CSWLog 'Nota: la herramienta corre elevada; las unidades mapeadas de usuarios sin sesion abierta no se ven.' -Level Info

    $summary = "{0} carpeta(s) compartida(s) por el usuario, {1} unidad(es) de red mapeada(s)" -f $nonAdmin, $maps.Count
    if ($shares.Count -eq 0) { return (New-CSWResult -Summary "$summary (no se pudo leer la lista de recursos compartidos)." -Status Warn) }
    return (New-CSWResult -Summary "$summary.")
}

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

$script:UsersBackupDefaultDest = ''
try { $script:UsersBackupDefaultDest = Get-CSWDataPath Backups } catch { }

Register-CSWModule -Id 'UsersBackup' -Name 'Usuarios y backup' -Order 80 -Icon 'users' `
    -Description 'Cuentas locales, perfiles, copia de seguridad de datos, drivers y clave de Windows' -Actions @(
    @{ Id = 'ListUsers'; Name = 'Listar usuarios locales'; Command = 'Get-CSWUsersLocal'
        Description = 'Muestra cuentas locales: habilitada, administrador, último inicio, caducidad y bloqueo.' },
    @{ Id = 'Profiles'; Name = 'Perfiles de usuario'; Command = 'Get-CSWUsersProfiles'
        Description = 'Lista los perfiles y detecta perfiles temporales, corruptos o con clave .bak.'
        Inputs = @(@{ Name = 'IncludeSize'; Label = 'Calcular tamaño (lento)'; Type = 'Bool'; Default = $false }) },
    @{ Id = 'CreateUser'; Name = 'Crear usuario local'; Command = 'New-CSWUsersLocal'
        Description = 'Crea una cuenta local estándar o administradora.'
        Risk = 'Medium'; ModifiesSystem = $true
        ConfirmMessage = 'Se creará una nueva cuenta local en el equipo.'
        Inputs = @(
            @{ Name = 'UserName'; Label = 'Nombre de usuario'; Default = '' },
            @{ Name = 'Password'; Label = 'Contraseña'; Default = '' },
            @{ Name = 'IsAdmin'; Label = 'Administrador'; Type = 'Bool'; Default = $false }
        ) },
    @{ Id = 'ResetPassword'; Name = 'Restablecer contraseña'; Command = 'Reset-CSWUsersPassword'
        Description = 'Cambia la contraseña de una cuenta local.'
        Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'Se cambiará la contraseña. Los archivos cifrados con EFS y las credenciales guardadas del usuario pueden perderse.'
        Inputs = @(
            @{ Name = 'UserName'; Label = 'Usuario'; Default = '' },
            @{ Name = 'Password'; Label = 'Nueva contraseña'; Default = '' }
        ) },
    @{ Id = 'EnableUser'; Name = 'Habilitar/deshabilitar usuario'; Command = 'Set-CSWUsersEnabled'
        Description = 'Habilita o deshabilita una cuenta local.'
        Risk = 'Medium'; ModifiesSystem = $true; ConfirmMessage = 'Se cambiará el estado de la cuenta (una cuenta deshabilitada no puede iniciar sesión).'
        Inputs = @(
            @{ Name = 'UserName'; Label = 'Usuario'; Default = '' },
            @{ Name = 'Enable'; Label = 'Habilitar'; Type = 'Bool'; Default = $true }
        ) },
    @{ Id = 'UnlockUser'; Name = 'Desbloquear cuenta'; Command = 'Unlock-CSWUsersAccount'
        Description = 'Desbloquea una cuenta local bloqueada por intentos fallidos.'
        Risk = 'Medium'; ConfirmMessage = 'Se desbloqueará la cuenta indicada (podrá volver a intentar iniciar sesión).'
        Inputs = @(@{ Name = 'UserName'; Label = 'Usuario'; Default = '' }) },
    @{ Id = 'BackupProfile'; Name = 'Backup de perfil'; Command = 'Backup-CSWUsersProfile'
        Description = 'Copia Escritorio, Documentos, Descargas, Imágenes, Música, Videos, Favoritos, marcadores y firmas de Outlook.'
        LongRunning = $true
        Inputs = @(
            @{ Name = 'UserName'; Label = 'Usuario'; Default = $env:USERNAME },
            @{ Name = 'Destination'; Label = 'Carpeta destino'; Default = $script:UsersBackupDefaultDest }
        ) },
    @{ Id = 'RestoreProfile'; Name = 'Restaurar backup de perfil'; Command = 'Restore-CSWUsersProfileBackup'
        Description = 'Restaura un backup de perfil en la cuenta indicada (no sobrescribe archivos más nuevos).'
        Risk = 'High'; ModifiesSystem = $true; LongRunning = $true
        ConfirmMessage = 'Se copiarán archivos dentro del perfil del usuario destino; los marcadores del navegador se reemplazan (se guarda copia .bak).'
        Inputs = @(
            @{ Name = 'Source'; Label = 'Carpeta del backup (Perfil_...)'; Default = '' },
            @{ Name = 'UserName'; Label = 'Usuario destino'; Default = '' }
        ) },
    @{ Id = 'BackupDrivers'; Name = 'Backup de drivers'; Command = 'Backup-CSWUsersDrivers'
        Description = 'Exporta todos los drivers de terceros a una carpeta fechada en Backups.'
        LongRunning = $true },
    @{ Id = 'DriverList'; Name = 'Lista de drivers (CSV)'; Command = 'Export-CSWUsersDriverList'
        Description = 'Exporta a CSV la lista de drivers de terceros instalados.' },
    @{ Id = 'ProductKey'; Name = 'Backup clave de Windows'; Command = 'Backup-CSWUsersProductKey'
        Description = 'Guarda la clave de producto (OEM del firmware e instalada) y el estado de activación en un TXT.'
        Risk = 'Medium'; ConfirmMessage = 'Se guardará la clave de producto COMPLETA de Windows en un TXT dentro de Backups (carpeta solo para Administradores). En el registro y el informe solo aparecen los últimos 5 caracteres. Trate el archivo como confidencial.' },
    @{ Id = 'Shares'; Name = 'Compartidos y unidades de red'; Command = 'Get-CSWUsersShares'
        Description = 'Lista las carpetas compartidas del equipo y las unidades de red mapeadas.' }
)

Export-ModuleMember -Function *
