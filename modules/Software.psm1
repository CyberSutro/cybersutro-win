#Requires -Version 5.1
<#
    Cybersutro win - Modulo Software
    Gestion de aplicaciones con winget (actualizar, instalar packs, exportar/importar)
    y retirada conservadora de apps preinstaladas (bloatware) solo de una lista curada.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# Packs predefinidos (IDs exactos del repositorio winget)
$script:SwPacks = [ordered]@{
    'Basico'  = @('7zip.7zip', 'VideoLAN.VLC', 'Google.Chrome', 'Adobe.Acrobat.Reader.64-bit')
    'Tecnico' = @('7zip.7zip', 'Notepad++.Notepad++', 'CPUID.CPU-Z', 'REALiX.HWiNFO', 'CrystalDewWorld.CrystalDiskInfo', 'voidtools.Everything')
    'Oficina' = @('TheDocumentFoundation.LibreOffice', 'Zoom.Zoom', 'Adobe.Acrobat.Reader.64-bit')
}
$script:SwPackChoices = @(
    'Basico: 7zip, VLC, Chrome, Adobe Reader',
    'Tecnico: 7zip, Notepad++, CPU-Z, HWiNFO, CrystalDiskInfo, Everything',
    'Oficina: LibreOffice, Zoom, Adobe Reader'
)

# Lista CURADA y conservadora de apps preinstaladas prescindibles (patrones -like)
$script:SwBloatPatterns = @(
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingFinance', 'Microsoft.BingSports', 'Microsoft.BingTravel',
    'Microsoft.BingFoodAndDrink', 'Microsoft.BingHealthAndFitness',
    'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People',
    'Microsoft.WindowsFeedbackHub', 'Microsoft.ZuneVideo', 'Microsoft.MixedReality.Portal',
    'Microsoft.SkypeApp', 'Clipchamp.Clipchamp', 'Microsoft.Microsoft3DViewer', 'Microsoft.Print3D', 'Microsoft.3DBuilder',
    'Microsoft.MicrosoftOfficeHub', 'Microsoft.Messaging', 'Microsoft.OneConnect', 'Microsoft.Wallet', 'Microsoft.549981C3F5F10',
    'Microsoft.WindowsMaps', 'Microsoft.MicrosoftJournal', 'MicrosoftCorporationII.MicrosoftFamily',
    'king.com.*', 'SpotifyAB.SpotifyMusic', 'Disney.*', '4DF9E0F8.Netflix', 'Facebook.*', 'BytedanceInc.TikTok', '*.TikTok',
    '*.Twitter', '9E2F88E3.Twitter', 'AmazonVideo.PrimeVideo', '7EE7776C.LinkedInforWindows', '*.CandyCrush*', '*.BubbleWitch3Saga',
    '*.MarchofEmpires', '*.Asphalt8Airborne', '*.DisneyMagicKingdoms', '*.HiddenCity*', '*.FarmVille2CountryEscape', '*.RoyalRevolt2',
    'ShazamEntertainmentLtd.Shazam', 'Flipboard.Flipboard', 'PandoraMediaInc.*', 'ActiproSoftwareLLC.*', 'AdobeSystemsIncorporated.AdobePhotoshopExpress',
    'D5EA27B7.Duolingo-LearnLanguagesforFree', '*.EclipseManager', '*.Plex', 'Playtika.CaesarsSlotsFreeCasino', 'A278AB0D.MarchofEmpires',
    'A278AB0D.DragonManiaLegends', 'GAMELOFTSA.*', 'NORDCURRENT.COOKINGFEVER', 'Nordcurrent.CookingFever'
)

# Nunca se tocan aunque coincida algun patron (sistema / apps esenciales)
$script:SwProtectedPatterns = @(
    'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.WindowsCalculator', 'Microsoft.Windows.Photos', 'Microsoft.MicrosoftEdge*',
    'Microsoft.WindowsTerminal*', 'Microsoft.DesktopAppInstaller', 'Microsoft.Windows.*', 'Microsoft.UI.Xaml*', 'Microsoft.VCLibs*',
    'Microsoft.NET.*', 'Microsoft.Services.Store.*', 'Microsoft.SecHealthUI', 'Microsoft.WindowsNotepad', 'Microsoft.Paint',
    'Microsoft.ScreenSketch', 'Microsoft.HEIFImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.VP9VideoExtensions',
    'Microsoft.WebMediaExtensions', 'Microsoft.WebpImageExtension', 'Microsoft.RawImageExtension', 'Microsoft.AV1VideoExtension',
    'Microsoft.XboxIdentityProvider', 'Microsoft.XboxGameCallableUI', 'Microsoft.AAD.BrokerPlugin', 'Microsoft.AccountsControl',
    'Microsoft.LockApp', 'Microsoft.Win32WebViewHost', 'MicrosoftWindows.*', 'windows.*', 'Microsoft.WindowsAppRuntime*',
    'Microsoft.OneDriveSync', 'Microsoft.CompanyPortal', 'Microsoft.Office.Desktop*'
)

# Codigos de salida conocidos de winget (HRESULT con signo)
$script:SwWingetCodes = @{
    '8A150014' = 'No se encontro ningun paquete con ese criterio'
    '8A15002B' = 'No hay actualizacion aplicable para el paquete'
    '8A150061' = 'El paquete ya esta instalado'
    '8A150109' = 'Instalado; se requiere reiniciar para completar'
    '8A15010A' = 'Se requiere reiniciar antes de instalar'
    '8A150101' = 'El instalador esta en uso por otro proceso'
    '8A150102' = 'Hay otra instalacion en curso; intente mas tarde'
    '8A150103' = 'Hay archivos en uso; cierre la aplicacion e intente de nuevo'
    '8A150104' = 'Falta una dependencia del paquete'
    '8A150105' = 'Disco lleno'
    '8A150106' = 'Memoria insuficiente'
    '8A150107' = 'Se requiere conexion a Internet'
    '8A150111' = 'La aplicacion esta en ejecucion; cierrela e intente de nuevo'
    '8A15002E' = 'Hay varios paquetes que coinciden; use el ID exacto'
    '8A150010' = 'Fallo de configuracion de origen o acuerdos no aceptados'
}

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------
function Get-CSWSwProp {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

function Test-CSWSwPackageId {
    # IDs de winget: letras, numeros, punto, guion, guion bajo y '+' (evita inyeccion en argumentos)
    param([string]$Id)
    return ($Id -match '^[A-Za-z0-9][A-Za-z0-9\.\-_\+]{0,127}$')
}

function Get-CSWSwWinget {
    # Localiza winget.exe (alias de usuario, PATH o carpeta WindowsApps de App Installer)
    $cand = @()
    $cmd = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { $cand += $cmd.Source }
    $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    $cand += $alias
    try {
        $wa = Join-Path $env:ProgramFiles 'WindowsApps'
        $dirs = @(Get-ChildItem -Path $wa -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -Directory -ErrorAction Stop)
        $dirs += @(Get-ChildItem -Path $wa -Filter 'Microsoft.DesktopAppInstaller_*_arm64__8wekyb3d8bbwe' -Directory -ErrorAction SilentlyContinue)
        $sorted = $dirs | Sort-Object { try { [version](($_.Name -split '_')[1]) } catch { [version]'0.0' } } -Descending
        foreach ($d in $sorted) { $cand += (Join-Path $d.FullName 'winget.exe') }
    }
    catch { }
    foreach ($c in $cand) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

function Get-CSWSwWingetVersion {
    param([string]$Path)
    try {
        $v = ((Get-CSWExternalOutput -FilePath $Path -Arguments '--version' -Utf8 -TimeoutSeconds 30) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if ($v -match 'v?(\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] }
    }
    catch { }
    return $null
}

function Get-CSWSwMissingWingetResult {
    Write-CSWLog 'winget no esta disponible en este equipo.' -Level Warn
    Write-CSWLog 'Para instalarlo: abra Microsoft Store y actualice/instale "Instalador de aplicaciones" (App Installer, ID 9NBLGGH4NNS1).' -Level Info
    Write-CSWLog 'Sin Store (LTSC/Server): descargue el .msixbundle de https://aka.ms/getwinget e instalelo con Add-AppxPackage (requiere VCLibs y UI.Xaml).' -Level Info
    Write-CSWLog 'Si acaba de instalarse, cierre sesion o reinicie para registrar el alias winget.exe.' -Level Info
    return (New-CSWResult -Summary 'winget no esta instalado: instale "Instalador de aplicaciones" (App Installer) desde Microsoft Store' -Status Warn)
}

function Get-CSWSwContext {
    # Devuelve @{ Path; Version; NoInteract } o $null si winget no existe
    $p = Get-CSWSwWinget
    if (-not $p) { return $null }
    $v = Get-CSWSwWingetVersion $p
    $ni = ''
    if ($v -and $v -ge [version]'1.4') { $ni = ' --disable-interactivity' }
    return [pscustomobject]@{ Path = $p; Version = $v; NoInteract = $ni }
}

function Get-CSWSwExitText {
    param([int]$Code)
    if ($Code -eq 0) { return 'Correcto' }
    $hex = '{0:X8}' -f $Code
    if ($script:SwWingetCodes.ContainsKey($hex)) { return ('{0} (0x{1})' -f $script:SwWingetCodes[$hex], $hex) }
    return ('Codigo 0x{0}' -f $hex)
}

function Invoke-CSWSwWinget {
    # Ejecuta winget via Invoke-CSWExternal decodificando su salida UTF-8.
    # Devuelve @{ Code; Lines } con las lineas que se mostraron en el log.
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Arguments)
    $state = Get-CSWState
    $startIdx = $state.LogLines.Count
    # winget escribe UTF-8; se decodifica asi sin tocar [Console]::OutputEncoding (es global del proceso)
    $code = Invoke-CSWExternal -FilePath $Ctx.Path -Arguments $Arguments -Utf8
    $lines = @()
    $all = @($state.LogLines.ToArray())
    for ($i = $startIdx; $i -lt $all.Count; $i++) { if ($all[$i].Level -eq 'Data') { $lines += [string]$all[$i].Message } }
    return [pscustomobject]@{ Code = [int]$code; Lines = $lines }
}

function Get-CSWSwTableCount {
    # Cuenta filas de una tabla de winget (lineas tras el separador ----- que contienen un ID)
    param([string[]]$Lines)
    $count = 0
    $inTable = $false
    foreach ($l in $Lines) {
        if ($l -match '^-{10,}') { $inTable = $true; continue }
        if (-not $inTable) { continue }
        if ($l -match '^\d+\s+\S+.*(upgrade|actualizac|paquete|package)' ) { $inTable = $false; continue }
        if ($l -match '\S+\s+[A-Za-z0-9][A-Za-z0-9\.\-_\+]+\.[A-Za-z0-9\.\-_\+]+\s+\S+') { $count++ }
    }
    return $count
}

function Initialize-CSWSwAppx {
    # En PowerShell 7 el modulo Appx necesita la capa de compatibilidad de Windows PowerShell
    if ($PSVersionTable.PSEdition -eq 'Core') {
        if (-not (Get-Module -Name Appx)) {
            try { Import-Module Appx -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue 3>$null } catch { }
        }
    }
    return [bool](Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)
}

function Test-CSWSwProtected {
    param([string]$Name)
    foreach ($p in $script:SwProtectedPatterns) { if ($Name -like $p) { return $true } }
    return $false
}

function Test-CSWSwBloat {
    param([string]$Name)
    if (Test-CSWSwProtected $Name) { return $false }
    foreach ($p in $script:SwBloatPatterns) { if ($Name -like $p) { return $true } }
    return $false
}

function Get-CSWSwBloatInventory {
    # Devuelve apps de la lista curada presentes para el usuario actual y aprovisionadas
    $items = New-Object System.Collections.ArrayList
    $userPkgs = @()
    try { $userPkgs = @(Get-AppxPackage -ErrorAction Stop) } catch { Write-CSWLog "No se pudieron listar las apps del usuario: $($_.Exception.Message)" -Level Warn }
    foreach ($p in $userPkgs) {
        if (-not (Test-CSWSwBloat $p.Name)) { continue }
        if ([bool](Get-CSWSwProp $p 'IsFramework' $false)) { continue }
        if ([bool](Get-CSWSwProp $p 'NonRemovable' $false)) { continue }
        if ([string](Get-CSWSwProp $p 'SignatureKind' '') -eq 'System') { continue }
        [void]$items.Add([pscustomobject]@{ Ambito = 'Usuario'; Nombre = $p.Name; Version = [string]$p.Version; Paquete = $p.PackageFullName })
    }
    if (Test-CSWAdmin) {
        try {
            foreach ($p in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)) {
                if (-not (Test-CSWSwBloat $p.DisplayName)) { continue }
                [void]$items.Add([pscustomobject]@{ Ambito = 'Aprovisionado'; Nombre = $p.DisplayName; Version = [string]$p.Version; Paquete = $p.PackageName })
            }
        }
        catch { Write-CSWLog "No se pudieron listar las apps aprovisionadas: $($_.Exception.Message)" -Level Warn }
    }
    else { Write-CSWLog 'Sin administrador no se listan las apps aprovisionadas (las que se instalan a usuarios nuevos).' -Level Info }
    return @($items | Sort-Object Ambito, Nombre)
}

# ---------------------------------------------------------------------------
# Acciones winget
# ---------------------------------------------------------------------------
function Test-CSWSwWinget {
    Write-CSWLog 'Comprobando winget...' -Level Step
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    $verTxt = 'desconocida'
    if ($ctx.Version) { $verTxt = $ctx.Version.ToString() }
    Write-CSWLog "Ruta: $($ctx.Path)" -Level Info
    Write-CSWLog "Version de winget: $verTxt" -Level Info
    try {
        $ai = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop | Select-Object -First 1
        if ($ai) { Write-CSWLog "App Installer: $($ai.Version)" -Level Info }
    }
    catch { }
    if (Get-Module -ListAvailable -Name 'Microsoft.WinGet.Client' -ErrorAction SilentlyContinue) { Write-CSWLog 'Modulo PowerShell Microsoft.WinGet.Client disponible.' -Level Info }
    Write-CSWLog 'Fuentes configuradas:' -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments 'source list'
    if ($r.Code -ne 0) {
        Write-CSWLog ("winget source list: {0}" -f (Get-CSWSwExitText $r.Code)) -Level Warn
        return (New-CSWResult -Summary "winget $verTxt instalado, pero sus fuentes dan error (use 'Reparar fuentes')" -Status Warn)
    }
    $hasWinget = @($r.Lines | Where-Object { $_ -match '^winget\s+https?://' }).Count -gt 0
    if (-not $hasWinget) {
        Write-CSWLog "La fuente 'winget' no aparece configurada." -Level Warn
        return (New-CSWResult -Summary "winget $verTxt instalado, falta la fuente principal 'winget' (use 'Reparar fuentes')" -Status Warn)
    }
    if ($ctx.Version -and $ctx.Version -lt [version]'1.4') {
        return (New-CSWResult -Summary "winget $verTxt es antiguo; actualice App Installer desde Microsoft Store" -Status Warn)
    }
    return (New-CSWResult -Summary "winget $verTxt operativo con sus fuentes configuradas")
}

function Get-CSWSwUpdates {
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    Write-CSWLog 'Buscando actualizaciones disponibles (winget upgrade)...' -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ('upgrade --include-unknown --accept-source-agreements' + $ctx.NoInteract)
    $n = Get-CSWSwTableCount $r.Lines
    if ($r.Code -ne 0 -and $n -eq 0) {
        $hex = '{0:X8}' -f $r.Code
        if ($hex -eq '8A150014' -or $hex -eq '8A15002B') { return (New-CSWResult -Summary 'Todas las aplicaciones gestionadas por winget estan al dia') }
        return (New-CSWResult -Summary ("No se pudo consultar actualizaciones: {0}" -f (Get-CSWSwExitText $r.Code)) -Status Error)
    }
    if ($n -eq 0) { return (New-CSWResult -Summary 'Todas las aplicaciones gestionadas por winget estan al dia') }
    return (New-CSWResult -Summary "$n aplicacion(es) con actualizacion disponible" -Status Warn)
}

function Update-CSWSwAll {
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    Write-CSWLog 'Actualizando todas las aplicaciones (puede tardar varios minutos)...' -Level Step
    Write-CSWLog 'Consejo: cierre navegadores y programas abiertos para evitar fallos por archivos en uso.' -Level Info
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ('upgrade --all --silent --include-unknown --accept-source-agreements --accept-package-agreements' + $ctx.NoInteract)
    $hex = '{0:X8}' -f $r.Code
    if ($r.Code -eq 0) { return (New-CSWResult -Summary 'Aplicaciones actualizadas correctamente con winget') }
    if ($hex -eq '8A15002B' -or $hex -eq '8A150014') { return (New-CSWResult -Summary 'No habia actualizaciones pendientes') }
    if ($hex -eq '8A150109') { return (New-CSWResult -Summary 'Aplicaciones actualizadas; reinicie el equipo para completar' -Status Warn) }
    Write-CSWLog ("winget termino con: {0}" -f (Get-CSWSwExitText $r.Code)) -Level Warn
    return (New-CSWResult -Summary ("Actualizacion completada con incidencias: {0}. Revise el registro." -f (Get-CSWSwExitText $r.Code)) -Status Warn)
}

function Install-CSWSwPackageCore {
    # Instala un ID exacto; devuelve 'OK', 'Ya instalado', 'Reinicio' o 'Error'
    param($Ctx, [string]$Id)
    Write-CSWLog "Instalando $Id..." -Level Step
    $r = Invoke-CSWSwWinget -Ctx $Ctx -Arguments ("install --id $Id --exact --silent --source winget --accept-source-agreements --accept-package-agreements" + $Ctx.NoInteract)
    $hex = '{0:X8}' -f $r.Code
    if ($r.Code -eq 0) { Write-CSWLog "$Id instalado." -Level Ok; return 'OK' }
    if ($hex -eq '8A150061' -or $hex -eq '8A15002B') { Write-CSWLog "$Id ya estaba instalado y al dia." -Level Ok; return 'Ya instalado' }
    if ($hex -eq '8A150109') { Write-CSWLog "$Id instalado; requiere reinicio." -Level Warn; return 'Reinicio' }
    Write-CSWLog ("{0}: {1}" -f $Id, (Get-CSWSwExitText $r.Code)) -Level Error
    return 'Error'
}

function Install-CSWSwPack {
    param([string]$Pack = 'Basico: 7zip, VLC, Chrome, Adobe Reader')
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    $key = ($Pack -split ':')[0].Trim()
    if (-not $script:SwPacks.Contains($key)) {
        return (New-CSWResult -Summary "Pack desconocido: '$Pack'. Opciones: $(($script:SwPacks.Keys) -join ', ')" -Status Error)
    }
    $ids = @($script:SwPacks[$key])
    Write-CSWLog ("Pack {0}: {1}" -f $key, ($ids -join ', ')) -Level Step
    $results = foreach ($id in $ids) {
        $res = Install-CSWSwPackageCore -Ctx $ctx -Id $id
        [pscustomobject]@{ Paquete = $id; Resultado = $res }
    }
    $results = @($results)
    $results
    $err = @($results | Where-Object { $_.Resultado -eq 'Error' })
    $reboot = @($results | Where-Object { $_.Resultado -eq 'Reinicio' })
    $okCount = $results.Count - $err.Count
    if ($err.Count) {
        return (New-CSWResult -Summary ("Pack {0}: {1}/{2} instalados; fallaron: {3}" -f $key, $okCount, $results.Count, (($err | ForEach-Object { $_.Paquete }) -join ', ')) -Status Warn)
    }
    if ($reboot.Count) { return (New-CSWResult -Summary "Pack $key instalado; se requiere reiniciar" -Status Warn) }
    return (New-CSWResult -Summary ("Pack {0} instalado ({1} aplicaciones)" -f $key, $results.Count))
}

function Install-CSWSwPackage {
    param([string]$Id)
    if (-not $Id -or -not (Test-CSWSwPackageId $Id.Trim())) { return (New-CSWResult -Summary "ID de paquete no valido: '$Id' (ejemplo: 7zip.7zip)" -Status Error) }
    $Id = $Id.Trim()
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    $res = Install-CSWSwPackageCore -Ctx $ctx -Id $Id
    switch ($res) {
        'OK' { return (New-CSWResult -Summary "$Id instalado correctamente") }
        'Ya instalado' { return (New-CSWResult -Summary "$Id ya estaba instalado") }
        'Reinicio' { return (New-CSWResult -Summary "$Id instalado; reinicie para completar" -Status Warn) }
        default { return (New-CSWResult -Summary "No se pudo instalar $Id (revise el ID con 'Buscar paquete')" -Status Error) }
    }
}

function Find-CSWSwPackage {
    param([string]$Query)
    if (-not $Query -or -not $Query.Trim()) { return (New-CSWResult -Summary 'Indique un texto a buscar' -Status Error) }
    # Va entre comillas en la linea de comandos: se quitan comillas, acentos graves, barras
    # invertidas (una '\' final escaparia la comilla de cierre) y caracteres de control
    $q = ($Query -replace '["`\\\p{Cc}]', '').Trim()
    if ($q.Length -gt 100) { $q = $q.Substring(0, 100).Trim() }
    if (-not $q) { return (New-CSWResult -Summary 'Indique un texto a buscar' -Status Error) }
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    Write-CSWLog "Buscando '$q' en winget..." -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ("search --query `"$q`" --source winget --accept-source-agreements" + $ctx.NoInteract)
    $n = Get-CSWSwTableCount $r.Lines
    if ($r.Code -ne 0 -and $n -eq 0) {
        $hex = '{0:X8}' -f $r.Code
        if ($hex -eq '8A150014') { return (New-CSWResult -Summary "No se encontraron paquetes para '$q'" -Status Warn) }
        return (New-CSWResult -Summary ("Busqueda fallida: {0}" -f (Get-CSWSwExitText $r.Code)) -Status Error)
    }
    Write-CSWLog 'Use la columna Id con "Instalar paquete por ID".' -Level Info
    return (New-CSWResult -Summary "$n resultado(s) para '$q'")
}

function Remove-CSWSwPackage {
    param([string]$Id)
    if (-not $Id -or -not (Test-CSWSwPackageId $Id.Trim())) { return (New-CSWResult -Summary "ID de paquete no valido: '$Id'" -Status Error) }
    $Id = $Id.Trim()
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    Write-CSWLog "Desinstalando $Id..." -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ("uninstall --id $Id --exact --silent --accept-source-agreements" + $ctx.NoInteract)
    $hex = '{0:X8}' -f $r.Code
    if ($r.Code -eq 0) { return (New-CSWResult -Summary "$Id desinstalado correctamente") }
    if ($hex -eq '8A150014') { return (New-CSWResult -Summary "$Id no esta instalado en este equipo" -Status Warn) }
    if ($hex -eq '8A150109') { return (New-CSWResult -Summary "$Id desinstalado; reinicie para completar" -Status Warn) }
    return (New-CSWResult -Summary ("No se pudo desinstalar {0}: {1}" -f $Id, (Get-CSWSwExitText $r.Code)) -Status Error)
}

function Export-CSWSwApps {
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    $file = Join-Path (Get-CSWDataPath Backups) ('winget_apps_{0}_{1:yyyyMMdd_HHmmss}.json' -f $env:COMPUTERNAME, (Get-Date))
    Write-CSWLog "Exportando lista de aplicaciones a $file" -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ("export --output `"$file`" --source winget --accept-source-agreements" + $ctx.NoInteract)
    if (-not (Test-Path -LiteralPath $file)) { return (New-CSWResult -Summary ("No se pudo exportar la lista: {0}" -f (Get-CSWSwExitText $r.Code)) -Status Error) }
    $count = 0
    try {
        $j = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        foreach ($s in @($j.Sources)) { $count += @($s.Packages).Count }
    }
    catch { }
    if ($r.Code -ne 0) { Write-CSWLog 'Algunas aplicaciones no estan en winget y no se incluyeron (normal).' -Level Info }
    Write-CSWLog "Para restaurar en otro equipo use 'Importar lista de apps' con este archivo." -Level Info
    return (New-CSWResult -Summary "Lista de $count aplicaciones exportada a $file")
}

function Install-CSWSwImport {
    param([string]$Path)
    if (-not $Path) { return (New-CSWResult -Summary 'Indique la ruta del archivo JSON exportado con winget' -Status Error) }
    $Path = $Path.Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return (New-CSWResult -Summary "No existe el archivo: $Path" -Status Error) }
    $count = 0
    try {
        $j = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $j.PSObject.Properties['Sources']) { throw 'sin seccion Sources' }
        foreach ($s in @($j.Sources)) { $count += @($s.Packages).Count }
    }
    catch { return (New-CSWResult -Summary "El archivo no es una exportacion valida de winget ($($_.Exception.Message))" -Status Error) }
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    Write-CSWLog "Importando $count aplicaciones desde $Path (puede tardar)..." -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments ("import --import-file `"$Path`" --ignore-unavailable --accept-source-agreements --accept-package-agreements" + $ctx.NoInteract)
    if ($r.Code -eq 0) { return (New-CSWResult -Summary "Importacion completada ($count aplicaciones en la lista)") }
    Write-CSWLog ("winget import: {0}" -f (Get-CSWSwExitText $r.Code)) -Level Warn
    return (New-CSWResult -Summary ("Importacion con incidencias: {0}. Revise el registro." -f (Get-CSWSwExitText $r.Code)) -Status Warn)
}

function Repair-CSWSwSources {
    $ctx = Get-CSWSwContext
    if (-not $ctx) { return (Get-CSWSwMissingWingetResult) }
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    Write-CSWLog 'Restableciendo fuentes de winget...' -Level Step
    $r = Invoke-CSWSwWinget -Ctx $ctx -Arguments 'source reset --force'
    if ($r.Code -ne 0) { Write-CSWLog ("source reset: {0}" -f (Get-CSWSwExitText $r.Code)) -Level Warn }
    Write-CSWLog 'Actualizando fuentes...' -Level Step
    $u = Invoke-CSWSwWinget -Ctx $ctx -Arguments 'source update'
    if ($r.Code -eq 0 -and $u.Code -eq 0) { return (New-CSWResult -Summary 'Fuentes de winget restablecidas y actualizadas') }
    return (New-CSWResult -Summary ("Reparacion de fuentes con incidencias: {0}" -f (Get-CSWSwExitText ([int]($r.Code -bor $u.Code)))) -Status Warn)
}

# ---------------------------------------------------------------------------
# Acciones bloatware (AppX)
# ---------------------------------------------------------------------------
function Get-CSWSwBloatware {
    if (-not (Initialize-CSWSwAppx)) { return (New-CSWResult -Summary 'El modulo Appx no esta disponible en esta sesion' -Status Warn) }
    Write-CSWLog 'Buscando apps preinstaladas prescindibles (lista curada conservadora)...' -Level Step
    $items = @(Get-CSWSwBloatInventory)
    if (-not $items.Count) { return (New-CSWResult -Summary 'No se encontraron apps preinstaladas prescindibles') }
    $items | Select-Object Ambito, Nombre, Version
    $u = @($items | Where-Object { $_.Ambito -eq 'Usuario' }).Count
    $p = @($items | Where-Object { $_.Ambito -eq 'Aprovisionado' }).Count
    return (New-CSWResult -Summary ("{0} apps prescindibles encontradas ({1} del usuario, {2} aprovisionadas)" -f @($items | Select-Object -ExpandProperty Nombre -Unique).Count, $u, $p))
}

function Remove-CSWSwBloatware {
    if (-not (Initialize-CSWSwAppx)) { return (New-CSWResult -Summary 'El modulo Appx no esta disponible en esta sesion' -Status Warn) }
    Write-CSWLog 'Eliminando apps de la lista curada (usuario actual y aprovisionadas)...' -Level Step
    $items = @(Get-CSWSwBloatInventory)
    if (-not $items.Count) { return (New-CSWResult -Summary 'No habia apps prescindibles que eliminar') }
    $ok = 0
    $fail = @()
    foreach ($it in $items) {
        # Doble comprobacion de seguridad antes de eliminar
        if (Test-CSWSwProtected $it.Nombre) { Write-CSWLog "Omitida (protegida): $($it.Nombre)" -Level Info; continue }
        try {
            if ($it.Ambito -eq 'Usuario') { Remove-AppxPackage -Package $it.Paquete -ErrorAction Stop }
            else { [void](Remove-AppxProvisionedPackage -Online -PackageName $it.Paquete -ErrorAction Stop) }
            Write-CSWLog ("Eliminada ({0}): {1}" -f $it.Ambito, $it.Nombre) -Level Ok
            $ok++
        }
        catch {
            Write-CSWLog ("No se pudo eliminar {0} ({1}): {2}" -f $it.Nombre, $it.Ambito, $_.Exception.Message) -Level Warn
            $fail += $it.Nombre
        }
    }
    if ($fail.Count) { return (New-CSWResult -Summary ("{0} apps prescindibles eliminadas; {1} no se pudieron quitar" -f $ok, $fail.Count) -Status Warn) }
    return (New-CSWResult -Summary "$ok apps preinstaladas prescindibles eliminadas")
}

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------
Register-CSWModule -Id 'Software' -Name 'Software' -Order 60 -Icon 'package' `
    -Description 'Instalación y actualización de aplicaciones con winget y limpieza de apps preinstaladas' -Actions @(
    @{ Id = 'CheckWinget'; Name = 'Comprobar winget'; Command = 'Test-CSWSwWinget'; Risk = 'Low'
        Description = 'Verifica que winget esté instalado, su versión y sus fuentes' },
    @{ Id = 'ListUpdates'; Name = 'Ver actualizaciones'; Command = 'Get-CSWSwUpdates'; Risk = 'Low'
        Description = 'Lista las aplicaciones con actualización disponible (winget upgrade)' },
    @{ Id = 'UpdateAll'; Name = 'Actualizar todo'; Command = 'Update-CSWSwAll'; Risk = 'Medium'; LongRunning = $true; ModifiesSystem = $true
        ConfirmMessage = 'Se actualizarán en silencio todas las aplicaciones con versión nueva. Cierre los programas abiertos; puede tardar varios minutos.'
        Description = 'Actualiza todas las aplicaciones en modo silencioso con winget' },
    @{ Id = 'InstallPack'; Name = 'Instalar pack'; Command = 'Install-CSWSwPack'; Risk = 'Medium'; LongRunning = $true; ModifiesSystem = $true
        ConfirmMessage = 'Se instalarán en silencio las aplicaciones del pack seleccionado.'
        Description = 'Instala un conjunto predefinido de aplicaciones (básico, técnico u oficina)'
        Inputs = @(@{ Name = 'Pack'; Label = 'Pack'; Type = 'Choice'; Choices = $script:SwPackChoices; Default = $script:SwPackChoices[0] }) },
    @{ Id = 'InstallPackage'; Name = 'Instalar paquete por ID'; Command = 'Install-CSWSwPackage'; Risk = 'Medium'; ModifiesSystem = $true
        ConfirmMessage = 'Se instalará en silencio el paquete indicado desde el repositorio de winget.'
        Description = 'Instala un paquete de winget por su ID exacto'
        Inputs = @(@{ Name = 'Id'; Label = 'ID de winget (ej. 7zip.7zip)'; Default = '' }) },
    @{ Id = 'SearchPackage'; Name = 'Buscar paquete'; Command = 'Find-CSWSwPackage'; Risk = 'Low'
        Description = 'Busca aplicaciones en el repositorio de winget para obtener su ID'
        Inputs = @(@{ Name = 'Query'; Label = 'Texto a buscar'; Default = '' }) },
    @{ Id = 'UninstallPackage'; Name = 'Desinstalar paquete'; Command = 'Remove-CSWSwPackage'; Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'Se desinstalará la aplicación indicada y podrían perderse sus datos o configuración.'
        Description = 'Desinstala una aplicación por su ID de winget'
        Inputs = @(@{ Name = 'Id'; Label = 'ID de winget'; Default = '' }) },
    @{ Id = 'ExportApps'; Name = 'Exportar lista de apps'; Command = 'Export-CSWSwApps'; Risk = 'Low'
        Description = 'Guarda en Backups un JSON con las aplicaciones instaladas para reinstalarlas después' },
    @{ Id = 'ImportApps'; Name = 'Importar lista de apps'; Command = 'Install-CSWSwImport'; Risk = 'Medium'; LongRunning = $true; ModifiesSystem = $true
        ConfirmMessage = 'Se instalarán todas las aplicaciones de la lista exportada.'
        Description = 'Instala las aplicaciones de un archivo exportado con winget'
        Inputs = @(@{ Name = 'Path'; Label = 'Ruta del archivo JSON'; Default = '' }) },
    @{ Id = 'ListBloatware'; Name = 'Ver apps prescindibles'; Command = 'Get-CSWSwBloatware'; Risk = 'Low'
        Description = 'Lista las apps preinstaladas prescindibles presentes (lista curada conservadora)' },
    @{ Id = 'RemoveBloatware'; Name = 'Quitar apps prescindibles'; Command = 'Remove-CSWSwBloatware'; Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'Se eliminarán las apps preinstaladas de la lista curada (juegos, noticias, Skype, Clipchamp...) para el usuario actual y para usuarios nuevos. Se pueden reinstalar desde Microsoft Store.'
        Description = 'Elimina las apps prescindibles de la lista curada (nunca Store, Calculadora, Fotos, Edge ni componentes del sistema)' },
    @{ Id = 'RepairSources'; Name = 'Reparar fuentes winget'; Command = 'Repair-CSWSwSources'; Risk = 'Medium'
        ConfirmMessage = 'Se restablecerán las fuentes de winget a su configuración por defecto (se eliminan fuentes personalizadas).'
        Description = 'Restablece y actualiza las fuentes de winget (winget source reset --force)' }
)

Export-ModuleMember -Function *
