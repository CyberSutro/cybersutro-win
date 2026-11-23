#Requires -Version 5.1
<#
    Cybersutro win - Nucleo (CSW.Core)
    Registro de modulos/acciones, log, punto de restauracion, historial e informe HTML.
    Compatible con Windows PowerShell 5.1 y PowerShell 7.
    Ver docs/CONTRATO.md para el contrato que deben cumplir los modulos.
#>

Set-StrictMode -Version 2.0

$script:CSWVersion = '1.0.0'

# ---------------------------------------------------------------------------
# Estado compartido (sincronizado: la GUI lo comparte con su runspace de trabajo)
# ---------------------------------------------------------------------------
function Initialize-CSWCore {
    [CmdletBinding()]
    param(
        [hashtable]$State,
        [string]$RootPath
    )
    if ($State) {
        $global:CSW = $State
    }
    elseif (-not (Get-Variable -Name CSW -Scope Global -ErrorAction SilentlyContinue)) {
        $global:CSW = [hashtable]::Synchronized(@{})
    }

    if (-not $global:CSW.ContainsKey('DataPath')) {
        # Como administrador: C:\ProgramData\CybersutroWin restringida a Administradores y SYSTEM
        # (logs, informes y copias contienen datos del cliente y, a veces, secretos).
        # Sin privilegios: %LOCALAPPDATA%\CybersutroWin (privada del usuario por defecto).
        $isAdminNow = $false
        try { $isAdminNow = [bool](Test-CSWAdmin) } catch { }
        $data = Join-Path $env:ProgramData 'CybersutroWin'
        if (-not $isAdminNow -and $env:LOCALAPPDATA) { $data = Join-Path $env:LOCALAPPDATA 'CybersutroWin' }
        foreach ($sub in 'Logs', 'Reports', 'Backups') {
            $p = Join-Path $data $sub
            if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
        }
        $aclNote = ''
        if ($isAdminNow) { $aclNote = Protect-CSWDataFolder -Path $data }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $global:CSW.Version           = $script:CSWVersion
        $global:CSW.DataPath          = $data
        $global:CSW.LogFile           = Join-Path $data ("Logs\CSW_{0}_{1}.log" -f $env:COMPUTERNAME, $stamp)
        $global:CSW.SessionStart      = Get-Date
        $global:CSW.History           = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $global:CSW.LogLines          = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $global:CSW.LogQueue          = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
        $global:CSW.RestorePointDone  = $false
        $global:CSW.TechName          = $env:USERNAME
        $global:CSW.ClientName        = ''
        $global:CSW.Notes             = ''
        $global:CSW.DataAclNote       = $aclNote
        if ($aclNote) { Write-CSWLog $aclNote -Level Warn }
    }
    if ($RootPath) { $global:CSW.RootPath = $RootPath }
    if (-not $global:CSW.ContainsKey('ReportSections')) { $global:CSW.ReportSections = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) }
    if (-not $global:CSW.ContainsKey('Modules')) { $global:CSW.Modules = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) }
}

function Protect-CSWDataFolder {
    <#
        Deja la carpeta de datos accesible solo para Administradores y SYSTEM (sin herencia),
        con propietario Administradores. Si ya estaba asi no hace nada (evita recorrer backups
        grandes en cada arranque). Tolera fallos: devuelve texto vacio o el motivo del aviso.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        $adm = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $sys = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $di = New-Object System.IO.DirectoryInfo($Path)
        $cur = $di.GetAccessControl()
        $rules = @($cur.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $owner = $cur.GetOwner([System.Security.Principal.SecurityIdentifier])
        $extra = @($rules | Where-Object { $_.IdentityReference -ne $adm -and $_.IdentityReference -ne $sys })
        if ($cur.AreAccessRulesProtected -and $extra.Count -eq 0 -and $rules.Count -gt 0 -and $owner -eq $adm) { return '' }

        $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $full = [System.Security.AccessControl.FileSystemRights]::FullControl
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adm, $full, $inh, $prop, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sys, $full, $inh, $prop, $allow)))
        try { $acl.SetOwner($adm) } catch { }
        try { $di.SetAccessControl($acl) }
        catch {
            # Sin permiso para cambiar el propietario (carpeta creada por otro usuario): solo DACL
            $acl2 = New-Object System.Security.AccessControl.DirectorySecurity
            $acl2.SetAccessRuleProtection($true, $false)
            foreach ($r in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) { $acl2.AddAccessRule($r) }
            $di.SetAccessControl($acl2)
        }
        # Los elementos ya existentes pasan a heredar la nueva ACL
        $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
        if (Test-Path -LiteralPath $icacls) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo($icacls, ('"{0}\*" /reset /T /C /Q' -f $Path.TrimEnd('\')))
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $pr = [System.Diagnostics.Process]::Start($psi)
            if (-not $pr.WaitForExit(120000)) { try { $pr.Kill() } catch { } }
        }
        return ''
    }
    catch { return ("No se pudieron restringir los permisos de {0}: {1}" -f $Path, $_.Exception.Message) }
}

function Get-CSWState { if (-not (Get-Variable CSW -Scope Global -ErrorAction SilentlyContinue)) { Initialize-CSWCore }; return $global:CSW }

function Get-CSWDataPath {
    param([ValidateSet('Root', 'Logs', 'Reports', 'Backups')][string]$Kind = 'Root')
    $s = Get-CSWState
    if ($Kind -eq 'Root') { return $s.DataPath }
    return (Join-Path $s.DataPath $Kind)
}

# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------
function Write-CSWLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Ok', 'Warn', 'Error', 'Step', 'Data')][string]$Level = 'Info'
    )
    $s = Get-CSWState
    $entry = [pscustomobject]@{ Time = Get-Date; Level = $Level; Message = $Message }
    $line = '[{0:HH:mm:ss}] [{1,-5}] {2}' -f $entry.Time, $Level.ToUpper(), $Message
    try { Add-Content -Path $s.LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    [void]$s.LogLines.Add($entry)

    # En GUI se encola para el panel de log; en consola se muestra directamente
    if ($s.ContainsKey('GuiMode') -and $s.GuiMode) { $s.LogQueue.Enqueue($entry) }
    else {
        $color = switch ($Level) { 'Ok' { 'Green' } 'Warn' { 'Yellow' } 'Error' { 'Red' } 'Step' { 'Cyan' } 'Data' { 'Gray' } default { 'White' } }
        Write-Host $line -ForegroundColor $color
    }
}

# Convierte la salida de una accion (objetos o texto) en lineas de log tipo 'Data'
function Write-CSWOutput {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin { $items = New-Object System.Collections.ArrayList }
    process {
        if ($null -eq $InputObject) { return }
        # Fechas visibles siempre como dd/MM/yyyy HH:mm, independientemente de la cultura del sistema
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hasDate = $false
            foreach ($pp in $InputObject.PSObject.Properties) { if ($pp.Value -is [datetime]) { $hasDate = $true; break } }
            if ($hasDate) {
                $o = [ordered]@{}
                foreach ($pp in $InputObject.PSObject.Properties) {
                    if ($pp.Value -is [datetime]) { $o[$pp.Name] = Format-CSWDate $pp.Value -WithTime } else { $o[$pp.Name] = $pp.Value }
                }
                $InputObject = [pscustomobject]$o
            }
        }
        [void]$items.Add($InputObject)
    }
    end {
        if ($items.Count -eq 0) { return }
        if ($items[0] -is [string]) { $text = ($items -join [Environment]::NewLine) }
        else { $text = ($items | Format-Table -AutoSize | Out-String -Width 200) }
        foreach ($l in ($text -split "`r?`n")) {
            if ($l.Trim()) { Write-CSWLog -Message $l.TrimEnd() -Level Data }
        }
    }
}

# ---------------------------------------------------------------------------
# Registro de modulos y acciones
# ---------------------------------------------------------------------------
function Register-CSWModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = '',
        [string]$Icon = '',
        [int]$Order = 50,
        [Parameter(Mandatory)][object[]]$Actions
    )
    $s = Get-CSWState
    $acts = foreach ($a in $Actions) {
        $h = @{} + $a
        foreach ($req in 'Id', 'Name', 'Command') { if (-not $h.ContainsKey($req)) { throw "Accion de '$Id' sin '$req'" } }
        if (-not $h.ContainsKey('Description'))    { $h.Description = '' }
        if (-not $h.ContainsKey('Risk'))           { $h.Risk = 'Low' }
        if (-not $h.ContainsKey('ModifiesSystem')) { $h.ModifiesSystem = $false }
        if (-not $h.ContainsKey('ConfirmMessage')) { $h.ConfirmMessage = '' }
        if (-not $h.ContainsKey('Inputs'))         { $h.Inputs = @() }
        if (-not $h.ContainsKey('LongRunning'))    { $h.LongRunning = $false }
        $h.ModuleId = $Id
        $h.FullId = "$Id.$($h.Id)"
        [pscustomobject]$h
    }
    $existing = @($s.Modules | Where-Object { $_.Id -eq $Id })
    foreach ($e in $existing) { [void]$s.Modules.Remove($e) }
    [void]$s.Modules.Add([pscustomobject]@{
            Id = $Id; Name = $Name; Description = $Description; Icon = $Icon; Order = $Order; Actions = @($acts)
        })
}

function Get-CSWModule {
    param([string]$Id)
    $s = Get-CSWState
    $m = @($s.Modules | Sort-Object Order, Name)
    if ($Id) { $m = @($m | Where-Object { $_.Id -eq $Id }) }
    return $m
}

function Get-CSWAction {
    param([Parameter(Mandatory)][string]$FullId)
    foreach ($m in (Get-CSWModule)) {
        foreach ($a in $m.Actions) { if ($a.FullId -eq $FullId) { return $a } }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Confirmacion (solo consola; la GUI confirma con MessageBox antes de invocar)
# ---------------------------------------------------------------------------
function Confirm-CSWAction {
    param([Parameter(Mandatory)]$Action)
    if ($Action.Risk -eq 'Low') { return $true }
    $msg = $Action.ConfirmMessage
    if (-not $msg) { $msg = "La accion '$($Action.Name)' modifica el sistema." }
    Write-Host ''
    Write-Host ("  [!] Riesgo {0}: {1}" -f $Action.Risk, $msg) -ForegroundColor Yellow
    $r = Read-Host '  Escriba S para continuar'
    return ($r -match '^(s|si|y|yes)$')
}

# ---------------------------------------------------------------------------
# Punto de restauracion
# ---------------------------------------------------------------------------
function New-CSWRestorePoint {
    [CmdletBinding()]
    param([string]$Description = 'Cybersutro win - antes de mantenimiento', [switch]$Force)
    $s = Get-CSWState
    if ($s.RestorePointDone -and -not $Force) { return $true }
    Write-CSWLog 'Creando punto de restauracion del sistema...' -Level Step
    if (-not (Test-CSWAdmin)) {
        Write-CSWLog 'No se pudo crear el punto de restauracion: requiere ejecutar como administrador.' -Level Warn
        return $false
    }
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $prevExists = $false; $prev = $null; $changed = $false
    try {
        # Windows limita a un punto cada 24 h: se desactiva temporalmente el limite y se restaura despues
        $item = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties['SystemRestorePointCreationFrequency']) {
            $prevExists = $true; $prev = $item.SystemRestorePointCreationFrequency
        }
        try { Set-ItemProperty -Path $key -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord -ErrorAction Stop; $changed = $true } catch { }
        if (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue) {
            try { Enable-ComputerRestore -Drive "$($env:SystemDrive)\" -ErrorAction Stop } catch { }
            Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        }
        else {
            # PowerShell 7 no incluye Checkpoint-Computer: se usa la clase WMI SystemRestore
            try { [void](Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName Enable -Arguments @{ Drive = "$($env:SystemDrive)\" } -ErrorAction Stop) } catch { }
            $r = Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName CreateRestorePoint -Arguments @{ Description = $Description; RestorePointType = [uint32]12; EventType = [uint32]100 } -ErrorAction Stop
            if ([int]$r.ReturnValue -ne 0) { throw ("CreateRestorePoint devolvio {0}" -f $r.ReturnValue) }
        }
        $s.RestorePointDone = $true
        Write-CSWLog 'Punto de restauracion creado.' -Level Ok
        return $true
    }
    catch {
        Write-CSWLog "No se pudo crear el punto de restauracion: $($_.Exception.Message)" -Level Warn
        return $false
    }
    finally {
        if ($changed) {
            if ($prevExists) { Set-ItemProperty -Path $key -Name SystemRestorePointCreationFrequency -Value $prev -ErrorAction SilentlyContinue }
            else { Remove-ItemProperty -Path $key -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------------------
# Ejecucion de acciones
# ---------------------------------------------------------------------------
function Invoke-CSWAction {
    <#
        Ejecuta una accion registrada. NO pide confirmacion (eso lo hace la UI).
        -Params: hashtable con los valores de los Inputs de la accion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Action,
        [hashtable]$Params = @{},
        [switch]$SkipRestorePoint
    )
    if ($Action -is [string]) { $Action = Get-CSWAction -FullId $Action; if (-not $Action) { throw 'Accion no encontrada' } }
    $s = Get-CSWState

    if ($Action.ModifiesSystem -and -not $SkipRestorePoint -and -not $s.RestorePointDone) {
        [void](New-CSWRestorePoint)
    }

    $start = Get-Date
    Write-CSWLog ("==> {0}" -f $Action.Name) -Level Step
    $status = 'OK'; $summary = ''
    try {
        $out = & $Action.Command @Params
        $res = @($out)
        # Una accion puede devolver un objeto resumen: @{ CSWSummary = '...'; CSWStatus = 'OK|Warn|Error' }
        $sumObj = @($res | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('CSWSummary') }) | Select-Object -Last 1
        $rest = @($res | Where-Object { -not ($_ -is [hashtable] -and $_.ContainsKey('CSWSummary')) })
        if ($rest.Count) { $rest | Write-CSWOutput }
        if ($sumObj) {
            $summary = [string]$sumObj.CSWSummary
            if ($sumObj.ContainsKey('CSWStatus')) { $status = [string]$sumObj.CSWStatus }
        }
        if ($status -eq 'OK') { Write-CSWLog ("Completado: {0} {1}" -f $Action.Name, $summary) -Level Ok }
        else { Write-CSWLog ("Finalizado con avisos: {0} {1}" -f $Action.Name, $summary) -Level Warn }
    }
    catch {
        $status = 'Error'; $summary = $_.Exception.Message
        Write-CSWLog ("Error en {0}: {1}" -f $Action.Name, $summary) -Level Error
    }
    $dur = (Get-Date) - $start
    [void]$s.History.Add([pscustomobject]@{
            Time     = $start
            Module   = $Action.ModuleId
            Action   = $Action.Name
            FullId   = $Action.FullId
            Params   = (($Params.GetEnumerator() | ForEach-Object {
                        if ($_.Key -match 'Pass|Secret|Key|Token') { "$($_.Key)=****" } else { "$($_.Key)=$($_.Value)" }
                    }) -join '; ')
            Status   = $status
            Summary  = $summary
            Duration = ('{0:mm\:ss}' -f $dur)
        })
    return $status
}

# ---------------------------------------------------------------------------
# Reparacion rapida (un clic)
# ---------------------------------------------------------------------------
$script:QuickRepairSteps = @(
    'Disk.CleanTemp',
    'Network.FlushDns',
    'Network.ConnectivityTest',
    'Repair.DismRestore',
    'Repair.Sfc',
    'Diagnostics.CriticalEvents'
)

function Get-CSWQuickRepairSteps { return $script:QuickRepairSteps }

function Invoke-CSWQuickRepair {
    [CmdletBinding()]
    param([switch]$NoReport)
    Write-CSWLog '##### REPARACION RAPIDA #####' -Level Step
    [void](New-CSWRestorePoint)
    $i = 0
    foreach ($id in $script:QuickRepairSteps) {
        $i++
        $a = Get-CSWAction -FullId $id
        if (-not $a) { Write-CSWLog "Paso $id no disponible, se omite." -Level Warn; continue }
        Write-CSWLog ("Paso {0}/{1}" -f $i, $script:QuickRepairSteps.Count) -Level Info
        [void](Invoke-CSWAction -Action $a -SkipRestorePoint)
    }
    Write-CSWLog '##### REPARACION RAPIDA FINALIZADA #####' -Level Ok
    if (-not $NoReport) { return (Export-CSWReport) }
}

# ---------------------------------------------------------------------------
# Informe HTML
# ---------------------------------------------------------------------------
function ConvertTo-CSWHtmlText([string]$t) { if ($null -eq $t) { return '' }; return [System.Net.WebUtility]::HtmlEncode($t) }

function Add-CSWReportSection {
    <#
        Agrega (o reemplaza, por Id) una seccion propia al informe HTML del servicio.
        -Html es el contenido interno de la tarjeta (sin <div class=card>). Clases CSS
        disponibles: table, .badge .ok/.warn/.err, .kpis/.kpi, .muted, .score.
        Todo texto variable debe pasar por ConvertTo-CSWHtmlText.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Html,
        [int]$Order = 50
    )
    $s = Get-CSWState
    $old = @($s.ReportSections | Where-Object { $_.Id -eq $Id })
    foreach ($o in $old) { [void]$s.ReportSections.Remove($o) }
    [void]$s.ReportSections.Add([pscustomobject]@{ Id = $Id; Title = $Title; Html = $Html; Order = $Order })
}

function Get-CSWSystemSummary {
    $o = [ordered]@{}
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $o['Equipo'] = $env:COMPUTERNAME
        $o['Fabricante / Modelo'] = "$($cs.Manufacturer) $($cs.Model)"
        $o['N/S'] = if ($bios) { $bios.SerialNumber } else { '' }
        $o['Sistema'] = "$($os.Caption) ($($os.Version), build $($os.BuildNumber))"
        $o['Procesador'] = $cpu.Name.Trim()
        $o['RAM'] = '{0:N1} GB' -f ($cs.TotalPhysicalMemory / 1GB)
        $o['Ultimo arranque'] = Format-CSWDate $os.LastBootUpTime -WithTime
        $disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
        $o['Discos'] = (($disks | ForEach-Object { '{0} {1:N0}/{2:N0} GB libres' -f $_.DeviceID, ($_.FreeSpace / 1GB), ($_.Size / 1GB) }) -join ' | ')
    }
    catch { $o['Equipo'] = $env:COMPUTERNAME }
    return $o
}

function Export-CSWReport {
    [CmdletBinding()]
    param([string]$Path, [switch]$Open)
    $s = Get-CSWState
    if (-not $Path) {
        $Path = Join-Path (Get-CSWDataPath Reports) ("Informe_{0}_{1:yyyyMMdd_HHmm}.html" -f $env:COMPUTERNAME, (Get-Date))
    }
    $sys = Get-CSWSystemSummary
    $keyNames = @{ 'Ultimo arranque' = 'Último arranque'; 'N/S' = 'Número de serie' }
    $sysRows = ($sys.GetEnumerator() | ForEach-Object {
            $k = [string]$_.Key
            if ($keyNames.ContainsKey($k)) { $k = $keyNames[$k] }
            "<tr><th>$(ConvertTo-CSWHtmlText $k)</th><td>$(ConvertTo-CSWHtmlText ([string]$_.Value))</td></tr>"
        }) -join "`n"

    # ToArray: copia bajo bloqueo (el runspace de trabajo puede estar escribiendo a la vez)
    $hist = @($s.History.ToArray())
    $ok = @($hist | Where-Object Status -eq 'OK').Count
    $warn = @($hist | Where-Object Status -eq 'Warn').Count
    $err = @($hist | Where-Object Status -eq 'Error').Count
    $histRows = ($hist | ForEach-Object {
            $cls = switch ($_.Status) { 'OK' { 'ok' } 'Warn' { 'warn' } default { 'err' } }
            $lbl = switch ($_.Status) { 'OK' { 'Correcta' } 'Warn' { 'Con avisos' } 'Error' { 'Error' } default { [string]$_.Status } }
            "<tr><td class='nowrap'>{0:HH:mm:ss}</td><td>{1}</td><td><b>{2}</b></td><td><span class='badge {3}'>{4}</span></td><td>{5}</td><td class='nowrap'>{6}</td></tr>" -f $_.Time, (ConvertTo-CSWHtmlText $_.Module), (ConvertTo-CSWHtmlText $_.Action), $cls, (ConvertTo-CSWHtmlText $lbl), (ConvertTo-CSWHtmlText $_.Summary), (ConvertTo-CSWHtmlText $_.Duration)
        }) -join "`n"
    if (-not $histRows) { $histRows = "<tr><td colspan='6' class='muted'>No se ejecutaron acciones en esta sesi&oacute;n.</td></tr>" }

    $sections = @($s.ReportSections.ToArray())
    $logText = ConvertTo-CSWHtmlText ((@($s.LogLines.ToArray()) | ForEach-Object { '[{0:HH:mm:ss}] [{1}] {2}' -f $_.Time, $_.Level, $_.Message }) -join "`n")

    # Estado general del servicio (solo presentación)
    $total = $hist.Count
    if ($total -eq 0) { $stCls = 'st-mute'; $stTxt = 'Sin acciones registradas' }
    elseif ($err -gt 0) { $stCls = 'st-err'; $stTxt = 'Servicio con incidencias' }
    elseif ($warn -gt 0) { $stCls = 'st-warn'; $stTxt = 'Completado con avisos' }
    else { $stCls = 'st-ok'; $stTxt = 'Completado correctamente' }
    $stack = ''
    if ($total -gt 0) {
        $stack = "<div class='stack' title='Resultado de las acciones'><i class='s-ok' style='flex:$ok'></i><i class='s-warn' style='flex:$warn'></i><i class='s-err' style='flex:$err'></i></div>" +
        "<div class='legend'><span><i class='s-ok'></i>Correctas $ok</span><span><i class='s-warn'></i>Con avisos $warn</span><span><i class='s-err'></i>Con errores $err</span></div>"
    }
    $now = Get-Date
    $comp = ConvertTo-CSWHtmlText $env:COMPUTERNAME
    $ref = ConvertTo-CSWHtmlText ('CSW-{0}-{1:yyyyMMdd-HHmm}' -f $env:COMPUTERNAME, $now)
    $verTxt = ConvertTo-CSWHtmlText ([string]$s.Version)
    $techTxt = '&mdash;'
    if ($s.TechName) { $techTxt = ConvertTo-CSWHtmlText ([string]$s.TechName) }
    $clientTxt = '&mdash;'
    if ($s.ClientName) { $clientTxt = ConvertTo-CSWHtmlText ([string]$s.ClientName) }
    $dateTxt = ConvertTo-CSWHtmlText (Format-CSWDate $now -WithTime)
    $rpTxt = 'No'; $rpCls = 'k-mute'
    if ($s.RestorePointDone) { $rpTxt = 'S&iacute;'; $rpCls = 'k-ok' }
    $sectionHtml = ($sections | Sort-Object Order | ForEach-Object { "<section class='card'><h2>$(ConvertTo-CSWHtmlText $_.Title)</h2>$($_.Html)</section>" }) -join "`n"
    $notesHtml = ''
    if ($s.Notes) { $notesHtml = "<section class='card'><h2>Observaciones del t&eacute;cnico</h2><p class='notes'>$(ConvertTo-CSWHtmlText $s.Notes)</p></section>" }

    $logo = @'
<svg viewBox="0 0 64 64" role="img" aria-label="Cybersutro win"><defs><linearGradient id="cswg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2A86E0"/><stop offset=".55" stop-color="#0B5CAD"/><stop offset="1" stop-color="#073F78"/></linearGradient></defs><path d="M32 3 56 11.5V30c0 15.5-10.4 26.6-24 31C18.4 56.6 8 45.5 8 30V11.5Z" fill="url(#cswg)"/><path d="M32 3 8 11.5V30c0 15.5 10.4 26.6 24 31Z" fill="#fff" opacity=".13"/><path d="M13 32h8.5L26 21l6.5 22L37 32h7.5" fill="none" stroke="#fff" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="49.5" cy="32" r="3.7" fill="#5CD6FF"/></svg>
'@
    $css = @'
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

    $html = @"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de servicio t&eacute;cnico - $comp</title>
<style>
$css
</style></head><body>
<div class="page">
<div class="topbar"></div>
<header class="doc-head">
  <div class="brand">$logo<div><div class="wordmark"><b>Cybersutro</b><span> win</span></div><div class="tagline">Soporte t&eacute;cnico para Windows</div></div></div>
  <div class="doc-meta"><h1 class="doc-title">Informe de servicio t&eacute;cnico</h1><div class="doc-sub">Ref. $ref &middot; $dateTxt</div></div>
</header>
<div class="meta-grid">
  <div><label>Equipo</label><div>$comp</div></div>
  <div><label>Cliente</label><div>$clientTxt</div></div>
  <div><label>T&eacute;cnico</label><div>$techTxt</div></div>
  <div><label>Herramienta</label><div>Cybersutro win v$verTxt</div></div>
</div>
<main class="content">
<section class="card"><div class="sumhead"><h2 style="border:0;padding:0;margin:0">Resumen del servicio</h2><span class="status $stCls">$stTxt</span></div>
<div class="kpis">
<div class="kpi k-brand"><b>$total</b><span>Acciones ejecutadas</span></div>
<div class="kpi k-ok"><b style="color:var(--ok)">$ok</b><span>Correctas</span></div>
<div class="kpi k-warn"><b style="color:var(--warn)">$warn</b><span>Con avisos</span></div>
<div class="kpi k-err"><b style="color:var(--err)">$err</b><span>Con errores</span></div>
<div class="kpi $rpCls"><b>$rpTxt</b><span>Punto de restauraci&oacute;n</span></div>
</div>$stack</section>
<section class="card"><h2>Equipo</h2><table class="kv">$sysRows</table></section>
$sectionHtml
<section class="card"><h2>Acciones realizadas</h2><table><thead><tr><th style="width:74px">Hora</th><th style="width:110px">M&oacute;dulo</th><th style="width:auto">Acci&oacute;n</th><th style="width:96px">Estado</th><th style="width:auto">Resultado</th><th style="width:80px">Duraci&oacute;n</th></tr></thead><tbody>
$histRows
</tbody></table></section>
$notesHtml
<section class="card"><h2>Conformidad</h2><p class="muted" style="margin-top:0">El cliente declara haber recibido el equipo y la informaci&oacute;n de este informe.</p><div class="sign"><div>Firma del t&eacute;cnico</div><div>Conformidad del cliente</div></div></section>
<section class="card logcard"><h2>Registro detallado</h2><pre class="log">$logText</pre></section>
</main>
<footer class="doc-foot"><span>Generado por Cybersutro win v$verTxt &middot; $dateTxt</span><span>$comp &middot; Ref. $ref</span></footer>
</div>
</body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
    Write-CSWLog "Informe generado: $Path" -Level Ok
    if ($Open) { Start-Process $Path }
    return $Path
}

# ---------------------------------------------------------------------------
# Utilidades para modulos
# ---------------------------------------------------------------------------
function Test-CSWAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Programas que NO se matan si el tecnico pulsa Detener (interrumpirlos a mitad puede dejar
# el sistema o el disco en mal estado); la GUI avisa de que pueden seguir en segundo plano.
$script:CSWNoKillOnStop = @('sfc.exe', 'dism.exe', 'chkdsk.exe', 'defrag.exe', 'winmgmt.exe', 'pnputil.exe', 'cleanmgr.exe')

function Stop-CSWProcessTree {
    <# Termina un proceso y sus hijos (taskkill /T) usando solo .NET: funciona aunque la canalizacion se este deteniendo. #>
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { if ($Process.HasExited) { return } } catch { return }
    try {
        $tk = Join-Path $env:SystemRoot 'System32\taskkill.exe'
        $psi = New-Object System.Diagnostics.ProcessStartInfo($tk, ('/T /F /PID {0}' -f $Process.Id))
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $k = [System.Diagnostics.Process]::Start($psi)
        [void]$k.WaitForExit(10000)
    }
    catch { }
    try { if (-not $Process.HasExited) { $Process.Kill() } } catch { }
}

function New-CSWProcess {
    # Proceso sin ventana, con salida redirigida y entrada estandar CERRADA: un programa que pida
    # confirmacion recibe fin de archivo en lugar de quedarse esperando para siempre (en la GUI no hay consola).
    param([string]$FilePath, [string]$Arguments, [System.Text.Encoding]$Encoding)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    if ($null -eq $Encoding) {
        try { $Encoding = [System.Text.Encoding]::GetEncoding([Console]::OutputEncoding.CodePage) } catch { $Encoding = $null }
    }
    if ($null -ne $Encoding) { $psi.StandardOutputEncoding = $Encoding; $psi.StandardErrorEncoding = $Encoding }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    try { $p.StandardInput.Close() } catch { }
    return $p
}

function Invoke-CSWExternal {
    <#
        Ejecuta un programa externo (sfc, dism, chkdsk, netsh, winget...) capturando
        su salida linea a linea hacia el log en tiempo real. Devuelve el ExitCode
        (-1 si se agoto el tiempo). Maneja la salida UTF-16 de sfc.exe (-Unicode) y UTF-8 (-Utf8).
        La lectura es asincrona con sondeo: el boton Detener de la GUI la interrumpe y el
        proceso se termina (salvo los de $script:CSWNoKillOnStop).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Arguments = '',
        [switch]$Unicode,
        [switch]$Utf8,
        [int]$TimeoutSeconds = 0
    )
    Write-CSWLog "> $FilePath $Arguments" -Level Info
    $enc = $null
    if ($Unicode) { $enc = [System.Text.Encoding]::Unicode }
    elseif ($Utf8) { $enc = New-Object System.Text.UTF8Encoding($false) }
    $p = New-CSWProcess -FilePath $FilePath -Arguments $Arguments -Encoding $enc
    $errTask = $p.StandardError.ReadToEndAsync()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $finished = $false
    $lastPct = ''
    try {
        $lineTask = $p.StandardOutput.ReadLineAsync()
        while ($true) {
            if ($lineTask.Wait(250)) {
                $line = $lineTask.Result
                if ($null -eq $line) { break }
                $lineTask = $p.StandardOutput.ReadLineAsync()
                $line = ($line -replace "`0", '').Trim()
                if (-not $line) { continue }
                # Evita inundar el log con barras de progreso repetidas
                if ($line -match '(\d{1,3}(\.\d)?)\s*%') {
                    $pct = $Matches[1]
                    if ($pct -eq $lastPct) { continue }
                    if ($line.Length -lt 90 -and [int][double]$pct % 10 -ne 0) { continue }
                    $lastPct = $pct
                }
                Write-CSWLog $line -Level Data
            }
            elseif ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; break }
        }
        while (-not $timedOut -and -not $p.WaitForExit(250)) {
            if ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true }
        }
        $finished = -not $timedOut
    }
    finally {
        if (-not $finished) {
            $leaf = [System.IO.Path]::GetFileName($FilePath).ToLowerInvariant()
            if ($timedOut -or ($script:CSWNoKillOnStop -notcontains $leaf)) { Stop-CSWProcessTree -Process $p }
        }
    }
    if ($timedOut) {
        Write-CSWLog ("{0} supero el tiempo maximo de {1} s y se detuvo." -f [System.IO.Path]::GetFileName($FilePath), $TimeoutSeconds) -Level Warn
        try { $p.Dispose() } catch { }
        return -1
    }
    $err = ''
    try { if ($errTask.Wait(5000)) { $err = $errTask.Result } } catch { }
    if ($err -and $err.Trim()) { foreach ($l in ($err -split "`r?`n")) { if ($l.Trim()) { Write-CSWLog ($l -replace "`0", '').Trim() -Level Warn } } }
    $code = $p.ExitCode
    try { $p.Dispose() } catch { }
    return $code
}

function Get-CSWExternalOutput {
    <#
        Ejecuta un programa y devuelve su salida estandar como texto SIN volcarla al log
        (para analizarla). Entrada cerrada y tiempo maximo (por defecto 60 s).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Arguments = '',
        [switch]$Utf8,
        [int]$TimeoutSeconds = 60
    )
    $enc = $null
    if ($Utf8) { $enc = New-Object System.Text.UTF8Encoding($false) }
    $p = New-CSWProcess -FilePath $FilePath -Arguments $Arguments -Encoding $enc
    $done = $false
    try {
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $outTask.Wait(250)) {
            if ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw ("{0} no respondio en {1} s" -f [System.IO.Path]::GetFileName($FilePath), $TimeoutSeconds) }
        }
        [void]$p.WaitForExit(5000)
        try { [void]$errTask.Wait(2000) } catch { }
        $done = $true
        return [string]$outTask.Result
    }
    finally {
        if (-not $done) { Stop-CSWProcessTree -Process $p }
        try { $p.Dispose() } catch { }
    }
}

function Format-CSWDate {
    <# Fecha para el cliente: siempre dd/MM/yyyy (y HH:mm), sin depender de la cultura del sistema. #>
    param($Date, [switch]$WithTime, [switch]$WithSeconds)
    if ($null -eq $Date -or ([string]$Date) -eq '') { return '' }
    $d = $null
    if ($Date -is [datetime]) { $d = $Date }
    else { try { $d = [datetime]$Date } catch { return [string]$Date } }
    $fmt = 'dd/MM/yyyy'
    if ($WithSeconds) { $fmt = 'dd/MM/yyyy HH:mm:ss' } elseif ($WithTime) { $fmt = 'dd/MM/yyyy HH:mm' }
    return $d.ToString($fmt, [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CSWAdminRequiredResult {
    <# Resultado uniforme cuando una accion necesita privilegios y la sesion no los tiene. #>
    param([string]$Detail = '')
    $msg = 'Requiere ejecutar como administrador'
    if ($Detail) { $msg += " ($Detail)" }
    Write-CSWLog ("{0}. Abra Cybersutro win con 'Ejecutar como administrador'." -f $msg) -Level Error
    return (New-CSWResult -Summary "$msg." -Status Error)
}

function Test-CSWHostName {
    <# Valida un nombre de host o una IP (v4/v6) antes de usarlo en argumentos o peticiones. #>
    param([string]$Name)
    if (-not $Name) { return $false }
    $n = $Name.Trim()
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($n, [ref]$ip)) { return $true }
    return ($n -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.?$')
}

function New-CSWResult {
    <# Objeto resumen que una accion devuelve al final. #>
    param([Parameter(Mandatory)][string]$Summary, [ValidateSet('OK', 'Warn', 'Error')][string]$Status = 'OK')
    return @{ CSWSummary = $Summary; CSWStatus = $Status }
}

Export-ModuleMember -Function *-CSW*
