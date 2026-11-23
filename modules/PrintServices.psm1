#Requires -Version 5.1
<#
    Cybersutro win - Modulo PrintServices (Impresoras y servicios)
    Diagnostico y reparacion de impresion (cola, Spooler, drivers) y de servicios de Windows.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Datos de referencia
# ---------------------------------------------------------------------------

# Servicios automaticos que es normal encontrar detenidos (se paran solos al terminar su trabajo)
$script:PrintSvcAutoStopExclusions = @(
    'gupdate', 'gupdatem', 'GoogleUpdater*', 'GoogleChromeElevationService',
    'edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService',
    'MapsBroker', 'sppsvc', 'RemoteRegistry', 'WbioSrvc', 'tiledatamodelsvc',
    'clr_optimization*', 'DoSvc', 'UsoSvc', 'WaaSMedicSvc', 'BITS', 'wuauserv',
    'TrustedInstaller', 'SgrmBroker', 'WMPNetworkSvc', 'MozillaMaintenance',
    'ShellHWDetection', 'sedsvc', 'StorSvc', 'TabletInputService', 'stisvc',
    'Intel(R) TPM Provisioning Service', 'IntelAudioService', 'OneSyncSvc*',
    'CDPUserSvc*', 'BcastDVRUserService*', 'BluetoothUserService*', 'MessagingService*',
    'PimIndexMaintenanceSvc*', 'UnistoreSvc*', 'UserDataSvc*', 'WpnUserService*',
    'AdobeARMservice', 'ClickToRunSvc', 'ose64', 'ose', 'NetTcpPortSharing', 'wlidsvc',
    'brave', 'bravem', 'BraveElevationService', 'asus', 'AsusUpdateCheck', 'MozillaMaintenance*'
)

# Servicios esenciales para soporte: modos de inicio aceptados y si deben estar en ejecucion
$script:PrintSvcEssentials = @(
    @{ Name = 'Spooler';           Modes = @('Auto');           MustRun = $true;  Note = 'Cola de impresion' },
    @{ Name = 'Dhcp';              Modes = @('Auto');           MustRun = $true;  Note = 'Cliente DHCP (IP automatica)' },
    @{ Name = 'Dnscache';          Modes = @('Auto');           MustRun = $true;  Note = 'Cliente DNS' },
    @{ Name = 'EventLog';          Modes = @('Auto');           MustRun = $true;  Note = 'Registro de eventos' },
    @{ Name = 'wuauserv';          Modes = @('Manual', 'Auto'); MustRun = $false; Note = 'Windows Update' },
    @{ Name = 'BITS';              Modes = @('Manual', 'Auto'); MustRun = $false; Note = 'Transferencia inteligente (descargas de Windows Update)' },
    @{ Name = 'CryptSvc';          Modes = @('Auto');           MustRun = $true;  Note = 'Servicios criptograficos (firmas, certificados)' },
    @{ Name = 'WinDefend';         Modes = @('Auto');           MustRun = $true;  Note = 'Antivirus Microsoft Defender' },
    @{ Name = 'mpssvc';            Modes = @('Auto');           MustRun = $true;  Note = 'Firewall de Windows' },
    @{ Name = 'LanmanWorkstation'; Modes = @('Auto');           MustRun = $true;  Note = 'Estacion de trabajo (acceso a recursos de red)' },
    @{ Name = 'LanmanServer';      Modes = @('Auto');           MustRun = $true;  Note = 'Servidor (compartir carpetas e impresoras)' },
    @{ Name = 'Winmgmt';           Modes = @('Auto');           MustRun = $true;  Note = 'Instrumental de administracion (WMI)' },
    @{ Name = 'AudioSrv';          Modes = @('Auto');           MustRun = $true;  Note = 'Audio de Windows' },
    @{ Name = 'Themes';            Modes = @('Auto');           MustRun = $true;  Note = 'Temas / apariencia' },
    @{ Name = 'W32Time';           Modes = @('Manual', 'Auto'); MustRun = $false; Note = 'Hora de Windows' }
)

# Servicios que nunca se deben detener desde la herramienta
$script:PrintSvcProtected = @('RpcSs', 'RpcEptMapper', 'DcomLaunch', 'LSM', 'BrokerInfrastructure', 'SamSs', 'Power', 'PlugPlay', 'CoreMessagingRegistrar', 'SystemEventsBroker')

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

function Test-CSWPrintCmdlets {
    return [bool](Get-Command -Name Get-Printer -ErrorAction SilentlyContinue)
}

function Get-CSWPrintSpoolFolder {
    return (Join-Path $env:SystemRoot 'System32\spool\PRINTERS')
}

function Get-CSWPrintSystemExe {
    param([Parameter(Mandatory)][string]$RelativePath)
    # En un PowerShell de 32 bits sobre Windows de 64 bits, System32 se redirige: usar Sysnative
    $sysnative = Join-Path $env:SystemRoot 'Sysnative'
    if ((-not [Environment]::Is64BitProcess) -and (Test-Path $sysnative)) {
        return (Join-Path $sysnative $RelativePath)
    }
    return (Join-Path (Join-Path $env:SystemRoot 'System32') $RelativePath)
}

function Get-CSWPrintCimPrinter {
    param([Parameter(Mandatory)][string]$PrinterName)
    $all = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop)
    $p = @($all | Where-Object { $_.Name -eq $PrinterName }) | Select-Object -First 1
    if (-not $p) { $p = @($all | Where-Object { $_.Name -like "*$PrinterName*" }) | Select-Object -First 1 }
    return $p
}

function Get-CSWPrintNameList {
    try { return ((@(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop) | ForEach-Object { $_.Name }) -join ', ') }
    catch { return '' }
}

function Get-CSWPrintPrinterStatusText {
    param($Code)
    switch ([int]$Code) {
        1 { 'Otro' } 2 { 'Desconocido' } 3 { 'Inactiva' } 4 { 'Imprimiendo' } 5 { 'Calentando' }
        6 { 'Detenida' } 7 { 'Sin conexion' } default { [string]$Code }
    }
}

function Get-CSWPrintRunningDependents {
    param([Parameter(Mandatory)][string]$Name)
    try {
        $sc = New-Object System.ServiceProcess.ServiceController($Name)
        return @($sc.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.ServiceName })
    }
    catch { return @() }
}

function Stop-CSWPrintServiceSafe {
    <# Detiene un servicio (y sus dependientes) con tiempo maximo. Devuelve $true si quedo detenido. #>
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 30)
    $sc = New-Object System.ServiceProcess.ServiceController($Name)
    $sc.Refresh()
    if ($sc.Status -eq 'Stopped') { return $true }
    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Write-CSWLog "Stop-Service fallo en ${Name}: $($_.Exception.Message)" -Level Warn
    }
    try {
        $sc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($TimeoutSec))
    }
    catch { }
    $sc.Refresh()
    if ($sc.Status -eq 'Stopped') { return $true }

    # Ultimo recurso: terminar el proceso del servicio (solo si es un proceso propio, no svchost compartido)
    try {
        $cim = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
        if ($cim -and $cim.ProcessId -gt 0) {
            $shared = @(Get-CimInstance -ClassName Win32_Service -Filter ("ProcessId={0}" -f $cim.ProcessId) -ErrorAction SilentlyContinue)
            if ($shared.Count -le 1) {
                Write-CSWLog "El servicio $Name no respondio; se fuerza el cierre del proceso $($cim.ProcessId)." -Level Warn
                Stop-Process -Id $cim.ProcessId -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
        }
    }
    catch { Write-CSWLog "No se pudo forzar el cierre de ${Name}: $($_.Exception.Message)" -Level Warn }
    $sc.Refresh()
    return ($sc.Status -eq 'Stopped')
}

function Start-CSWPrintServiceSafe {
    <# Inicia un servicio con tiempo maximo. Devuelve $true si quedo en ejecucion. #>
    param([Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 30)
    $sc = New-Object System.ServiceProcess.ServiceController($Name)
    $sc.Refresh()
    if ($sc.Status -eq 'Running') { return $true }
    if ($sc.Status -eq 'StartPending') { }
    elseif ($sc.Status -eq 'Paused') { $sc.Continue() }
    else { $sc.Start() }
    try {
        $sc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds($TimeoutSec))
    }
    catch { }
    $sc.Refresh()
    return ($sc.Status -eq 'Running')
}

function Get-CSWPrintServiceInfo {
    param([Parameter(Mandatory)][string]$Name)
    $safe = $Name.Replace("'", "''").Replace('\', '\\')
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $safe) -ErrorAction SilentlyContinue
    if (-not $svc) {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter ("DisplayName='{0}'" -f $safe) -ErrorAction SilentlyContinue
    }
    if ($svc) { return @($svc)[0] }
    return $null
}

function Get-CSWPrintDelayed {
    param($Svc)
    if ($Svc.PSObject.Properties['DelayedAutoStart'] -and $Svc.DelayedAutoStart) { return $true }
    return $false
}

function Test-CSWPrintTriggerStart {
    param([Parameter(Mandatory)][string]$Name)
    return (Test-Path -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}\TriggerInfo" -f $Name))
}

function Get-CSWPrintStoppedAutoList {
    <# Devuelve los servicios Auto detenidos que NO se consideran normales. #>
    $all = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction Stop)
    $result = New-Object System.Collections.ArrayList
    $skipped = 0
    # Minutos desde el arranque: los de inicio retrasado arrancan ~2 min despues del inicio de sesion
    $upMin = 9999
    try { $upMin = ((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).TotalMinutes } catch { }
    foreach ($s in $all) {
        $excluded = $false
        foreach ($pat in $script:PrintSvcAutoStopExclusions) {
            if ($s.Name -like $pat) { $excluded = $true; break }
        }
        # Plantillas de servicios por usuario (tipo 0x50/0x60): no se ejecutan por si mismas
        if (-not $excluded -and $s.ServiceType -match 'Unknown') { $excluded = $true }
        # "Automatico (desencadenador)": Windows lo inicia y lo detiene segun eventos (p. ej. gpsvc,
        # que se para tras aplicar las directivas). Estar detenido es su estado normal.
        if (-not $excluded -and (Test-CSWPrintTriggerStart $s.Name)) { $excluded = $true }
        # Inicio retrasado: aun no le ha tocado arrancar si el equipo acaba de iniciarse
        if (-not $excluded -and (Get-CSWPrintDelayed $s) -and $upMin -lt 10) { $excluded = $true }
        if ($excluded) { $skipped++; continue }
        [void]$result.Add($s)
    }
    return [pscustomobject]@{ Services = @($result); Skipped = $skipped; Total = $all.Count }
}

function ConvertTo-CSWPrintDriverVersion {
    param($Raw)
    try {
        $v = [uint64]$Raw
        if ($v -eq 0) { return '' }
        return ('{0}.{1}.{2}.{3}' -f (($v -shr 48) -band 0xFFFF), (($v -shr 32) -band 0xFFFF), (($v -shr 16) -band 0xFFFF), ($v -band 0xFFFF))
    }
    catch { return [string]$Raw }
}

# ---------------------------------------------------------------------------
# Acciones de impresion
# ---------------------------------------------------------------------------

function Get-CSWPrintPrinters {
    Write-CSWLog 'Consultando impresoras instaladas...' -Level Info
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler) {
        return (New-CSWResult -Summary 'El servicio de cola de impresion (Spooler) no existe en este equipo.' -Status Error)
    }
    if ($spooler.Status -ne 'Running') {
        Write-CSWLog "El servicio Spooler esta '$($spooler.Status)'. Sin el no se puede imprimir." -Level Warn
        return (New-CSWResult -Summary 'La cola de impresion (Spooler) esta detenida: no se pueden listar ni usar las impresoras.' -Status Warn)
    }

    $cimPrinters = @()
    try { $cimPrinters = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop) } catch { Write-CSWLog "Win32_Printer no disponible: $($_.Exception.Message)" -Level Warn }

    $rows = New-Object System.Collections.ArrayList
    $totalJobs = 0; $errorJobs = 0; $offline = 0
    if (Test-CSWPrintCmdlets) {
        $printers = @(Get-Printer -ErrorAction Stop)
        foreach ($p in $printers) {
            $cim = @($cimPrinters | Where-Object { $_.Name -eq $p.Name }) | Select-Object -First 1
            $jobs = @(Get-PrintJob -PrinterName $p.Name -ErrorAction SilentlyContinue)
            $jobErr = @($jobs | Where-Object { [string]$_.JobStatus -match 'Error|Blocked|Offline|PaperOut|UserIntervention' }).Count
            $totalJobs += $jobs.Count; $errorJobs += $jobErr
            $isOff = ($cim -and $cim.WorkOffline) -or ([string]$p.PrinterStatus -match 'Offline')
            if ($isOff) { $offline++ }
            $state = [string]$p.PrinterStatus
            if ($isOff -and $state -notmatch 'Offline') { $state = "$state (sin conexion)" }
            [void]$rows.Add([pscustomobject]@{
                    Impresora      = $p.Name
                    Driver         = $p.DriverName
                    Puerto         = $p.PortName
                    Estado         = $state
                    Predeterminada = $(if ($cim -and $cim.Default) { 'Si' } else { 'No' })
                    Compartida     = $(if ($p.Shared) { "Si ($($p.ShareName))" } else { 'No' })
                    Tipo           = [string]$p.Type
                    Trabajos       = $jobs.Count
                    TrabajosError  = $jobErr
                })
        }
    }
    else {
        Write-CSWLog 'Modulo PrintManagement no disponible; se usa WMI (Win32_Printer).' -Level Warn
        foreach ($c in $cimPrinters) {
            $jobs = @()
            try { $jobs = @(Get-CimInstance -ClassName Win32_PrintJob -ErrorAction Stop | Where-Object { $_.Name -like "$($c.Name),*" }) } catch { }
            $totalJobs += $jobs.Count
            if ($c.WorkOffline) { $offline++ }
            [void]$rows.Add([pscustomobject]@{
                    Impresora      = $c.Name
                    Driver         = $c.DriverName
                    Puerto         = $c.PortName
                    Estado         = (Get-CSWPrintPrinterStatusText $c.PrinterStatus)
                    Predeterminada = $(if ($c.Default) { 'Si' } else { 'No' })
                    Compartida     = $(if ($c.Shared) { "Si ($($c.ShareName))" } else { 'No' })
                    Tipo           = $(if ($c.Network) { 'Red' } else { 'Local' })
                    Trabajos       = $jobs.Count
                    TrabajosError  = 0
                })
        }
    }

    if ($rows.Count -eq 0) {
        return (New-CSWResult -Summary 'No hay impresoras instaladas en el equipo.' -Status Warn)
    }
    $rows | Sort-Object Impresora | Write-CSWOutput

    # Detalle de trabajos en cola
    if ($totalJobs -gt 0 -and (Test-CSWPrintCmdlets)) {
        Write-CSWLog "Trabajos en cola ($totalJobs):" -Level Step
        $jobRows = foreach ($r in $rows) {
            if ($r.Trabajos -gt 0) {
                Get-PrintJob -PrinterName $r.Impresora -ErrorAction SilentlyContinue | ForEach-Object {
                    [pscustomobject]@{
                        Impresora = $r.Impresora; Id = $_.Id; Documento = $_.DocumentName; Usuario = $_.UserName
                        Estado = [string]$_.JobStatus; Paginas = $_.TotalPages; Enviado = $_.SubmittedTime
                    }
                }
            }
        }
        @($jobRows) | Write-CSWOutput
    }

    $def = @($rows | Where-Object { $_.Predeterminada -eq 'Si' }) | Select-Object -First 1
    $defText = 'sin predeterminada'
    if ($def) { $defText = "predeterminada: $($def.Impresora)" }
    $summary = "{0} impresora(s), {1}; {2} trabajo(s) en cola" -f $rows.Count, $defText, $totalJobs
    $status = 'OK'
    if ($errorJobs -gt 0) { $summary += " ($errorJobs con error)"; $status = 'Warn' }
    if ($offline -gt 0) { $summary += "; $offline sin conexion"; $status = 'Warn' }
    return (New-CSWResult -Summary $summary -Status $status)
}

function Repair-CSWPrintSpoolerQueue {
    if (-not (Test-CSWAdmin)) {
        return (New-CSWAdminRequiredResult)
    }
    $folder = Get-CSWPrintSpoolFolder
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $svc) { return (New-CSWResult -Summary 'El servicio Spooler no existe en este equipo.' -Status Error) }

    $files = @(Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction SilentlyContinue)
    $jobCount = @($files | Where-Object { $_.Extension -eq '.SHD' }).Count
    if ($jobCount -eq 0) { $jobCount = @($files | Where-Object { $_.Extension -eq '.SPL' }).Count }
    $sizeMB = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum) / 1MB, 2)
    Write-CSWLog "Archivos en la cola: $($files.Count) ($jobCount trabajo(s), $sizeMB MB)." -Level Info

    $dependents = Get-CSWPrintRunningDependents -Name 'Spooler'
    Write-CSWLog 'Deteniendo el servicio de cola de impresion (Spooler)...' -Level Step
    if (-not (Stop-CSWPrintServiceSafe -Name 'Spooler' -TimeoutSec 30)) {
        return (New-CSWResult -Summary 'No se pudo detener la cola de impresion; reinicie el equipo e intente de nuevo.' -Status Error)
    }
    Write-CSWLog 'Spooler detenido.' -Level Ok

    $deleted = 0; $failed = 0
    foreach ($f in $files) {
        try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $deleted++ }
        catch { $failed++; Write-CSWLog "No se pudo borrar $($f.Name): $($_.Exception.Message)" -Level Warn }
    }
    # Por si aparecieron archivos nuevos mientras se detenia
    Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction Stop; $deleted++ } catch { $failed++ }
    }
    Write-CSWLog "Archivos de cola borrados: $deleted (fallidos: $failed)." -Level Info

    Write-CSWLog 'Iniciando el servicio Spooler...' -Level Step
    $started = $false
    try { $started = Start-CSWPrintServiceSafe -Name 'Spooler' -TimeoutSec 30 }
    catch { Write-CSWLog "Error al iniciar Spooler: $($_.Exception.Message)" -Level Error }
    foreach ($d in $dependents) {
        try { [void](Start-CSWPrintServiceSafe -Name $d -TimeoutSec 20); Write-CSWLog "Servicio dependiente reiniciado: $d" -Level Info }
        catch { Write-CSWLog "No se pudo reiniciar el dependiente ${d}: $($_.Exception.Message)" -Level Warn }
    }
    if (-not $started) {
        return (New-CSWResult -Summary "Cola vaciada ($jobCount trabajo(s) borrados) pero el servicio Spooler no arranco. Revise el visor de eventos." -Status Error)
    }
    Write-CSWLog 'Spooler en ejecucion.' -Level Ok
    $status = 'OK'
    if ($failed -gt 0) { $status = 'Warn' }
    return (New-CSWResult -Summary "Cola de impresion reparada: $jobCount trabajo(s) atascado(s) eliminado(s) y servicio reiniciado." -Status $status)
}

function Restart-CSWPrintSpooler {
    if (-not (Test-CSWAdmin)) {
        return (New-CSWAdminRequiredResult)
    }
    if (-not (Get-Service -Name Spooler -ErrorAction SilentlyContinue)) {
        return (New-CSWResult -Summary 'El servicio Spooler no existe en este equipo.' -Status Error)
    }
    $dependents = Get-CSWPrintRunningDependents -Name 'Spooler'
    Write-CSWLog 'Reiniciando el servicio de cola de impresion...' -Level Step
    if (-not (Stop-CSWPrintServiceSafe -Name 'Spooler' -TimeoutSec 30)) {
        return (New-CSWResult -Summary 'No se pudo detener el Spooler.' -Status Error)
    }
    $ok = $false
    try { $ok = Start-CSWPrintServiceSafe -Name 'Spooler' -TimeoutSec 30 } catch { Write-CSWLog $_.Exception.Message -Level Error }
    foreach ($d in $dependents) { try { [void](Start-CSWPrintServiceSafe -Name $d -TimeoutSec 20) } catch { } }
    if ($ok) { return (New-CSWResult -Summary 'Servicio de cola de impresion reiniciado correctamente.') }
    return (New-CSWResult -Summary 'El servicio de cola de impresion no volvio a arrancar.' -Status Error)
}

function Clear-CSWPrintJobs {
    param([string]$PrinterName = '')
    if (-not (Test-CSWPrintCmdlets)) {
        return (New-CSWResult -Summary 'El modulo PrintManagement no esta disponible en este Windows; use "Reparar cola de impresion".' -Status Warn)
    }
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        return (New-CSWResult -Summary 'La cola de impresion (Spooler) no esta en ejecucion.' -Status Warn)
    }
    $PrinterName = ([string]$PrinterName).Trim()
    $printers = @(Get-Printer -ErrorAction Stop)
    if ($PrinterName) {
        $printers = @($printers | Where-Object { $_.Name -eq $PrinterName })
        if ($printers.Count -eq 0) {
            Write-CSWLog "Impresoras disponibles: $(Get-CSWPrintNameList)" -Level Info
            return (New-CSWResult -Summary "No existe la impresora '$PrinterName'." -Status Error)
        }
    }
    if ($printers.Count -eq 0) { return (New-CSWResult -Summary 'No hay impresoras instaladas.' -Status Warn) }

    $removed = 0; $failed = 0
    foreach ($p in $printers) {
        $jobs = @(Get-PrintJob -PrinterName $p.Name -ErrorAction SilentlyContinue)
        if ($jobs.Count -eq 0) { continue }
        Write-CSWLog "Cancelando $($jobs.Count) trabajo(s) de '$($p.Name)'..." -Level Step
        foreach ($j in $jobs) {
            try {
                Remove-PrintJob -PrinterName $p.Name -ID $j.Id -ErrorAction Stop
                $removed++
                Write-CSWLog ("  Cancelado #{0} '{1}' ({2})" -f $j.Id, $j.DocumentName, $j.UserName) -Level Data
            }
            catch { $failed++; Write-CSWLog "  No se pudo cancelar #$($j.Id): $($_.Exception.Message)" -Level Warn }
        }
    }
    $target = 'todas las impresoras'
    if ($PrinterName) { $target = "'$PrinterName'" }
    if ($removed -eq 0 -and $failed -eq 0) { return (New-CSWResult -Summary "No habia trabajos pendientes en $target.") }
    if ($failed -gt 0) {
        return (New-CSWResult -Summary "Cancelados $removed trabajo(s) en $target; $failed no se pudieron cancelar (pruebe 'Reparar cola de impresion')." -Status Warn)
    }
    return (New-CSWResult -Summary "Cancelados $removed trabajo(s) de impresion en $target.")
}

function Invoke-CSWPrintTestPage {
    param([string]$PrinterName = '')
    $PrinterName = ([string]$PrinterName).Trim()
    try {
        if (-not $PrinterName) {
            $p = @(Get-CimInstance -ClassName Win32_Printer -Filter 'Default=TRUE' -ErrorAction Stop) | Select-Object -First 1
            if ($p) { Write-CSWLog "No se indico impresora; se usa la predeterminada: $($p.Name)" -Level Info }
        }
        else { $p = Get-CSWPrintCimPrinter -PrinterName $PrinterName }
    }
    catch { return (New-CSWResult -Summary "No se pudo consultar las impresoras: $($_.Exception.Message)" -Status Error) }
    if (-not $p) {
        Write-CSWLog "Impresoras disponibles: $(Get-CSWPrintNameList)" -Level Info
        return (New-CSWResult -Summary "No se encontro la impresora '$PrinterName'." -Status Error)
    }
    if ($p.WorkOffline) { Write-CSWLog "La impresora '$($p.Name)' figura SIN CONEXION; la pagina quedara en cola." -Level Warn }
    Write-CSWLog "Enviando pagina de prueba a '$($p.Name)'..." -Level Step
    try {
        $r = Invoke-CimMethod -InputObject $p -MethodName PrintTestPage -ErrorAction Stop
        if ($r.ReturnValue -eq 0) {
            return (New-CSWResult -Summary "Pagina de prueba enviada a '$($p.Name)'. Verifique que salga impresa.")
        }
        return (New-CSWResult -Summary "La impresora '$($p.Name)' rechazo la pagina de prueba (codigo $($r.ReturnValue))." -Status Error)
    }
    catch { return (New-CSWResult -Summary "Error al enviar la pagina de prueba: $($_.Exception.Message)" -Status Error) }
}

function Remove-CSWPrintPrinter {
    param([string]$PrinterName = '')
    $PrinterName = ([string]$PrinterName).Trim()
    if (-not $PrinterName) { return (New-CSWResult -Summary 'Debe indicar el nombre exacto de la impresora a quitar.' -Status Error) }
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    try {
        if (Test-CSWPrintCmdlets) {
            $p = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
            if (-not $p) {
                Write-CSWLog "Impresoras disponibles: $(Get-CSWPrintNameList)" -Level Info
                return (New-CSWResult -Summary "No existe la impresora '$PrinterName'." -Status Error)
            }
            Write-CSWLog "Impresora: $($p.Name) | driver: $($p.DriverName) | puerto: $($p.PortName)" -Level Info
            $jobs = @(Get-PrintJob -PrinterName $p.Name -ErrorAction SilentlyContinue)
            foreach ($j in $jobs) { try { Remove-PrintJob -PrinterName $p.Name -ID $j.Id -ErrorAction Stop } catch { } }
            if ($jobs.Count) { Write-CSWLog "Cancelados $($jobs.Count) trabajo(s) pendientes." -Level Info }
            Remove-Printer -Name $p.Name -ErrorAction Stop
        }
        else {
            $p = Get-CSWPrintCimPrinter -PrinterName $PrinterName
            if (-not $p -or $p.Name -ne $PrinterName) { return (New-CSWResult -Summary "No existe la impresora '$PrinterName'." -Status Error) }
            Remove-CimInstance -InputObject $p -ErrorAction Stop
        }
        Write-CSWLog 'El driver y el puerto se conservan (pueden quitarse desde la gestion de impresion).' -Level Info
        return (New-CSWResult -Summary "Impresora '$PrinterName' eliminada.")
    }
    catch { return (New-CSWResult -Summary "No se pudo quitar la impresora '$PrinterName': $($_.Exception.Message)" -Status Error) }
}

function Set-CSWPrintDefault {
    param([string]$PrinterName = '')
    $PrinterName = ([string]$PrinterName).Trim()
    if (-not $PrinterName) { return (New-CSWResult -Summary 'Debe indicar el nombre de la impresora.' -Status Error) }
    try { $p = Get-CSWPrintCimPrinter -PrinterName $PrinterName }
    catch { return (New-CSWResult -Summary "No se pudo consultar las impresoras: $($_.Exception.Message)" -Status Error) }
    if (-not $p) {
        Write-CSWLog "Impresoras disponibles: $(Get-CSWPrintNameList)" -Level Info
        return (New-CSWResult -Summary "No se encontro la impresora '$PrinterName'." -Status Error)
    }
    # "Permitir que Windows administre la impresora predeterminada" sobrescribe la eleccion manual
    $mode = $null
    try { $mode = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name LegacyDefaultPrinterMode -ErrorAction Stop).LegacyDefaultPrinterMode } catch { }
    if ($null -eq $mode -or $mode -eq 0) {
        Write-CSWLog 'Windows esta configurado para administrar la impresora predeterminada; puede cambiarla sola. Desactivelo en Configuracion > Impresoras si ocurre.' -Level Warn
    }
    Write-CSWLog 'Nota: la impresora predeterminada es por usuario; se aplica al usuario que ejecuta la herramienta.' -Level Info
    try {
        $r = Invoke-CimMethod -InputObject $p -MethodName SetDefaultPrinter -ErrorAction Stop
        if ($r.ReturnValue -eq 0) { return (New-CSWResult -Summary "'$($p.Name)' es ahora la impresora predeterminada.") }
        return (New-CSWResult -Summary "Windows no acepto el cambio de predeterminada (codigo $($r.ReturnValue))." -Status Error)
    }
    catch { return (New-CSWResult -Summary "Error al establecer la predeterminada: $($_.Exception.Message)" -Status Error) }
}

function Get-CSWPrintDrivers {
    if (-not (Test-CSWPrintCmdlets)) {
        return (New-CSWResult -Summary 'El modulo PrintManagement no esta disponible en este Windows.' -Status Warn)
    }
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        return (New-CSWResult -Summary 'La cola de impresion (Spooler) no esta en ejecucion.' -Status Warn)
    }
    $drivers = @(Get-PrinterDriver -ErrorAction Stop)
    if ($drivers.Count -eq 0) { return (New-CSWResult -Summary 'No hay drivers de impresora instalados.' -Status Warn) }
    $inUse = @()
    try { $inUse = @(Get-Printer -ErrorAction Stop | ForEach-Object { $_.DriverName }) } catch { }
    $rows = foreach ($d in $drivers) {
        $inf = ''
        if ($d.PSObject.Properties['InfPath'] -and $d.InfPath) { $inf = Split-Path -Leaf $d.InfPath }
        [pscustomobject]@{
            Driver     = $d.Name
            Fabricante = $d.Manufacturer
            Version    = (ConvertTo-CSWPrintDriverVersion $d.DriverVersion)
            Entorno    = $d.PrinterEnvironment
            Tipo       = "v$($d.MajorVersion)"
            EnUso      = $(if ($inUse -contains $d.Name) { 'Si' } else { 'No' })
            Inf        = $inf
        }
    }
    @($rows) | Sort-Object Driver | Write-CSWOutput
    $unused = @($rows | Where-Object { $_.EnUso -eq 'No' }).Count
    return (New-CSWResult -Summary ("{0} driver(s) de impresora instalados ({1} sin uso)." -f $drivers.Count, $unused))
}

# ---------------------------------------------------------------------------
# Acciones de servicios
# ---------------------------------------------------------------------------

function Get-CSWServiceStoppedAuto {
    Write-CSWLog 'Buscando servicios automaticos detenidos...' -Level Info
    try { $info = Get-CSWPrintStoppedAutoList }
    catch { return (New-CSWResult -Summary "No se pudo consultar los servicios: $($_.Exception.Message)" -Status Error) }
    Write-CSWLog ("Servicios automaticos no iniciados: {0}; considerados normales (excluidos): {1}." -f $info.Total, $info.Skipped) -Level Info
    if ($info.Services.Count -eq 0) {
        return (New-CSWResult -Summary 'Todos los servicios automaticos importantes estan en ejecucion.')
    }
    $info.Services | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Servicio    = $_.Name
            Nombre      = $_.DisplayName
            Estado      = $_.State
            Retrasado   = $(if (Get-CSWPrintDelayed $_) { 'Si' } else { 'No' })
            CodigoSalida = $(if ($_.ExitCode -eq 1066) { "1066/$($_.ServiceSpecificExitCode)" } else { $_.ExitCode })
            Cuenta      = $_.StartName
        }
    } | Write-CSWOutput
    $names = ($info.Services | ForEach-Object { $_.Name }) -join ', '
    return (New-CSWResult -Summary ("{0} servicio(s) automatico(s) detenido(s): {1}" -f $info.Services.Count, $names) -Status Warn)
}

function Start-CSWServiceStoppedAuto {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    try { $info = Get-CSWPrintStoppedAutoList }
    catch { return (New-CSWResult -Summary "No se pudo consultar los servicios: $($_.Exception.Message)" -Status Error) }
    if ($info.Services.Count -eq 0) { return (New-CSWResult -Summary 'No hay servicios automaticos detenidos que iniciar.') }
    $ok = New-Object System.Collections.ArrayList
    $bad = New-Object System.Collections.ArrayList
    foreach ($s in $info.Services) {
        Write-CSWLog "Iniciando $($s.Name) ($($s.DisplayName))..." -Level Step
        try {
            if (Start-CSWPrintServiceSafe -Name $s.Name -TimeoutSec 30) {
                [void]$ok.Add($s.Name); Write-CSWLog "  $($s.Name) en ejecucion." -Level Ok
            }
            else {
                $now = Get-CSWPrintServiceInfo -Name $s.Name
                $st = 'desconocido'
                if ($now) { $st = $now.State }
                # Algunos servicios arrancan y se detienen enseguida porque no tienen trabajo: no es un fallo real
                if ($now -and $now.State -eq 'Stopped' -and $now.ExitCode -eq 0) {
                    [void]$ok.Add($s.Name); Write-CSWLog "  $($s.Name) arranco y se detuvo solo (sin trabajo pendiente)." -Level Info
                }
                else { [void]$bad.Add($s.Name); Write-CSWLog "  $($s.Name) no quedo en ejecucion (estado: $st)." -Level Warn }
            }
        }
        catch {
            [void]$bad.Add($s.Name)
            $msg = $_.Exception.Message
            if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
            Write-CSWLog "  No se pudo iniciar $($s.Name): $msg" -Level Error
        }
    }
    [pscustomobject]@{ Iniciados = $ok.Count; Fallidos = $bad.Count; ConFallo = ($bad -join ', ') } | Write-CSWOutput
    if ($bad.Count -eq 0) { return (New-CSWResult -Summary "Se iniciaron $($ok.Count) servicio(s) automatico(s) que estaban detenidos.") }
    return (New-CSWResult -Summary ("Iniciados {0}; fallaron {1}: {2}" -f $ok.Count, $bad.Count, ($bad -join ', ')) -Status Warn)
}

function Invoke-CSWServiceManage {
    param([string]$Name = '', [string]$Action = 'Status')
    $Name = ([string]$Name).Trim()
    if (-not $Name) { return (New-CSWResult -Summary 'Debe indicar el nombre del servicio.' -Status Error) }
    if (@('Start', 'Stop', 'Restart', 'Status') -notcontains $Action) {
        return (New-CSWResult -Summary "Accion '$Action' no valida (Start, Stop, Restart o Status)." -Status Error)
    }
    $svc = Get-CSWPrintServiceInfo -Name $Name
    if (-not $svc) { return (New-CSWResult -Summary "No existe el servicio '$Name'." -Status Error) }
    $Name = $svc.Name

    if ($Action -ne 'Status') {
        if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
        if (($Action -eq 'Stop' -or $Action -eq 'Restart') -and ($script:PrintSvcProtected -contains $Name)) {
            return (New-CSWResult -Summary "El servicio '$Name' es critico para Windows y no se detiene desde la herramienta." -Status Error)
        }
        if (($Action -eq 'Start' -or $Action -eq 'Restart') -and $svc.StartMode -eq 'Disabled') {
            return (New-CSWResult -Summary "El servicio '$Name' esta deshabilitado; cambie su tipo de inicio antes de iniciarlo." -Status Warn)
        }
    }

    try {
        switch ($Action) {
            'Stop' {
                $deps = Get-CSWPrintRunningDependents -Name $Name
                if ($deps.Count) { Write-CSWLog "Tambien se detendran dependientes: $($deps -join ', ')" -Level Warn }
                Write-CSWLog "Deteniendo $Name..." -Level Step
                if (-not (Stop-CSWPrintServiceSafe -Name $Name -TimeoutSec 30)) { return (New-CSWResult -Summary "El servicio '$Name' no se detuvo." -Status Error) }
            }
            'Start' {
                Write-CSWLog "Iniciando $Name..." -Level Step
                if (-not (Start-CSWPrintServiceSafe -Name $Name -TimeoutSec 30)) { return (New-CSWResult -Summary "El servicio '$Name' no quedo en ejecucion." -Status Error) }
            }
            'Restart' {
                $deps = Get-CSWPrintRunningDependents -Name $Name
                Write-CSWLog "Reiniciando $Name..." -Level Step
                if (-not (Stop-CSWPrintServiceSafe -Name $Name -TimeoutSec 30)) { return (New-CSWResult -Summary "El servicio '$Name' no se detuvo." -Status Error) }
                if (-not (Start-CSWPrintServiceSafe -Name $Name -TimeoutSec 30)) { return (New-CSWResult -Summary "El servicio '$Name' no volvio a arrancar." -Status Error) }
                foreach ($d in $deps) { try { [void](Start-CSWPrintServiceSafe -Name $d -TimeoutSec 20) } catch { Write-CSWLog "No se pudo reiniciar el dependiente $d" -Level Warn } }
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        return (New-CSWResult -Summary "Error al ejecutar '$Action' sobre '$Name': $msg" -Status Error)
    }

    $svc = Get-CSWPrintServiceInfo -Name $Name
    $deps = @()
    $req = @()
    try {
        $sc = New-Object System.ServiceProcess.ServiceController($Name)
        $deps = @($sc.DependentServices | ForEach-Object { $_.ServiceName })
        $req = @($sc.ServicesDependedOn | ForEach-Object { $_.ServiceName })
    }
    catch { }
    $mode = $svc.StartMode
    if ($mode -eq 'Auto' -and (Get-CSWPrintDelayed $svc)) { $mode = 'Auto (retrasado)' }
    if (Test-CSWPrintTriggerStart $Name) { $mode = "$mode + desencadenador" }
    [pscustomobject]@{
        Servicio = $svc.Name; Nombre = $svc.DisplayName; Estado = $svc.State; Inicio = $mode
        PID = $svc.ProcessId; Cuenta = $svc.StartName; Salida = $svc.ExitCode
    } | Write-CSWOutput
    Write-CSWLog "Ejecutable: $($svc.PathName)" -Level Data
    if ($req.Count) { Write-CSWLog "Depende de: $($req -join ', ')" -Level Data }
    if ($deps.Count) { Write-CSWLog "Dependientes: $($deps -join ', ')" -Level Data }

    switch ($Action) {
        'Status'  { return (New-CSWResult -Summary "Servicio $($svc.DisplayName): $($svc.State), inicio $mode.") }
        'Start'   { return (New-CSWResult -Summary "Servicio $($svc.DisplayName) iniciado.") }
        'Stop'    { return (New-CSWResult -Summary "Servicio $($svc.DisplayName) detenido.") }
        'Restart' { return (New-CSWResult -Summary "Servicio $($svc.DisplayName) reiniciado.") }
    }
}

function Test-CSWServiceEssentials {
    Write-CSWLog 'Comprobando servicios esenciales de soporte...' -Level Info
    $warn = New-Object System.Collections.ArrayList
    # Con un antivirus de terceros activo, Defender queda en Manual/detenido: es lo esperado
    $otherAv = @()
    try {
        $otherAv = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Where-Object { $_.displayName -notmatch 'Defender' } | ForEach-Object { $_.displayName } | Select-Object -Unique)
    }
    catch { }
    if ($otherAv.Count) { Write-CSWLog ("Antivirus de terceros detectado: {0}" -f ($otherAv -join ', ')) -Level Info }
    $rows = foreach ($e in $script:PrintSvcEssentials) {
        $svc = Get-CSWPrintServiceInfo -Name $e.Name
        $expected = ($e.Modes -join '/')
        if ($e.MustRun) { $expected += ', en ejecucion' }
        if (-not $svc) {
            $res = 'NO EXISTE'
            if ($e.Name -eq 'WinDefend') { $res = 'NO EXISTE (otro antivirus?)' }
            [void]$warn.Add($e.Name)
            [pscustomobject]@{ Servicio = $e.Name; Funcion = $e.Note; Inicio = '-'; Estado = '-'; Esperado = $expected; Resultado = $res }
            continue
        }
        $problems = @()
        if ($e.Modes -notcontains $svc.StartMode) { $problems += "inicio $($svc.StartMode)" }
        if ($e.MustRun -and $svc.State -ne 'Running') { $problems += 'detenido' }
        $res = 'OK'
        if ($problems.Count -and $e.Name -eq 'WinDefend' -and $otherAv.Count) {
            $res = 'OK (sustituido por ' + ($otherAv -join ', ') + ')'
            $problems = @()
        }
        if ($problems.Count) {
            $res = 'AVISO: ' + ($problems -join ', ')
            if ($e.Name -eq 'WinDefend' -and $svc.StartMode -eq 'Disabled') { $res += ' (puede ser normal con otro antivirus)' }
            [void]$warn.Add($e.Name)
            Write-CSWLog ("{0} ({1}): {2}" -f $e.Name, $e.Note, ($problems -join ', ')) -Level Warn
        }
        $mode = $svc.StartMode
        if ($mode -eq 'Auto' -and (Get-CSWPrintDelayed $svc)) { $mode = 'Auto (retr.)' }
        [pscustomobject]@{ Servicio = $svc.Name; Funcion = $e.Note; Inicio = $mode; Estado = $svc.State; Esperado = $expected; Resultado = $res }
    }
    @($rows) | Write-CSWOutput
    if ($warn.Count -eq 0) {
        return (New-CSWResult -Summary "Los $($script:PrintSvcEssentials.Count) servicios esenciales estan correctamente configurados.")
    }
    return (New-CSWResult -Summary ("{0} servicio(s) esencial(es) con problemas: {1}" -f $warn.Count, ($warn -join ', ')) -Status Warn)
}

function Repair-CSWServiceWmiRepository {
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $exe = Get-CSWPrintSystemExe -RelativePath 'wbem\winmgmt.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return (New-CSWResult -Summary 'No se encontro winmgmt.exe.' -Status Error) }

    Write-CSWLog 'Verificando la coherencia del repositorio WMI...' -Level Step
    $code = Invoke-CSWExternal -FilePath $exe -Arguments '/verifyrepository'
    if ($code -eq 0) {
        Write-CSWLog 'El repositorio WMI es coherente; no se requiere reparacion.' -Level Ok
        return (New-CSWResult -Summary 'Repositorio WMI verificado: correcto, no requirio reparacion.')
    }
    Write-CSWLog ("Repositorio WMI inconsistente (codigo 0x{0:X8}). Intentando recuperarlo..." -f $code) -Level Warn

    $code2 = Invoke-CSWExternal -FilePath $exe -Arguments '/salvagerepository'
    if ($code2 -ne 0) {
        Write-CSWLog ("winmgmt /salvagerepository devolvio 0x{0:X8}." -f $code2) -Level Error
        return (New-CSWResult -Summary 'El repositorio WMI esta danado y no se pudo recuperar automaticamente. Puede requerir "winmgmt /resetrepository" o reparacion del sistema.' -Status Error)
    }
    Write-CSWLog 'Verificando de nuevo...' -Level Step
    $code3 = Invoke-CSWExternal -FilePath $exe -Arguments '/verifyrepository'
    if ($code3 -eq 0) {
        return (New-CSWResult -Summary 'El repositorio WMI estaba danado y se reparo correctamente. Se recomienda reiniciar el equipo.')
    }
    return (New-CSWResult -Summary 'Se intento reparar el repositorio WMI pero sigue inconsistente. Reinicie y vuelva a intentarlo.' -Status Warn)
}

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

Register-CSWModule -Id 'PrintServices' -Name 'Impresoras y servicios' -Order 70 -Icon 'printer' `
    -Description 'Diagnóstico y reparación de impresoras, cola de impresión y servicios de Windows' -Actions @(
    @{ Id = 'ListPrinters'; Name = 'Listar impresoras'; Command = 'Get-CSWPrintPrinters'
        Description = 'Muestra impresoras, driver, puerto, estado, predeterminada, compartida y trabajos en cola.' },
    @{ Id = 'RepairSpooler'; Name = 'Reparar cola de impresión'; Command = 'Repair-CSWPrintSpoolerQueue'
        Description = 'Detiene el Spooler, borra los trabajos atascados y lo vuelve a iniciar.'
        Risk = 'Medium'; ModifiesSystem = $true
        ConfirmMessage = 'Se detendrá la cola de impresión y se BORRARÁN todos los trabajos pendientes de todas las impresoras.' },
    @{ Id = 'RestartSpooler'; Name = 'Reiniciar Spooler'; Command = 'Restart-CSWPrintSpooler'
        Description = 'Reinicia el servicio de cola de impresión sin borrar trabajos.'; Risk = 'Medium'
        ConfirmMessage = 'Se reiniciará el servicio de cola de impresión: los trabajos que se estén imprimiendo en este momento pueden interrumpirse.' },
    @{ Id = 'ClearJobs'; Name = 'Cancelar trabajos'; Command = 'Clear-CSWPrintJobs'
        Description = 'Cancela los trabajos pendientes de una impresora (vacío = todas).'
        Risk = 'Medium'; ConfirmMessage = 'Se cancelarán los trabajos de impresión pendientes.'
        Inputs = @(@{ Name = 'PrinterName'; Label = 'Impresora (vacío = todas)'; Default = '' }) },
    @{ Id = 'TestPage'; Name = 'Imprimir página de prueba'; Command = 'Invoke-CSWPrintTestPage'
        Description = 'Envía la página de prueba de Windows a la impresora indicada (vacío = predeterminada).'
        Inputs = @(@{ Name = 'PrinterName'; Label = 'Impresora (vacío = predeterminada)'; Default = '' }) },
    @{ Id = 'RemovePrinter'; Name = 'Quitar impresora'; Command = 'Remove-CSWPrintPrinter'
        Description = 'Elimina una impresora del equipo (conserva driver y puerto).'
        Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'La impresora se eliminará y habrá que volver a instalarla para usarla.'
        Inputs = @(@{ Name = 'PrinterName'; Label = 'Nombre exacto de la impresora'; Default = '' }) },
    @{ Id = 'SetDefault'; Name = 'Establecer predeterminada'; Command = 'Set-CSWPrintDefault'
        Description = 'Marca una impresora como predeterminada para el usuario actual.'
        Risk = 'Medium'; ConfirmMessage = 'Se cambiará la impresora predeterminada del usuario que ejecuta la herramienta.'
        Inputs = @(@{ Name = 'PrinterName'; Label = 'Impresora'; Default = '' }) },
    @{ Id = 'ListDrivers'; Name = 'Drivers de impresora'; Command = 'Get-CSWPrintDrivers'
        Description = 'Lista los drivers de impresora instalados, su versión y si están en uso.' },
    @{ Id = 'StoppedAutoServices'; Name = 'Servicios automáticos detenidos'; Command = 'Get-CSWServiceStoppedAuto'
        Description = 'Detecta servicios de inicio automático que no están en ejecución (excluye los que se detienen solos).' },
    @{ Id = 'StartStoppedAuto'; Name = 'Iniciar servicios detenidos'; Command = 'Start-CSWServiceStoppedAuto'
        Description = 'Intenta iniciar cada servicio automático detenido y reporta el resultado.'
        Risk = 'Medium'; ConfirmMessage = 'Se intentará iniciar todos los servicios automáticos detenidos.' },
    @{ Id = 'ManageService'; Name = 'Gestionar un servicio'; Command = 'Invoke-CSWServiceManage'
        Description = 'Inicia, detiene, reinicia o muestra el estado detallado de un servicio.'
        Risk = 'Medium'; ConfirmMessage = 'Se cambiará el estado del servicio indicado (Status solo consulta).'
        Inputs = @(
            @{ Name = 'Name'; Label = 'Nombre del servicio'; Default = 'Spooler' },
            @{ Name = 'Action'; Label = 'Acción'; Type = 'Choice'; Choices = @('Status', 'Start', 'Stop', 'Restart'); Default = 'Status' }
        ) },
    @{ Id = 'EssentialServices'; Name = 'Servicios esenciales'; Command = 'Test-CSWServiceEssentials'
        Description = 'Comprueba estado y tipo de inicio de los servicios críticos para soporte.' },
    @{ Id = 'RepairWmi'; Name = 'Reparar repositorio WMI'; Command = 'Repair-CSWServiceWmiRepository'
        Description = 'Verifica el repositorio WMI y, si está inconsistente, lo recupera (salvage).'
        Risk = 'High'; ModifiesSystem = $true
        ConfirmMessage = 'Si el repositorio WMI está dañado se reconstruirá; algunos programas pueden necesitar reinstalar sus clases WMI. Se recomienda reiniciar después.' }
)

Export-ModuleMember -Function *
