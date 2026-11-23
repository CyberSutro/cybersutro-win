#Requires -Version 5.1
<#
    Cybersutro win - Modulo Diagnostico (Diagnostics)
    Inventario, estado de salud y analisis de problemas del equipo.
    Solo lectura salvo 'MemoryTest' (programa el diagnostico de memoria en el proximo arranque).
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

$script:WindowsAppId = '55c92734-d682-4d71-983e-d6ec3f16059f'

# ===========================================================================
# Utilidades internas
# ===========================================================================
function ConvertTo-CSWDiagBool {
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $Default }
    return ($t -match '^(1|true|\$true|si|s|yes|y)$')
}

function Get-CSWDiagProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-CSWDiagRegValue {
    param([string]$Path, [string]$Name)
    try {
        $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $p.$Name
    }
    catch { return $null }
}

function Format-CSWDiagSize {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Get-CSWDiagShortText {
    param([string]$Text, [int]$Max = 120)
    if (-not $Text) { return '' }
    $t = (($Text -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' '
    if (-not $t) { return '' }
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Get-CSWDiagWinEvent {
    param([hashtable]$Filter, [int]$MaxEvents = 500)
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Write-CSWLog ("No se pudieron consultar eventos ({0}): {1}" -f $Filter.LogName, $_.Exception.Message) -Level Warn
        }
        return @()
    }
}

function Get-CSWDiagUserHives {
    $out = New-Object System.Collections.ArrayList
    foreach ($k in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $user = $sid
        try { $user = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        [void]$out.Add([pscustomobject]@{ Sid = $sid; User = $user; Root = "Registry::HKEY_USERS\$sid" })
    }
    return $out
}

function Get-CSWDiagLicenseText {
    param([int]$Status)
    switch ($Status) {
        0 { return 'Sin licencia' }
        1 { return 'Activado' }
        2 { return 'Periodo de gracia inicial' }
        3 { return 'Periodo de gracia adicional' }
        4 { return 'Gracia por no genuino' }
        5 { return 'Notificacion (no activado)' }
        6 { return 'Gracia extendida' }
        default { return "Desconocido ($Status)" }
    }
}

function Get-CSWDiagActivationInfo {
    $filter = "ApplicationID='$($script:WindowsAppId)' AND PartialProductKey IS NOT NULL"
    $items = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter -ErrorAction Stop)
    foreach ($x in $items) {
        $grace = Get-CSWDiagProp $x 'GracePeriodRemaining'
        $graceDays = ''
        if ($grace) { $graceDays = [math]::Round(([double]$grace) / 1440, 0) }
        [pscustomobject]@{
            Producto     = [string]$x.Name
            Canal        = [string](Get-CSWDiagProp $x 'ProductKeyChannel')
            ClaveParcial = [string]$x.PartialProductKey
            EstadoCodigo = [int]$x.LicenseStatus
            Estado       = Get-CSWDiagLicenseText ([int]$x.LicenseStatus)
            GraciaDias   = $graceDays
        }
    }
}

function ConvertTo-CSWDiagDiskType {
    param($BusType, $MediaType)
    $b = [string]$BusType
    $m = [string]$MediaType
    switch ($b) {
        '3' { $b = 'ATA' } '7' { $b = 'USB' } '8' { $b = 'RAID' } '10' { $b = 'SAS' } '11' { $b = 'SATA' }
        '12' { $b = 'SD' } '13' { $b = 'MMC' } '15' { $b = 'Virtual' } '16' { $b = 'Storage Spaces' } '17' { $b = 'NVMe' }
    }
    switch ($m) { '0' { $m = 'Unspecified' } '3' { $m = 'HDD' } '4' { $m = 'SSD' } '5' { $m = 'SCM' } }
    if ($b -eq 'NVMe') { return 'NVMe (SSD)' }
    if ($m -eq 'SSD') { return "SSD ($b)" }
    if ($m -eq 'HDD') { return "HDD ($b)" }
    return "Desconocido ($b)"
}

function ConvertTo-CSWDiagHealthText {
    param($Health)
    switch ([string]$Health) {
        'Healthy' { return 'Correcto' } '0' { return 'Correcto' }
        'Warning' { return 'Advertencia' } '1' { return 'Advertencia' }
        'Unhealthy' { return 'Mal estado' } '2' { return 'Mal estado' }
        default { return 'Desconocido' }
    }
}

function Get-CSWDiagGpuMemory {
    # VRAM real desde el registro (Win32_VideoController.AdapterRAM se queda en 4 GB)
    $map = @{}
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    foreach ($k in @(Get-ChildItem -Path $base -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^\d{4}$') { continue }
        try {
            $desc = $k.GetValue('DriverDesc')
            if (-not $desc) { continue }
            $mem = $k.GetValue('HardwareInformation.qwMemorySize')
            if ($null -eq $mem) { $mem = $k.GetValue('HardwareInformation.MemorySize') }
            if ($mem -is [byte[]]) {
                if ($mem.Length -ge 8) { $mem = [BitConverter]::ToUInt64($mem, 0) }
                elseif ($mem.Length -ge 4) { $mem = [BitConverter]::ToUInt32($mem, 0) }
                else { $mem = $null }
            }
            if ($null -ne $mem -and [double]$mem -gt 0) { $map[[string]$desc] = [double]$mem }
        }
        catch { }
    }
    return $map
}

$script:BugCheckNames = @{
    '0xA'        = 'IRQL_NOT_LESS_OR_EQUAL (driver defectuoso)'
    '0x19'       = 'BAD_POOL_HEADER (driver o RAM)'
    '0x1A'       = 'MEMORY_MANAGEMENT (posible fallo de RAM)'
    '0x1E'       = 'KMODE_EXCEPTION_NOT_HANDLED (driver)'
    '0x24'       = 'NTFS_FILE_SYSTEM (disco / sistema de archivos)'
    '0x3B'       = 'SYSTEM_SERVICE_EXCEPTION (driver / sistema)'
    '0x4E'       = 'PFN_LIST_CORRUPT (RAM o driver)'
    '0x50'       = 'PAGE_FAULT_IN_NONPAGED_AREA (RAM o driver)'
    '0x7A'       = 'KERNEL_DATA_INPAGE_ERROR (disco o cable)'
    '0x7E'       = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (driver)'
    '0x7F'       = 'UNEXPECTED_KERNEL_MODE_TRAP (hardware / overclock)'
    '0x9F'       = 'DRIVER_POWER_STATE_FAILURE (suspension / driver)'
    '0xA0'       = 'INTERNAL_POWER_ERROR (energia)'
    '0xBE'       = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY (driver)'
    '0xC2'       = 'BAD_POOL_CALLER (driver)'
    '0xC5'       = 'DRIVER_CORRUPTED_EXPOOL (driver)'
    '0xD1'       = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL (driver, a menudo red)'
    '0xEF'       = 'CRITICAL_PROCESS_DIED (sistema / disco)'
    '0xF4'       = 'CRITICAL_OBJECT_TERMINATION (disco / sistema)'
    '0xFC'       = 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY (driver)'
    '0x101'      = 'CLOCK_WATCHDOG_TIMEOUT (CPU / BIOS)'
    '0x109'      = 'CRITICAL_STRUCTURE_CORRUPTION (RAM / driver)'
    '0x116'      = 'VIDEO_TDR_FAILURE (tarjeta grafica / driver)'
    '0x117'      = 'VIDEO_TDR_TIMEOUT_DETECTED (tarjeta grafica)'
    '0x124'      = 'WHEA_UNCORRECTABLE_ERROR (fallo de hardware)'
    '0x133'      = 'DPC_WATCHDOG_VIOLATION (driver / firmware SSD)'
    '0x139'      = 'KERNEL_SECURITY_CHECK_FAILURE (driver / RAM)'
    '0x13A'      = 'KERNEL_MODE_HEAP_CORRUPTION (driver)'
    '0x154'      = 'UNEXPECTED_STORE_EXCEPTION (disco)'
    '0x1000007E' = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M (driver)'
    '0x1000008E' = 'KERNEL_MODE_EXCEPTION_NOT_HANDLED_M (driver)'
    '0xC000021A' = 'STATUS_SYSTEM_PROCESS_TERMINATED (sistema)'
}

function Get-CSWDiagBugCheckName {
    param([string]$Code)
    if (-not $Code) { return '' }
    try {
        $n = [Convert]::ToInt64(($Code -replace '^0x', ''), 16)
        $key = '0x{0:X}' -f $n
        if ($script:BugCheckNames.ContainsKey($key)) { return $script:BugCheckNames[$key] }
        return ''
    }
    catch { return '' }
}

# ===========================================================================
# Resumen del sistema
# ===========================================================================
function Get-CSWDiagSystemSummary {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Recopilando informacion general del equipo...' -Level Step
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        Write-CSWLog "No se pudo consultar WMI/CIM: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudo leer la informacion del sistema (WMI no responde).' -Status Error)
    }
    $bios = $null; try { $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop } catch { }
    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
    $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue)
    $warnings = New-Object System.Collections.ArrayList

    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVer = Get-CSWDiagRegValue $cv 'DisplayVersion'
    if (-not $displayVer) { $displayVer = Get-CSWDiagRegValue $cv 'ReleaseId' }
    $ubr = Get-CSWDiagRegValue $cv 'UBR'
    $build = [string]$os.BuildNumber
    if ($null -ne $ubr) { $build = "$build.$ubr" }
    $caption = [string]$os.Caption
    # Windows 11 se identifica por build >= 22000 (algunas imagenes aun dicen 'Windows 10' en ProductName)
    if ([int]$os.BuildNumber -ge 22000 -and $caption -match 'Windows 10') { $caption = $caption -replace 'Windows 10', 'Windows 11' }

    $uptime = (Get-Date) - $os.LastBootUpTime
    $totalKB = [double]$os.TotalVisibleMemorySize
    $freeKB = [double]$os.FreePhysicalMemory
    $ramPct = 0
    if ($totalKB -gt 0) { $ramPct = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100, 0) }
    $installed = 0
    try { $installed = [double](@(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop) | Measure-Object -Property Capacity -Sum).Sum } catch { }

    $chassis = switch ([int]$cs.PCSystemType) { 1 { 'Sobremesa' } 2 { 'Portatil' } 3 { 'Estacion de trabajo' } 4 { 'Servidor' } 8 { 'Tablet / convertible' } default { 'Otro' } }

    $fw = 'Desconocido'
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { $fw = 'UEFI (Secure Boot activo)' } else { $fw = 'UEFI (Secure Boot desactivado)' }
    }
    catch {
        if ($_.Exception.Message -match 'not supported|no se admite|no compatible') { $fw = 'BIOS heredada (Legacy)' }
        else {
            # Sin privilegios: la clave SecureBoot\State solo existe en equipos UEFI
            $sbv = Get-CSWDiagRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
            if ($null -ne $sbv) {
                if ([int]$sbv -eq 1) { $fw = 'UEFI (Secure Boot activo)' } else { $fw = 'UEFI (Secure Boot desactivado)' }
            }
        }
    }

    $tpm = 'No detectado'
    try {
        $t = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
        if ($t) {
            $spec = ([string]$t.SpecVersion -split ',')[0].Trim()
            $en = 'desactivado'; if ($t.IsEnabled_InitialValue) { $en = 'activado' }
            $tpm = "TPM $spec ($en)"
        }
    }
    catch { }

    $act = 'Desconocido'
    try {
        $lic = @(Get-CSWDiagActivationInfo)
        if ($lic.Count) {
            $best = $lic | Sort-Object { if ($_.EstadoCodigo -eq 1) { 0 } else { 1 } } | Select-Object -First 1
            $act = $best.Estado
            if ($best.Canal) { $act = "$act ($($best.Canal))" }
            if ($best.EstadoCodigo -ne 1) { [void]$warnings.Add('Windows no activado') }
        }
    }
    catch { }

    $sysDrive = $null
    try { $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop } catch { }
    $diskText = ''
    if ($sysDrive -and $sysDrive.Size) {
        $freePct = [math]::Round(([double]$sysDrive.FreeSpace / [double]$sysDrive.Size) * 100, 0)
        $diskText = '{0} libres de {1} ({2}%)' -f (Format-CSWDiagSize $sysDrive.FreeSpace), (Format-CSWDiagSize $sysDrive.Size), $freePct
        if ($freePct -lt 10 -or [double]$sysDrive.FreeSpace -lt 10GB) { [void]$warnings.Add("poco espacio en $($env:SystemDrive)") }
    }
    if ($ramPct -ge 90) { [void]$warnings.Add("RAM al $ramPct%") }

    $cpuText = ''
    if ($cpus.Count) {
        $c = $cpus[0]
        $cpuText = '{0} ({1} nucleos / {2} hilos, {3:N1} GHz)' -f ([string]$c.Name).Trim(), $c.NumberOfCores, $c.NumberOfLogicalProcessors, ($c.MaxClockSpeed / 1000)
        if ($cpus.Count -gt 1) { $cpuText = "$($cpus.Count) x $cpuText" }
    }
    $gpuText = (($gpus | ForEach-Object { '{0} (driver {1})' -f $_.Name, $_.DriverVersion }) -join ' | ')

    $up = '{0} d {1} h {2} min' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    if ($uptime.TotalDays -ge 14) { Write-CSWLog "El equipo lleva $([int]$uptime.TotalDays) dias sin reiniciar; conviene reiniciar." -Level Warn }

    $o = [ordered]@{}
    $o['Equipo'] = $env:COMPUTERNAME
    $o['Dominio / Grupo'] = [string]$cs.Domain
    $o['Usuario actual'] = [string]$cs.UserName
    $o['Fabricante'] = [string]$cs.Manufacturer
    $o['Modelo'] = [string]$cs.Model
    $o['Tipo'] = $chassis
    if ($bios) {
        $o['N/S'] = [string]$bios.SerialNumber
        $biosDate = ''
        if ($bios.ReleaseDate) { $biosDate = ([datetime]$bios.ReleaseDate).ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
        $o['BIOS'] = ('{0} {1} ({2})' -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $biosDate).Trim()
    }
    $o['Firmware'] = $fw
    $o['TPM'] = $tpm
    $o['Sistema'] = ('{0} {1}' -f $caption, $displayVer).Trim()
    $o['Version / build'] = "$($os.Version) (build $build) $($os.OSArchitecture)"
    $o['Instalado el'] = ([datetime]$os.InstallDate).ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
    $o['Activacion'] = $act
    $o['Ultimo arranque'] = ([datetime]$os.LastBootUpTime).ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    $o['Tiempo encendido'] = $up
    $o['Procesador'] = $cpuText
    $o['RAM instalada'] = Format-CSWDiagSize $installed
    $o['RAM en uso'] = '{0}% ({1} de {2})' -f $ramPct, (Format-CSWDiagSize (($totalKB - $freeKB) * 1KB)), (Format-CSWDiagSize ($totalKB * 1KB))
    $o['Grafica'] = $gpuText
    $o["Disco $($env:SystemDrive)"] = $diskText

    foreach ($k in $o.Keys) { [pscustomobject]@{ Propiedad = $k; Valor = $o[$k] } }

    $sum = '{0} {1} - {2} - {3} RAM ({4}% en uso) - encendido {5}' -f $cs.Manufacturer, $cs.Model, $o['Sistema'], $o['RAM instalada'], $ramPct, $up
    if ($warnings.Count) { New-CSWResult -Summary ("$sum. Atencion: " + ($warnings -join ', ')) -Status Warn }
    else { New-CSWResult -Summary $sum }
}

# ===========================================================================
# Inventario de hardware
# ===========================================================================
function Get-CSWDiagHardwareInventory {
    [CmdletBinding()]
    param()
    $parts = New-Object System.Collections.ArrayList

    Write-CSWLog 'Placa base y BIOS' -Level Step
    try {
        $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
        $rows = @(
            [pscustomobject]@{ Componente = 'Placa base'; Fabricante = $bb.Manufacturer; Modelo = $bb.Product; Version = $bb.Version; NS = $bb.SerialNumber }
        )
        if ($bios) {
            $d = ''; if ($bios.ReleaseDate) { $d = ([datetime]$bios.ReleaseDate).ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
            $rows += [pscustomobject]@{ Componente = 'BIOS/UEFI'; Fabricante = $bios.Manufacturer; Modelo = $bios.SMBIOSBIOSVersion; Version = $d; NS = $bios.SerialNumber }
        }
        $rows | Write-CSWOutput
        [void]$parts.Add("placa $($bb.Manufacturer) $($bb.Product)")
    }
    catch { Write-CSWLog "No se pudo leer la placa base: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Procesador' -Level Step
    try {
        $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
        $cpus | ForEach-Object {
            $virt = Get-CSWDiagProp $_ 'VirtualizationFirmwareEnabled'
            $vt = 'N/D'; if ($null -ne $virt) { if ($virt) { $vt = 'Si' } else { $vt = 'No' } }
            [pscustomobject]@{
                Nombre        = ([string]$_.Name).Trim()
                Nucleos       = $_.NumberOfCores
                Hilos         = $_.NumberOfLogicalProcessors
                'MHz max'     = $_.MaxClockSpeed
                'MHz actual'  = $_.CurrentClockSpeed
                Socket        = $_.SocketDesignation
                'L2 KB'       = $_.L2CacheSize
                'L3 KB'       = $_.L3CacheSize
                Virtualizacion = $vt
            }
        } | Write-CSWOutput
        if ($cpus.Count) { [void]$parts.Add(([string]$cpus[0].Name).Trim()) }
    }
    catch { Write-CSWLog "No se pudo leer el procesador: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Memoria RAM' -Level Step
    try {
        $arrays = @(Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue | Where-Object { $_.Use -eq 3 })
        $slots = 0; $maxKB = 0
        foreach ($a in $arrays) {
            $slots += [int]$a.MemoryDevices
            $mx = Get-CSWDiagProp $a 'MaxCapacityEx'
            if (-not $mx) { $mx = $a.MaxCapacity }
            $maxKB += [double]$mx
        }
        $mods = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop)
        $typeMap = @{ 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
        $ffMap = @{ 8 = 'DIMM'; 12 = 'SODIMM'; 13 = 'SRIMM'; 0 = 'N/D' }
        $total = 0
        $mods | ForEach-Object {
            $total += [double]$_.Capacity
            $t = Get-CSWDiagProp $_ 'SMBIOSMemoryType'
            $tt = 'N/D'; if ($null -ne $t -and $typeMap.ContainsKey([int]$t)) { $tt = $typeMap[[int]$t] }
            $ff = 'N/D'; if ($null -ne $_.FormFactor -and $ffMap.ContainsKey([int]$_.FormFactor)) { $ff = $ffMap[[int]$_.FormFactor] }
            $cfg = Get-CSWDiagProp $_ 'ConfiguredClockSpeed'
            [pscustomobject]@{
                Ranura        = ('{0} {1}' -f $_.BankLabel, $_.DeviceLocator).Trim()
                Capacidad     = Format-CSWDiagSize $_.Capacity
                Tipo          = $tt
                Formato       = $ff
                'MHz nominal' = $_.Speed
                'MHz actual'  = $cfg
                Fabricante    = ([string]$_.Manufacturer).Trim()
                Referencia    = ([string]$_.PartNumber).Trim()
            }
        } | Write-CSWOutput
        $maxText = 'N/D'; if ($maxKB -gt 0) { $maxText = Format-CSWDiagSize ($maxKB * 1KB) }
        Write-CSWLog ("Ranuras: {0} ocupadas de {1} | Total instalado: {2} | Maximo soportado: {3}" -f $mods.Count, $slots, (Format-CSWDiagSize $total), $maxText) -Level Info
        if ($slots -gt $mods.Count) { Write-CSWLog ("Hay {0} ranura(s) libre(s) para ampliar memoria." -f ($slots - $mods.Count)) -Level Info }
        [void]$parts.Add("$(Format-CSWDiagSize $total) RAM en $($mods.Count)/$slots ranuras")
    }
    catch { Write-CSWLog "No se pudo leer la memoria: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Discos fisicos' -Level Step
    $diskCount = 0
    try {
        $pd = @(Get-PhysicalDisk -ErrorAction Stop)
        $pd | Sort-Object { [int]$_.DeviceId } | ForEach-Object {
            [pscustomobject]@{
                Disco     = $_.DeviceId
                Modelo    = $_.FriendlyName
                Tipo      = ConvertTo-CSWDiagDiskType $_.BusType $_.MediaType
                Tamano    = Format-CSWDiagSize $_.Size
                Salud     = ConvertTo-CSWDiagHealthText $_.HealthStatus
                Estado    = (@($_.OperationalStatus) -join ',')
                Firmware  = $_.FirmwareVersion
                NS        = ([string]$_.SerialNumber).Trim()
            }
        } | Write-CSWOutput
        $diskCount = $pd.Count
    }
    catch {
        Write-CSWLog 'Get-PhysicalDisk no disponible; usando Win32_DiskDrive.' -Level Warn
        try {
            $dd = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)
            $dd | ForEach-Object {
                [pscustomobject]@{ Disco = $_.Index; Modelo = $_.Model; Interfaz = $_.InterfaceType; Tamano = (Format-CSWDiagSize $_.Size); Estado = $_.Status; NS = ([string]$_.SerialNumber).Trim() }
            } | Write-CSWOutput
            $diskCount = $dd.Count
        }
        catch { Write-CSWLog "No se pudieron leer los discos: $($_.Exception.Message)" -Level Warn }
    }
    [void]$parts.Add("$diskCount disco(s)")

    Write-CSWLog 'Unidades logicas' -Level Step
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
            $pct = 0; if ($_.Size) { $pct = [math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100, 0) }
            [pscustomobject]@{ Unidad = $_.DeviceID; Etiqueta = $_.VolumeName; Formato = $_.FileSystem; Total = (Format-CSWDiagSize $_.Size); Libre = (Format-CSWDiagSize $_.FreeSpace); 'Libre %' = $pct }
        } | Write-CSWOutput
    }
    catch { Write-CSWLog "No se pudieron leer las unidades: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Tarjeta grafica y pantalla' -Level Step
    try {
        $vram = Get-CSWDiagGpuMemory
        Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | ForEach-Object {
            $mem = 0
            if ($vram.ContainsKey([string]$_.Name)) { $mem = $vram[[string]$_.Name] } elseif ($_.AdapterRAM) { $mem = [double]$_.AdapterRAM }
            $res = ''
            if ($_.CurrentHorizontalResolution) { $res = '{0}x{1} @{2}Hz' -f $_.CurrentHorizontalResolution, $_.CurrentVerticalResolution, $_.CurrentRefreshRate }
            $dd = ''; if ($_.DriverDate) { $dd = ([datetime]$_.DriverDate).ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
            [pscustomobject]@{ Grafica = $_.Name; VRAM = (Format-CSWDiagSize $mem); Driver = $_.DriverVersion; FechaDriver = $dd; Resolucion = $res; Estado = $_.Status }
        } | Write-CSWOutput
    }
    catch { Write-CSWLog "No se pudo leer la grafica: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Adaptadores de red fisicos' -Level Step
    try {
        Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Conexion = $_.NetConnectionID; Adaptador = $_.Name; MAC = $_.MACAddress; Fabricante = $_.Manufacturer }
        } | Write-CSWOutput
    }
    catch { Write-CSWLog "No se pudieron leer los adaptadores de red: $($_.Exception.Message)" -Level Warn }

    Write-CSWLog 'Audio' -Level Step
    try {
        Get-CimInstance -ClassName Win32_SoundDevice -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Dispositivo = $_.Name; Fabricante = $_.Manufacturer; Estado = $_.Status }
        } | Write-CSWOutput
    }
    catch { }

    New-CSWResult -Summary ('Inventario de hardware: ' + ($parts -join '; ') + '.')
}

# ===========================================================================
# Software instalado
# ===========================================================================
function Get-CSWDiagInstalledSoftware {
    [CmdletBinding()]
    param([object]$ExportCsv = $true, [string]$Filter = '')
    $doExport = ConvertTo-CSWDiagBool $ExportCsv $true
    Write-CSWLog 'Leyendo programas instalados (registro 64/32 bits, equipo y usuarios)...' -Level Step

    $sources = New-Object System.Collections.ArrayList
    $u = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $arch64 = '64 bits'; if (-not [Environment]::Is64BitOperatingSystem) { $arch64 = '32 bits' }
    [void]$sources.Add(@{ Path = "HKLM:\$u"; Scope = 'Equipo'; Arch = $arch64 })
    if ([Environment]::Is64BitOperatingSystem) {
        [void]$sources.Add(@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Equipo'; Arch = '32 bits' })
    }
    foreach ($h in @(Get-CSWDiagUserHives)) {
        [void]$sources.Add(@{ Path = "$($h.Root)\$u"; Scope = "Usuario $($h.User)"; Arch = $arch64 })
        [void]$sources.Add(@{ Path = "$($h.Root)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "Usuario $($h.User)"; Arch = '32 bits' })
    }

    $list = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($src in $sources) {
        foreach ($k in @(Get-ChildItem -Path $src.Path -ErrorAction SilentlyContinue)) {
            try {
                $name = [string]$k.GetValue('DisplayName')
                if (-not $name.Trim()) { continue }
                if ([string]$k.GetValue('SystemComponent') -eq '1') { continue }
                if ($k.GetValue('ParentKeyName')) { continue }
                $rt = [string]$k.GetValue('ReleaseType')
                if ($rt -match 'Update|Hotfix') { continue }
                $ver = [string]$k.GetValue('DisplayVersion')
                $key = ('{0}|{1}' -f $name.Trim(), $ver).ToLowerInvariant()
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $dateTxt = ''; $dateVal = $null
                $rawDate = [string]$k.GetValue('InstallDate')
                if ($rawDate -match '^\d{8}$') {
                    try { $dateVal = [datetime]::ParseExact($rawDate, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture); $dateTxt = $dateVal.ToString('dd/MM/yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { }
                }
                $size = $k.GetValue('EstimatedSize')
                $sizeMB = ''
                if ($size) { $sizeMB = [math]::Round(([double]$size) / 1024, 1) }
                [void]$list.Add([pscustomobject]@{
                        Nombre          = $name.Trim()
                        Version         = $ver
                        Editor          = [string]$k.GetValue('Publisher')
                        Instalado       = $dateTxt
                        TamanoMB        = $sizeMB
                        Arquitectura    = $src.Arch
                        Ambito          = $src.Scope
                        Ubicacion       = [string]$k.GetValue('InstallLocation')
                        Desinstalar     = [string]$k.GetValue('UninstallString')
                        DesinstalarSilencioso = [string]$k.GetValue('QuietUninstallString')
                        ClaveRegistro   = $k.Name
                        FechaInst       = $dateVal
                    })
            }
            catch { }
        }
    }

    $all = @($list | Sort-Object Nombre)
    if ($Filter) {
        $f = "*$Filter*"
        $all = @($all | Where-Object { $_.Nombre -like $f -or $_.Editor -like $f })
        Write-CSWLog "Filtro aplicado: '$Filter' ($($all.Count) coincidencias)" -Level Info
    }
    if (-not $all.Count) {
        return (New-CSWResult -Summary 'No se encontraron programas con esos criterios.' -Status Warn)
    }

    $csvPath = ''
    if ($doExport) {
        try {
            $csvPath = Join-Path (Get-CSWDataPath Reports) ('Software_{0}_{1:yyyyMMdd_HHmmss}.csv' -f $env:COMPUTERNAME, (Get-Date))
            $all | Select-Object -Property * -ExcludeProperty FechaInst | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
            Write-CSWLog "Lista exportada a CSV: $csvPath" -Level Ok
        }
        catch {
            Write-CSWLog "No se pudo exportar el CSV: $($_.Exception.Message)" -Level Warn
            $csvPath = ''
        }
    }

    $all | Select-Object Nombre, Version, Editor, Instalado, TamanoMB, Arquitectura
    $limit = (Get-Date).Date.AddDays(-30)
    $recent = @($all | Where-Object { $null -ne $_.FechaInst -and $_.FechaInst -ge $limit })
    if ($recent.Count) { Write-CSWLog ("Instalados en los ultimos 30 dias: {0}" -f (($recent | ForEach-Object { $_.Nombre }) -join ', ')) -Level Info }

    $sum = "$($all.Count) programas instalados"
    if ($csvPath) { $sum += " (lista exportada a $csvPath)" }
    New-CSWResult -Summary "$sum."
}

# ===========================================================================
# Dispositivos / drivers con problemas
# ===========================================================================
function Get-CSWDiagProblemDevices {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Buscando dispositivos con errores en el Administrador de dispositivos...' -Level Step
    $codes = @{
        1 = 'Mal configurado'; 3 = 'Driver danado o memoria insuficiente'; 10 = 'El dispositivo no puede iniciar'
        12 = 'Recursos insuficientes o en conflicto'; 14 = 'Requiere reiniciar el equipo'; 18 = 'Hay que reinstalar los drivers'
        19 = 'Configuracion del registro danada'; 21 = 'Windows esta quitando el dispositivo'; 22 = 'Deshabilitado'
        24 = 'No presente o drivers incompletos'; 28 = 'Drivers no instalados'; 29 = 'Deshabilitado por el firmware'
        31 = 'No funciona correctamente (driver no carga)'; 32 = 'Servicio del driver deshabilitado'; 37 = 'El driver no se pudo inicializar'
        38 = 'Driver ya cargado por otra instancia'; 39 = 'Driver danado o ausente'; 40 = 'Clave de servicio del driver invalida'
        41 = 'El driver cargo pero no encuentra el hardware'; 43 = 'Windows lo detuvo porque reporto fallos'; 45 = 'Desconectado'
        47 = 'Preparado para extraccion segura'; 48 = 'Driver bloqueado por incompatibilidad'; 52 = 'Firma digital del driver no verificada'
    }
    $info = @(22, 45, 47)
    try { $devs = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction Stop) }
    catch {
        Write-CSWLog "No se pudo consultar los dispositivos: $($_.Exception.Message)" -Level Error
        return (New-CSWResult -Summary 'No se pudo consultar el Administrador de dispositivos.' -Status Error)
    }
    if (-not $devs.Count) { return (New-CSWResult -Summary 'Todos los dispositivos funcionan correctamente (sin errores de driver).') }

    $rows = foreach ($d in $devs) {
        $c = [int]$d.ConfigManagerErrorCode
        $txt = "Codigo $c"; if ($codes.ContainsKey($c)) { $txt = $codes[$c] }
        $hw = ''
        $ids = Get-CSWDiagProp $d 'HardwareID'
        if ($ids) { $hw = @($ids)[0] }
        $name = [string]$d.Name; if (-not $name) { $name = '(Dispositivo desconocido)' }
        [pscustomobject]@{
            Dispositivo = $name
            Clase       = [string](Get-CSWDiagProp $d 'PNPClass')
            Codigo      = $c
            Problema    = $txt
            HardwareID  = $hw
        }
    }
    $rows = @($rows | Sort-Object Codigo, Dispositivo)
    $rows
    $real = @($rows | Where-Object { $info -notcontains $_.Codigo })
    if (@($rows | Where-Object { $_.Codigo -eq 28 }).Count) {
        Write-CSWLog 'Consejo: para drivers no instalados (codigo 28) busque el HardwareID (VEN_xxxx&DEV_xxxx) en la web del fabricante o use Windows Update.' -Level Info
    }
    if ($real.Count) {
        return (New-CSWResult -Summary ("{0} dispositivo(s) con problemas de driver: {1}." -f $real.Count, (($real | Select-Object -First 5 | ForEach-Object { $_.Dispositivo }) -join ', ')) -Status Warn)
    }
    New-CSWResult -Summary ("Sin errores de driver; {0} dispositivo(s) deshabilitado(s) o desconectado(s)." -f $rows.Count)
}

# ===========================================================================
# Eventos criticos (ID obligatorio: Diagnostics.CriticalEvents)
# ===========================================================================
function Get-CSWDiagCriticalEvents {
    [CmdletBinding()]
    param([int]$Days = 7)
    if ($Days -lt 1) { $Days = 7 }
    $start = (Get-Date).AddDays(-$Days)
    Write-CSWLog "Buscando eventos Criticos y de Error en System y Application (ultimos $Days dias)..." -Level Step
    $events = New-Object System.Collections.ArrayList
    $readErrors = 0
    foreach ($log in 'System', 'Application') {
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2; StartTime = $start } -MaxEvents 5000 -ErrorAction Stop)
            foreach ($e in $ev) { [void]$events.Add($e) }
            Write-CSWLog ("{0}: {1} eventos" -f $log, $ev.Count) -Level Info
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { Write-CSWLog "${log}: sin eventos criticos ni errores." -Level Ok }
            else { $readErrors++; Write-CSWLog "No se pudo leer el registro ${log}: $($_.Exception.Message)" -Level Warn }
        }
    }
    if ($readErrors -ge 2) {
        if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult 'registros de eventos') }
        return (New-CSWResult -Summary 'No se pudieron leer los registros de eventos System y Application.' -Status Error)
    }
    if (-not $events.Count) { return (New-CSWResult -Summary "Sin errores ni eventos criticos en los ultimos $Days dias.") }

    $crit = @($events | Where-Object { $_.Level -eq 1 }).Count
    $errs = $events.Count - $crit

    Write-CSWLog 'Agrupado por origen (mas frecuentes primero)' -Level Step
    $groups = @($events | Group-Object -Property LogName, ProviderName | Sort-Object Count -Descending)
    $groups | Select-Object -First 20 | ForEach-Object {
        $items = @($_.Group)
        $last = $items | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $ids = (($items | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { '{0} (x{1})' -f $_.Name, $_.Count }) -join ', ')
        [pscustomobject]@{
            Registro   = $items[0].LogName
            Origen     = $items[0].ProviderName
            Total      = $items.Count
            Criticos   = @($items | Where-Object { $_.Level -eq 1 }).Count
            'Ultima vez' = $last.TimeCreated.ToString('dd/MM HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
            'IDs principales' = $ids
        }
    } | Write-CSWOutput

    Write-CSWLog 'Los 15 eventos mas recientes' -Level Step
    $events | Sort-Object TimeCreated -Descending | Select-Object -First 15 | ForEach-Object {
        $lvl = 'Error'; if ($_.Level -eq 1) { $lvl = 'CRITICO' }
        $msg = ''
        try { $msg = Get-CSWDiagShortText ([string]$_.Message) 110 } catch { }
        if (-not $msg) { $msg = '(sin descripcion)' }
        [pscustomobject]@{
            Fecha    = $_.TimeCreated.ToString('dd/MM HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            Nivel    = $lvl
            Registro = $_.LogName
            Origen   = $_.ProviderName
            Id       = $_.Id
            Mensaje  = $msg
        }
    } | Write-CSWOutput

    # Pistas sobre origenes conocidos
    $prov = @($groups | ForEach-Object { $_.Group[0].ProviderName })
    if ($prov -contains 'Microsoft-Windows-Kernel-Power') { Write-CSWLog 'Hay apagados inesperados (Kernel-Power 41): revisar alimentacion, temperaturas o pantallazos azules.' -Level Warn }
    if ($prov -match '^(disk|Ntfs|storahci|stornvme|volmgr)$') { Write-CSWLog 'Hay errores de disco/almacenamiento: revise Salud de hardware > Salud de discos (SMART) y haga copia de seguridad.' -Level Warn }
    if ($prov -contains 'Microsoft-Windows-WHEA-Logger') { Write-CSWLog 'Hay errores de hardware WHEA (CPU/RAM/PCIe): posible fallo de hardware.' -Level Warn }
    if ($prov -contains 'DistributedCOM') { Write-CSWLog 'Los errores DistributedCOM (10016) son habituales y normalmente inofensivos.' -Level Info }

    $top = $groups[0].Group[0].ProviderName
    $sum = "Ultimos $Days dias: $crit critico(s) y $errs error(es); origen mas frecuente: $top ($($groups[0].Count))."
    if ($crit -gt 0 -or $errs -gt 200) { return (New-CSWResult -Summary $sum -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Historial de pantallazos azules (BSOD) y apagados inesperados
# ===========================================================================
function Get-CSWDiagBsodHistory {
    [CmdletBinding()]
    param([int]$Days = 90)
    if ($Days -lt 1) { $Days = 90 }
    $start = (Get-Date).AddDays(-$Days)
    Write-CSWLog "Buscando pantallazos azules y apagados inesperados (ultimos $Days dias)..." -Level Step

    $rows = New-Object System.Collections.ArrayList
    $codes = New-Object System.Collections.ArrayList

    $bc = @(Get-CSWDiagWinEvent @{ LogName = 'System'; Id = 1001; StartTime = $start } 300 | Where-Object { $_.ProviderName -match 'WER-SystemErrorReporting|BugCheck' })
    foreach ($e in $bc) {
        $msg = [string]$e.Message
        $code = ''
        if ($msg -match '(0x[0-9a-fA-F]{8,16})') { $code = $Matches[1] }
        elseif ($e.Properties.Count -gt 0 -and ([string]$e.Properties[0].Value) -match '(0x[0-9a-fA-F]+)') { $code = $Matches[1] }
        $dump = ''
        if ($msg -match '([A-Za-z]:\\[^\s"]+\.dmp)') { $dump = $Matches[1] }
        if ($code) { [void]$codes.Add($code) }
        [void]$rows.Add([pscustomobject]@{
                Fecha  = $e.TimeCreated.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                Tipo   = 'Pantallazo azul'
                Codigo = $code
                Significado = Get-CSWDiagBugCheckName $code
                Detalle = $dump
            })
    }

    $kp = @(Get-CSWDiagWinEvent @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $start } 300)
    foreach ($e in $kp) {
        $code = ''; $det = 'Perdida de energia, cuelgue o boton de apagado'
        try {
            if ($e.Properties.Count -gt 0) {
                $v = [int64]$e.Properties[0].Value
                if ($v -ne 0) { $code = '0x{0:X}' -f $v; $det = 'Reinicio por pantallazo azul' }
            }
        }
        catch { }
        [void]$rows.Add([pscustomobject]@{
                Fecha  = $e.TimeCreated.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                Tipo   = 'Apagado incorrecto (Kernel-Power 41)'
                Codigo = $code
                Significado = Get-CSWDiagBugCheckName $code
                Detalle = $det
            })
    }

    $us = @(Get-CSWDiagWinEvent @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $start } 300)
    foreach ($e in $us) {
        [void]$rows.Add([pscustomobject]@{
                Fecha  = $e.TimeCreated.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                Tipo   = 'Apagado inesperado (6008)'
                Codigo = ''
                Significado = ''
                Detalle = 'El sistema anterior se cerro de forma inesperada'
            })
    }

    if ($rows.Count) { $rows | Sort-Object { [datetime]::ParseExact($_.Fecha, 'dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) } -Descending | Write-CSWOutput }

    Write-CSWLog 'Archivos de volcado de memoria' -Level Step
    $dumps = New-Object System.Collections.ArrayList
    $mini = Join-Path $env:SystemRoot 'Minidump'
    foreach ($f in @(Get-ChildItem -Path $mini -Filter '*.dmp' -ErrorAction SilentlyContinue)) { [void]$dumps.Add($f) }
    $full = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (Test-Path $full) { [void]$dumps.Add((Get-Item $full)) }
    $lkr = Join-Path $env:SystemRoot 'LiveKernelReports'
    foreach ($f in @(Get-ChildItem -Path $lkr -Filter '*.dmp' -Recurse -ErrorAction SilentlyContinue)) { [void]$dumps.Add($f) }
    if ($dumps.Count) {
        $dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 20 | ForEach-Object {
            [pscustomobject]@{ Archivo = $_.FullName; Fecha = $_.LastWriteTime.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture); Tamano = (Format-CSWDiagSize $_.Length) }
        } | Write-CSWOutput
        Write-CSWLog 'Los volcados pueden analizarse con WinDbg (!analyze -v) o BlueScreenView.' -Level Info
        if (@($dumps | Where-Object { $_.FullName -like "$lkr*" }).Count) { Write-CSWLog 'LiveKernelReports suele indicar cuelgues de la grafica (WATCHDOG/TDR) o USB.' -Level Info }
    }
    else { Write-CSWLog 'No hay archivos de volcado (.dmp).' -Level Info }

    $bsodCount = $bc.Count
    $kpCount = $kp.Count
    if (-not $rows.Count) { return (New-CSWResult -Summary "Sin pantallazos azules ni apagados inesperados en los ultimos $Days dias.") }
    $topText = ''
    if ($codes.Count) {
        $topCode = ($codes | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
        $topName = Get-CSWDiagBugCheckName $topCode
        $topText = " Codigo mas frecuente: $topCode"
        if ($topName) { $topText += " - $topName" }
        $topText += '.'
    }
    $sum = "Ultimos $Days dias: $bsodCount pantallazo(s) azul(es), $kpCount apagado(s) incorrecto(s), $($us.Count) cierre(s) inesperado(s).$topText"
    New-CSWResult -Summary $sum -Status Warn
}

# ===========================================================================
# Bateria
# ===========================================================================
function Get-CSWDiagBatteryReport {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Comprobando bateria...' -Level Step
    $bat = @()
    try { $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) } catch { }
    if (-not $bat.Count) {
        return (New-CSWResult -Summary 'El equipo no tiene bateria (sobremesa o bateria no detectada).' -Status Warn)
    }
    foreach ($b in $bat) {
        $st = switch ([int]$b.BatteryStatus) { 1 { 'Descargando' } 2 { 'Conectado a corriente' } 3 { 'Carga completa' } 4 { 'Baja' } 5 { 'Critica' } 6 { 'Cargando' } 7 { 'Cargando (alta)' } 8 { 'Cargando (baja)' } 9 { 'Cargando (critica)' } default { 'Desconocido' } }
        Write-CSWLog ("Bateria: {0} | Carga {1}% | {2} | Autonomia estimada {3} min" -f $b.Name, $b.EstimatedChargeRemaining, $st, $b.EstimatedRunTime) -Level Info
    }

    $reportPath = Join-Path (Get-CSWDataPath Reports) ('Bateria_{0}_{1:yyyyMMdd_HHmmss}.html' -f $env:COMPUTERNAME, (Get-Date))
    $code = Invoke-CSWExternal -FilePath 'powercfg.exe' -Arguments ('/batteryreport /output "{0}"' -f $reportPath)
    $reportOk = ($code -eq 0 -and (Test-Path $reportPath))
    if ($reportOk) { Write-CSWLog "Informe de bateria guardado en: $reportPath" -Level Ok }
    else { Write-CSWLog "powercfg /batteryreport fallo (codigo $code)." -Level Warn }

    $design = 0; $full = 0; $cycles = $null
    try {
        $sd = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction Stop)
        $fc = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)
        foreach ($x in $sd) { $design += [double]$x.DesignedCapacity }
        foreach ($x in $fc) { $full += [double]$x.FullChargedCapacity }
    }
    catch { }
    try {
        $cc = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction Stop)
        if ($cc.Count) { $cycles = ($cc | Measure-Object -Property CycleCount -Sum).Sum }
    }
    catch { }

    if (($design -le 0 -or $full -le 0) -and $reportOk) {
        try {
            $html = Get-Content -Path $reportPath -Raw
            if ($html -match '(?is)DESIGN CAPACITY.*?<td>\s*([\d\.,\s]+)\s*mWh') { $design = [double](($Matches[1]) -replace '[^\d]', '') }
            if ($html -match '(?is)FULL CHARGE CAPACITY.*?<td>\s*([\d\.,\s]+)\s*mWh') { $full = [double](($Matches[1]) -replace '[^\d]', '') }
            if (-not $cycles -and $html -match '(?is)CYCLE COUNT.*?<td>\s*(\d+)\s*<') { $cycles = [int]$Matches[1] }
        }
        catch { }
    }

    if ($design -gt 0 -and $full -gt 0) {
        $health = [math]::Round(($full / $design) * 100, 0)
        if ($health -gt 100) { $health = 100 }
        [pscustomobject]@{
            'Capacidad de diseno' = ('{0:N0} mWh' -f $design)
            'Capacidad actual'    = ('{0:N0} mWh' -f $full)
            'Salud'               = "$health%"
            'Ciclos'              = $cycles
            'Informe'             = $reportPath
        }
        $txt = "Salud de la bateria: $health% de la capacidad original ({0:N0} de {1:N0} mWh)" -f $full, $design
        if ($null -ne $cycles -and $cycles -gt 0) { $txt += ", $cycles ciclos" }
        if ($health -lt 50) { return (New-CSWResult -Summary "$txt. Bateria muy desgastada: se recomienda sustituirla." -Status Warn) }
        if ($health -lt 70) { return (New-CSWResult -Summary "$txt. Desgaste notable; autonomia reducida." -Status Warn) }
        return (New-CSWResult -Summary "$txt. Estado correcto.")
    }
    if ($reportOk) { return (New-CSWResult -Summary "No se pudo calcular la salud de la bateria; informe completo en $reportPath" -Status Warn) }
    New-CSWResult -Summary 'No se pudo obtener informacion de la bateria.' -Status Warn
}

# ===========================================================================
# Temperaturas / estado termico
# ===========================================================================
function Get-CSWDiagThermal {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Leyendo sensores termicos disponibles (ACPI, zonas termicas, discos)...' -Level Step
    $rows = New-Object System.Collections.ArrayList
    $hot = New-Object System.Collections.ArrayList
    $throttle = $false

    try {
        $tz = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        foreach ($z in $tz) {
            $c = [math]::Round(([double]$z.CurrentTemperature / 10) - 273.15, 1)
            if ($c -lt 5 -or $c -gt 125) { continue }
            $crit = ''
            if ($z.CriticalTripPoint) { $crit = [math]::Round(([double]$z.CriticalTripPoint / 10) - 273.15, 0) }
            [void]$rows.Add([pscustomobject]@{ Sensor = ($z.InstanceName -replace '^ACPI\\ThermalZone\\', 'ACPI '); Temperatura = "$c C"; Critico = $crit; Fuente = 'ACPI' })
            if ($c -ge 85) { [void]$hot.Add("$($z.InstanceName) $c C") }
        }
    }
    catch { Write-CSWLog 'MSAcpi_ThermalZoneTemperature no disponible (habitual; depende del fabricante).' -Level Info }

    if (-not $rows.Count) {
        try {
            $pz = @(Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop)
            foreach ($z in $pz) {
                $c = [math]::Round([double]$z.Temperature - 273.15, 1)
                if ($c -lt 5 -or $c -gt 125) { continue }
                $pl = Get-CSWDiagProp $z 'PercentPassiveLimit'
                if ($null -ne $pl -and [int]$pl -lt 100) { $throttle = $true }
                [void]$rows.Add([pscustomobject]@{ Sensor = $z.Name; Temperatura = "$c C"; Critico = ''; Fuente = 'Zona termica' })
                if ($c -ge 85) { [void]$hot.Add("$($z.Name) $c C") }
            }
        }
        catch { }
    }

    try {
        foreach ($d in @(Get-PhysicalDisk -ErrorAction Stop)) {
            $rc = $null
            try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
            $t = Get-CSWDiagProp $rc 'Temperature'
            if ($null -ne $t -and [int]$t -gt 0) {
                $tm = Get-CSWDiagProp $rc 'TemperatureMax'
                [void]$rows.Add([pscustomobject]@{ Sensor = "Disco: $($d.FriendlyName)"; Temperatura = "$t C"; Critico = $tm; Fuente = 'SMART' })
                if ([int]$t -ge 60) { [void]$hot.Add("$($d.FriendlyName) $t C") }
            }
        }
    }
    catch { }

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($cpu.MaxClockSpeed -and $cpu.CurrentClockSpeed) {
            Write-CSWLog ("CPU: {0} MHz actuales de {1} MHz nominales." -f $cpu.CurrentClockSpeed, $cpu.MaxClockSpeed) -Level Info
        }
        $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
        $pp = Get-CSWDiagProp $perf 'PercentofMaximumFrequency'
        if ($null -ne $pp) {
            Write-CSWLog "Frecuencia de la CPU al $pp% de su maximo." -Level Info
            $lim = Get-CSWDiagProp $perf 'PercentPerformanceLimit'
            if ($null -ne $lim -and [int]$lim -lt 100) { $throttle = $true; Write-CSWLog "La CPU esta limitada al $lim% de rendimiento (temperatura o energia)." -Level Warn }
        }
    }
    catch { }

    if ($rows.Count) { $rows | Write-CSWOutput }
    if (-not $rows.Count) {
        return (New-CSWResult -Summary 'El equipo no expone sensores de temperatura a Windows; use HWiNFO o el software del fabricante.' -Status Warn)
    }
    Write-CSWLog 'Nota: los valores ACPI son aproximados y no siempre corresponden al nucleo de la CPU.' -Level Info
    if ($hot.Count) { return (New-CSWResult -Summary ('Temperaturas elevadas: ' + ($hot -join ', ') + '. Revisar ventilacion y limpieza.') -Status Warn) }
    if ($throttle) { return (New-CSWResult -Summary 'Temperaturas normales, pero la CPU esta reduciendo su rendimiento (limitacion termica o de energia).' -Status Warn) }
    New-CSWResult -Summary ("Temperaturas normales ({0} sensor(es) leidos)." -f $rows.Count)
}

# ===========================================================================
# Rendimiento actual
# ===========================================================================
function Get-CSWDiagPerformance {
    [CmdletBinding()]
    param([int]$SampleSeconds = 2)
    if ($SampleSeconds -lt 1) { $SampleSeconds = 2 }
    Write-CSWLog "Midiendo el uso de recursos durante $SampleSeconds segundos..." -Level Step
    $cores = [Environment]::ProcessorCount
    $warn = New-Object System.Collections.ArrayList

    $s1 = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        try { $t = $p.TotalProcessorTime; if ($null -ne $t) { $s1[$p.Id] = $t.TotalMilliseconds } } catch { }
    }
    $raw1 = $null
    try { $raw1 = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop } catch { }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds $SampleSeconds
    $procs = @(Get-Process -ErrorAction SilentlyContinue)
    $elapsed = $sw.Elapsed.TotalMilliseconds

    $cpuRows = New-Object System.Collections.ArrayList
    foreach ($p in $procs) {
        if ($p.Id -eq 0) { continue }
        $pct = 0
        try {
            $t = $p.TotalProcessorTime
            if ($null -ne $t -and $s1.ContainsKey($p.Id)) { $pct = (($t.TotalMilliseconds - $s1[$p.Id]) / $elapsed / $cores) * 100 }
        }
        catch { }
        [void]$cpuRows.Add([pscustomobject]@{ Name = $p.ProcessName; Id = $p.Id; Cpu = $pct; Ws = [double]$p.WorkingSet64; Priv = [double]$p.PrivateMemorySize64 })
    }

    $cpuTotal = $null
    # CPU total exacta: diferencia entre dos muestras del contador bruto (tiempo inactivo / marca de tiempo)
    try {
        if ($raw1) {
            $raw2 = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            $dt = [double]$raw2.Timestamp_Sys100NS - [double]$raw1.Timestamp_Sys100NS
            if ($dt -gt 0) {
                $idle = ([double]$raw2.PercentProcessorTime - [double]$raw1.PercentProcessorTime) / $dt
                $cpuTotal = [int][math]::Round([math]::Max(0, [math]::Min(100, (1 - $idle) * 100)), 0)
            }
        }
    }
    catch { }
    if ($null -eq $cpuTotal) { $cpuTotal = [int][math]::Min(100, ($cpuRows | Measure-Object -Property Cpu -Sum).Sum) }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ramPct = 0; $ramTxt = ''
    if ($os) {
        $tot = [double]$os.TotalVisibleMemorySize * 1KB; $free = [double]$os.FreePhysicalMemory * 1KB
        $ramPct = [math]::Round((($tot - $free) / $tot) * 100, 0)
        $ramTxt = '{0} de {1}' -f (Format-CSWDiagSize ($tot - $free)), (Format-CSWDiagSize $tot)
    }
    $commitTxt = ''
    try {
        $mem = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $commitTxt = '{0} de {1}' -f (Format-CSWDiagSize $mem.CommittedBytes), (Format-CSWDiagSize $mem.CommitLimit)
    }
    catch { }

    Write-CSWLog ("CPU total: {0}% | RAM: {1}% ({2}) | Memoria comprometida: {3} | Procesos: {4}" -f $cpuTotal, $ramPct, $ramTxt, $commitTxt, $procs.Count) -Level Info
    if ($cpuTotal -ge 85) { [void]$warn.Add("CPU al $cpuTotal%") }
    if ($ramPct -ge 90) { [void]$warn.Add("RAM al $ramPct%") }

    Write-CSWLog 'Top 10 por CPU (agrupado por programa)' -Level Step
    $byName = @($cpuRows | Group-Object Name | ForEach-Object {
            [pscustomobject]@{
                Programa  = $_.Name
                Procesos  = $_.Count
                'CPU %'   = [math]::Round(($_.Group | Measure-Object -Property Cpu -Sum).Sum, 1)
                'RAM'     = Format-CSWDiagSize (($_.Group | Measure-Object -Property Ws -Sum).Sum)
                RamBytes  = ($_.Group | Measure-Object -Property Ws -Sum).Sum
            }
        })
    $byName | Sort-Object 'CPU %' -Descending | Select-Object -First 10 Programa, Procesos, 'CPU %', RAM | Write-CSWOutput

    Write-CSWLog 'Top 10 por memoria RAM (agrupado por programa)' -Level Step
    $byName | Sort-Object RamBytes -Descending | Select-Object -First 10 Programa, Procesos, RAM, 'CPU %' | Write-CSWOutput

    Write-CSWLog 'Actividad de discos' -Level Step
    try {
        $disks = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop | Where-Object { $_.Name -ne '_Total' })
        $disks | ForEach-Object {
            $active = 100 - [int]$_.PercentIdleTime
            if ($active -lt 0) { $active = 0 }
            if ($active -ge 90) { [void]$warn.Add("disco $($_.Name) al $active%") }
            [pscustomobject]@{
                Disco        = $_.Name
                'Actividad %' = $active
                'Lectura/s'  = Format-CSWDiagSize $_.DiskReadBytesPersec
                'Escritura/s' = Format-CSWDiagSize $_.DiskWriteBytesPersec
                'Cola'       = $_.CurrentDiskQueueLength
                'ms/operacion' = [math]::Round([double]$_.AvgDisksecPerTransfer * 1000, 1)
            }
        } | Write-CSWOutput
    }
    catch { Write-CSWLog "Contadores de disco no disponibles: $($_.Exception.Message)" -Level Warn }

    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
            if ($_.Size) {
                $pct = [math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100, 0)
                Write-CSWLog ("Espacio {0} {1} libres de {2} ({3}%)" -f $_.DeviceID, (Format-CSWDiagSize $_.FreeSpace), (Format-CSWDiagSize $_.Size), $pct) -Level Info
                if ($pct -lt 10) { [void]$warn.Add("poco espacio en $($_.DeviceID)") }
            }
        }
    }
    catch { }

    $topCpu = ($byName | Sort-Object 'CPU %' -Descending | Select-Object -First 1)
    $topRam = ($byName | Sort-Object RamBytes -Descending | Select-Object -First 1)
    $sum = "CPU $cpuTotal%, RAM $ramPct%. Mayor consumo de CPU: $($topCpu.Programa) ($($topCpu.'CPU %')%); de RAM: $($topRam.Programa) ($($topRam.RAM))."
    if ($warn.Count) { return (New-CSWResult -Summary ("$sum Atencion: " + ($warn -join ', ') + '.') -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Programas de inicio
# ===========================================================================
function Get-CSWDiagStartupApproved {
    # Devuelve hashtable 'ruta|nombre' -> $true (habilitado) / $false (deshabilitado en el Administrador de tareas)
    $map = @{}
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add(@{ Root = 'HKLM:'; Tag = 'HKLM' })
    foreach ($h in @(Get-CSWDiagUserHives)) { [void]$roots.Add(@{ Root = $h.Root; Tag = $h.Sid }) }
    foreach ($r in $roots) {
        foreach ($sub in 'Run', 'Run32', 'StartupFolder') {
            $path = "$($r.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"
            $k = Get-Item -Path $path -ErrorAction SilentlyContinue
            if (-not $k) { continue }
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                if ($v -is [byte[]] -and $v.Length -gt 0) { $map[$n.ToLowerInvariant()] = (($v[0] -band 1) -eq 0) }
            }
        }
    }
    return $map
}

function Get-CSWDiagStartupPrograms {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Leyendo programas que se inician con Windows...' -Level Step
    $approved = Get-CSWDiagStartupApproved
    $items = New-Object System.Collections.ArrayList
    $seen = @{}

    $addItem = {
        param($Name, $Command, $Origin, $User)
        # Normaliza la ubicacion para que Win32_StartupCommand y el registro coincidan (HKLM\Run, HKCU\Run, HKLM\Wow6432Node\Run...)
        $Origin = ([string]$Origin) -replace '^HKU\\S-1-5-[\d-]+\\', 'HKCU\' -replace '(?i)\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', '\$1'
        $Origin = $Origin -replace '(?i)\\Wow6432Node\\', '\WOW6432Node\'
        $key = ('{0}|{1}' -f $Name, $Origin).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        $state = 'Habilitado'
        $n = ([string]$Name).ToLowerInvariant()
        foreach ($cand in @($n, "$n.lnk")) {
            if ($approved.ContainsKey($cand)) { if (-not $approved[$cand]) { $state = 'Deshabilitado' }; break }
        }
        $cmd = [string]$Command
        if ($cmd.Length -gt 90) { $cmd = $cmd.Substring(0, 87) + '...' }
        [void]$items.Add([pscustomobject]@{ Nombre = $Name; Estado = $state; Origen = $Origin; Usuario = $User; Comando = $cmd })
    }

    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop)) {
            & $addItem $s.Name $s.Command $s.Location $s.User
        }
    }
    catch { Write-CSWLog "Win32_StartupCommand no disponible: $($_.Exception.Message)" -Level Warn }

    $regSources = New-Object System.Collections.ArrayList
    foreach ($sub in 'Run', 'RunOnce') {
        [void]$regSources.Add(@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\$sub"; Origin = "HKLM\$sub"; User = 'Todos' })
        [void]$regSources.Add(@{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\$sub"; Origin = "HKLM\WOW6432Node\$sub"; User = 'Todos' })
        foreach ($h in @(Get-CSWDiagUserHives)) {
            [void]$regSources.Add(@{ Path = "$($h.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\$sub"; Origin = "HKCU\$sub"; User = $h.User })
        }
    }
    foreach ($src in $regSources) {
        $k = Get-Item -Path $src.Path -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            if (-not $n) { continue }
            & $addItem $n ([string]$k.GetValue($n)) $src.Origin $src.User
        }
    }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and [string]$_.State -ne 'Disabled' })
        foreach ($t in $tasks) {
            $trig = @($t.Triggers | Where-Object { $_ -and $_.CimClass.CimClassName -match 'MSFT_TaskLogonTrigger|MSFT_TaskBootTrigger' })
            if (-not $trig.Count) { continue }
            $act = @($t.Actions | Select-Object -First 1)
            $cmd = ''
            if ($act.Count -and $act[0].PSObject.Properties['Execute']) { $cmd = ('{0} {1}' -f $act[0].Execute, $act[0].Arguments).Trim() }
            & $addItem $t.TaskName $cmd 'Tarea programada' ([string]$t.Principal.UserId)
        }
    }
    catch { Write-CSWLog "No se pudieron leer las tareas programadas: $($_.Exception.Message)" -Level Info }

    if (-not $items.Count) { return (New-CSWResult -Summary 'No hay programas configurados para iniciarse con Windows.') }
    $items | Sort-Object @{ Expression = 'Estado'; Descending = $true }, Origen, Nombre
    $en = @($items | Where-Object { $_.Estado -eq 'Habilitado' }).Count
    $sum = "$($items.Count) elementos de inicio ($en habilitados)."
    if ($en -gt 15) { return (New-CSWResult -Summary "$sum Demasiados programas al inicio: conviene deshabilitar los innecesarios para acelerar el arranque." -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Prueba de memoria RAM (Windows Memory Diagnostic)
# ===========================================================================
function Start-CSWDiagMemoryTest {
    [CmdletBinding()]
    param()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not (Test-Path $bcd)) { return (New-CSWResult -Summary 'No se encontro bcdedit.exe.' -Status Error) }
    Write-CSWLog 'Comprobando que el diagnostico de memoria existe en el gestor de arranque...' -Level Step
    $code = Invoke-CSWExternal -FilePath $bcd -Arguments '/enum {memdiag}'
    if ($code -ne 0) { return (New-CSWResult -Summary 'El gestor de arranque no tiene la herramienta de diagnostico de memoria ({memdiag}).' -Status Error) }
    Write-CSWLog 'Programando el diagnostico de memoria para el proximo arranque...' -Level Step
    $code = Invoke-CSWExternal -FilePath $bcd -Arguments '/bootsequence {memdiag} /addfirst'
    if ($code -ne 0) { return (New-CSWResult -Summary "No se pudo programar la prueba de memoria (bcdedit codigo $code)." -Status Error) }
    Write-CSWLog 'Prueba programada. NO se reinicia automaticamente: reinicie el equipo cuando el cliente lo permita.' -Level Ok
    Write-CSWLog 'La prueba tarda 10-30 min; el resultado aparece tras iniciar sesion y en la accion "Resultado prueba de memoria".' -Level Info
    New-CSWResult -Summary 'Prueba de memoria RAM programada para el proximo reinicio (pendiente de reiniciar).'
}

function Get-CSWDiagMemoryTestResults {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Buscando resultados del Diagnostico de memoria de Windows...' -Level Step
    $ev = @(Get-CSWDiagWinEvent @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } 10)
    if (-not $ev.Count) { return (New-CSWResult -Summary 'No hay resultados de pruebas de memoria en este equipo.' -Status Warn) }
    $ev | ForEach-Object {
        [pscustomobject]@{ Fecha = $_.TimeCreated.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture); Id = $_.Id; Resultado = (Get-CSWDiagShortText ([string]$_.Message) 140) }
    }
    $last = $ev[0]
    # 1101/1201 = sin errores; 1102/1202 = errores detectados
    if ($last.Id -eq 1102 -or $last.Id -eq 1202) {
        return (New-CSWResult -Summary ("Ultima prueba de memoria ({0:dd\/MM\/yyyy}): SE DETECTARON ERRORES de hardware en la RAM." -f $last.TimeCreated) -Status Warn)
    }
    New-CSWResult -Summary ("Ultima prueba de memoria ({0:dd\/MM\/yyyy}): sin errores." -f $last.TimeCreated)
}

# ===========================================================================
# Activacion de Windows
# ===========================================================================
function Get-CSWDiagActivation {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Consultando el estado de licencia de Windows...' -Level Step
    $products = @()
    try { $products = @(Get-CSWDiagActivationInfo) }
    catch { Write-CSWLog "SoftwareLicensingProduct no responde: $($_.Exception.Message)" -Level Warn }

    if (-not $products.Count) {
        $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
        $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
        if ((Test-Path $slmgr) -and (Test-Path $cscript)) {
            Write-CSWLog 'Consultando con slmgr /dli...' -Level Info
            [void](Invoke-CSWExternal -FilePath $cscript -Arguments ('//NoLogo "{0}" /dli' -f $slmgr))
        }
        return (New-CSWResult -Summary 'No se pudo determinar la activacion por WMI; revise la salida de slmgr en el registro.' -Status Warn)
    }

    try {
        $svc = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $oa3 = [string](Get-CSWDiagProp $svc 'OA3xOriginalProductKey')
        if ($oa3 -and $oa3.Length -ge 5) {
            Write-CSWLog ("Clave OEM grabada en el firmware: si (termina en {0}). Edicion: {1}" -f $oa3.Substring($oa3.Length - 5), (Get-CSWDiagProp $svc 'OA3xOriginalProductKeyDescription')) -Level Info
        }
        else { Write-CSWLog 'Clave OEM grabada en el firmware: no' -Level Info }
        $kms = [string](Get-CSWDiagProp $svc 'KeyManagementServiceMachine')
        if ($kms) { Write-CSWLog "Servidor KMS configurado: $kms" -Level Info }
    }
    catch { }

    $products | Select-Object Producto, Canal, ClaveParcial, Estado, GraciaDias
    $main = $products | Sort-Object { if ($_.EstadoCodigo -eq 1) { 0 } else { 1 } } | Select-Object -First 1
    $chan = ''; if ($main.Canal) { $chan = " (licencia $($main.Canal))" }
    if ($main.EstadoCodigo -eq 1) {
        if ($main.Canal -match 'Volume:GVLK' -and $main.GraciaDias) {
            return (New-CSWResult -Summary "Windows activado por KMS$chan; renovacion en $($main.GraciaDias) dias.")
        }
        return (New-CSWResult -Summary "Windows esta activado$chan.")
    }
    New-CSWResult -Summary ("Windows NO esta activado: {0}{1}." -f $main.Estado, $chan) -Status Warn
}

# ===========================================================================
# Registro del modulo
# ===========================================================================
Register-CSWModule -Id 'Diagnostics' -Name 'Diagnóstico' -Order 10 -Icon 'diagnostics' `
    -Description 'Inventario, estado de salud y análisis de fallos del equipo' -Actions @(
    @{ Id = 'SystemSummary'; Name = 'Resumen del sistema'; Command = 'Get-CSWDiagSystemSummary'
        Description = 'Fabricante, modelo, N/S, BIOS, Windows, activación, uptime, CPU, RAM, gráfica y disco del sistema.' }
    @{ Id = 'HardwareInventory'; Name = 'Inventario de hardware'; Command = 'Get-CSWDiagHardwareInventory'
        Description = 'Placa base, CPU, módulos RAM y ranuras, discos (SSD/HDD/NVMe), gráfica, red y audio.' }
    @{ Id = 'InstalledSoftware'; Name = 'Software instalado'; Command = 'Get-CSWDiagInstalledSoftware'
        Description = 'Lista los programas instalados (64/32 bits, equipo y usuarios) y la exporta a CSV.'
        Inputs = @(
            @{ Name = 'Filter'; Label = 'Filtrar por nombre o editor (opcional)'; Default = '' },
            @{ Name = 'ExportCsv'; Label = 'Exportar a CSV en Informes'; Type = 'Bool'; Default = $true }
        ) }
    @{ Id = 'ProblemDevices'; Name = 'Drivers con problemas'; Command = 'Get-CSWDiagProblemDevices'
        Description = 'Dispositivos con error en el Administrador de dispositivos (drivers ausentes o fallando).' }
    @{ Id = 'CriticalEvents'; Name = 'Eventos críticos'; Command = 'Get-CSWDiagCriticalEvents'
        Description = 'Errores y eventos críticos de System y Application de los últimos días, agrupados por origen.'
        Inputs = @(@{ Name = 'Days'; Label = 'Días a revisar'; Default = '7' }) }
    @{ Id = 'BsodHistory'; Name = 'Pantallazos azules'; Command = 'Get-CSWDiagBsodHistory'
        Description = 'Historial de BSOD (BugCheck), apagados inesperados (Kernel-Power 41) y volcados de memoria.'
        Inputs = @(@{ Name = 'Days'; Label = 'Días a revisar'; Default = '90' }) }
    @{ Id = 'Performance'; Name = 'Rendimiento actual'; Command = 'Get-CSWDiagPerformance'
        Description = 'Uso de CPU, RAM y disco, y los 10 programas que más CPU y memoria consumen.' }
    @{ Id = 'StartupPrograms'; Name = 'Programas de inicio'; Command = 'Get-CSWDiagStartupPrograms'
        Description = 'Programas que arrancan con Windows (claves Run, carpeta Inicio, tareas al iniciar sesión).' }
    @{ Id = 'MemoryTestResults'; Name = 'Resultado prueba de RAM'; Command = 'Get-CSWDiagMemoryTestResults'
        Description = 'Muestra el resultado de las últimas pruebas del Diagnóstico de memoria de Windows.' }
    @{ Id = 'Activation'; Name = 'Activación de Windows'; Command = 'Get-CSWDiagActivation'
        Description = 'Estado de licencia y activación de Windows, canal de licencia y clave OEM del firmware.' }
)

Export-ModuleMember -Function *
