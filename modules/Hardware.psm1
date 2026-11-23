#Requires -Version 5.1
<#
    Cybersutro win - Modulo Hardware (revision profunda de salud del hardware)

    Organizacion:
      - Funciones internas Get-CSWHw*Findings: recogen datos y devuelven "hallazgos"
        (objetos Componente / Prueba / Valor / Estado / Detalle + Categoria y
        Recomendacion ocultas). No devuelven New-CSWResult.
      - Funciones-accion (Test-CSWHw*, Invoke-CSWHwFullHealthCheck, Start-CSWHwMemoryTest):
        loguean, guardan los hallazgos en el estado compartido, actualizan la seccion
        'HardwareHealth' del informe y terminan con New-CSWResult.

    Estados de un hallazgo: OK, Aviso, Fallo, 'Sin datos' (dato inaccesible: VM, sin
    permisos, controladora RAID/USB que no expone SMART...). 'Sin datos' nunca penaliza.

    Puntuacion global (0-100), pesos por categoria:
      Disco 35, RAM 20, Bateria 15, CPU/termico 15, GPU 5, Perifericos 10.
      Fallo en una categoria resta todo su peso; Aviso resta la mitad.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Constantes y umbrales (documentados)
# ---------------------------------------------------------------------------
$script:HwEventDays = 30            # ventana de eventos analizada

# Discos
$script:HwDiskTempWarn     = 60     # C: a partir de aqui el disco trabaja caliente (Aviso)
$script:HwDiskWearWarn     = 70     # % de vida consumida (SSD) -> Aviso
$script:HwDiskWearFail     = 90     # % de vida consumida (SSD) -> Fallo (fin de vida cercano)
$script:HwDiskHddHoursWarn = 35000  # horas de uso de un HDD (~4 anos 24/7) -> Aviso por antiguedad
$script:HwDiskReallocFail  = 50     # sectores reasignados que por si solos indican degradacion seria

# RAM
$script:HwRamUseWarn       = 90     # % memoria fisica en uso -> Aviso
$script:HwRamCommitWarn    = 90     # % del limite de compromiso en uso -> Aviso
$script:HwPagefileWarn     = 80     # % de uso del archivo de paginacion -> Aviso
$script:HwHardFaultWarn    = 500    # paginas leidas de disco por segundo (media) -> Aviso (presion de memoria)
$script:HwRamMinGB         = 4      # menos de 4 GB es insuficiente para Windows 10/11 -> Aviso

# Bateria (desgaste = 1 - capacidad_completa / capacidad_de_diseno)
$script:HwBattWearWarn     = 20     # 20-40 % -> Aviso
$script:HwBattWearFail     = 40     # > 40 % -> Fallo (recomendar reemplazo)
$script:HwBattCyclesWarn   = 800    # ciclos altos para la mayoria de baterias de portatil

# CPU / termico
$script:HwCpuTempWarn      = 80     # C en zona termica ACPI -> Aviso
$script:HwCpuTempFail      = 90     # C en zona termica ACPI -> Fallo
$script:HwCpuLoadWarn      = 90     # % de carga media sostenida en las muestras -> Aviso
$script:HwKp41Warn         = 1      # apagados inesperados en 30 dias -> Aviso
$script:HwKp41Fail         = 5      # apagados inesperados en 30 dias -> Fallo (fuente/termico/hardware)

# GPU
$script:HwGpuDriverAgeDays = 730    # driver con mas de 2 anos -> Aviso
$script:HwTdrFail          = 5      # reinicios del driver de video en 30 dias -> Fallo (1-4 = Aviso)

# Categorias para la puntuacion
$script:HwCategories = @(
    [pscustomobject]@{ Key = 'Disco';       Label = 'Discos';        Weight = 35 },
    [pscustomobject]@{ Key = 'RAM';         Label = 'Memoria RAM';   Weight = 20 },
    [pscustomobject]@{ Key = 'Bateria';     Label = 'Bateria';       Weight = 15 },
    [pscustomobject]@{ Key = 'CPU';         Label = 'CPU / termico'; Weight = 15 },
    [pscustomobject]@{ Key = 'GPU';         Label = 'Graficos';      Weight = 5 },
    [pscustomobject]@{ Key = 'Perifericos'; Label = 'Perifericos';   Weight = 10 }
)

# Recomendaciones por defecto si un hallazgo no trae una concreta
$script:HwDefaultRec = @{
    'Disco|Fallo'       = 'Respaldar los datos de inmediato y reemplazar el disco.'
    'Disco|Aviso'       = 'Vigilar el disco y mantener copias de seguridad al dia.'
    'RAM|Fallo'         = 'Reemplazar el modulo de memoria defectuoso.'
    'RAM|Aviso'         = 'Revisar la memoria RAM y su configuracion.'
    'Bateria|Fallo'     = 'Reemplazar la bateria.'
    'Bateria|Aviso'     = 'La bateria muestra desgaste: planificar su reemplazo.'
    'CPU|Fallo'         = 'Revisar refrigeracion, pasta termica y fuente de alimentacion.'
    'CPU|Aviso'         = 'Limpiar el polvo de ventiladores y revisar la temperatura.'
    'GPU|Fallo'         = 'Reinstalar el driver de video y revisar la tarjeta grafica.'
    'GPU|Aviso'         = 'Actualizar el driver de video desde el fabricante.'
    'Perifericos|Fallo' = 'Reinstalar el driver o revisar el dispositivo afectado.'
    'Perifericos|Aviso' = 'Revisar el dispositivo y su driver en el Administrador de dispositivos.'
}

# Codigos de error de ConfigManager (Administrador de dispositivos)
$script:HwCmErrors = @{
    1  = 'Dispositivo mal configurado'
    3  = 'Driver danado o memoria insuficiente'
    10 = 'El dispositivo no puede iniciarse'
    12 = 'Recursos insuficientes (conflicto de recursos)'
    14 = 'Requiere reiniciar el equipo'
    18 = 'Hay que reinstalar el driver'
    19 = 'Configuracion del registro danada'
    21 = 'Windows esta quitando el dispositivo'
    22 = 'Dispositivo deshabilitado'
    24 = 'Dispositivo no presente o sin driver completo'
    28 = 'Driver no instalado'
    29 = 'Deshabilitado por el firmware'
    31 = 'El driver no se pudo cargar correctamente'
    32 = 'Servicio del driver deshabilitado'
    37 = 'El driver devolvio un error al iniciar'
    39 = 'Driver danado o ausente'
    41 = 'El driver se cargo pero no encuentra el hardware'
    43 = 'Windows detuvo el dispositivo porque informo problemas'
    45 = 'Dispositivo no conectado actualmente'
    48 = 'Driver bloqueado por incompatibilidad'
    52 = 'Driver sin firma digital valida'
}

# Eventos de disco relevantes (proveedor -> id -> descripcion)
$script:HwDiskEventInfo = @{
    'disk|7'      = 'Bloque defectuoso'
    'disk|51'     = 'Error durante una operacion de paginacion'
    'disk|153'    = 'Operacion de E/S reintentada'
    'ntfs|55'     = 'Estructura del sistema de archivos danada'
    'ntfs|98'     = 'Volumen con errores (requiere chkdsk)'
    'ntfs|137'    = 'Error del administrador de recursos transaccional'
    'storahci|129' = 'Reinicio de la controladora SATA'
    'stornvme|129' = 'Reinicio de la controladora NVMe'
    'iastora|129'  = 'Reinicio de la controladora Intel RST'
    'iastorac|129' = 'Reinicio de la controladora Intel RST'
    'iastoravc|129' = 'Reinicio de la controladora Intel RST'
}

# ===========================================================================
# Utilidades internas
# ===========================================================================
function Get-CSWHwProp {
    # Lectura segura de propiedades (StrictMode 2.0 lanza error si no existen)
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function ConvertTo-CSWHwNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    $d = 0.0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    try { return [double]$Value } catch { return $null }
}

function Get-CSWHwShortText {
    param([string]$Text, [int]$Max = 140)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function New-CSWHwFinding {
    param(
        [Parameter(Mandatory)][string]$Categoria,
        [Parameter(Mandatory)][string]$Componente,
        [Parameter(Mandatory)][string]$Prueba,
        [AllowEmptyString()][string]$Valor = '',
        [ValidateSet('OK', 'Aviso', 'Fallo', 'Sin datos')][string]$Estado = 'OK',
        [AllowEmptyString()][string]$Detalle = '',
        [AllowEmptyString()][string]$Recomendacion = '',
        [switch]$Summary
    )
    if (-not $Recomendacion -and ($Estado -eq 'Fallo' -or $Estado -eq 'Aviso')) {
        $k = "$Categoria|$Estado"
        if ($script:HwDefaultRec.ContainsKey($k)) { $Recomendacion = $script:HwDefaultRec[$k] }
    }
    $o = [pscustomobject]@{
        Componente    = $Componente
        Prueba        = $Prueba
        Valor         = $Valor
        Estado        = $Estado
        Detalle       = $Detalle
        Categoria     = $Categoria
        Recomendacion = $Recomendacion
        EsVeredicto   = [bool]$Summary
    }
    # En la tabla del log solo se muestran las 5 columnas principales
    $set = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]@('Componente', 'Prueba', 'Valor', 'Estado', 'Detalle'))
    $o | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($set)) -Force
    return $o
}

function Get-CSWHwWorst {
    # Peor estado de una lista de hallazgos: Fallo > Aviso > OK > Sin datos
    param($Findings)
    $list = @($Findings | Where-Object { $null -ne $_ })
    if (@($list | Where-Object { $_.Estado -eq 'Fallo' }).Count) { return 'Fallo' }
    if (@($list | Where-Object { $_.Estado -eq 'Aviso' }).Count) { return 'Aviso' }
    if (@($list | Where-Object { $_.Estado -eq 'OK' }).Count) { return 'OK' }
    return 'Sin datos'
}

function Get-CSWHwCim {
    # Get-CimInstance tolerante: devuelve @() si la clase no existe o no hay permisos
    param([Parameter(Mandatory)][string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter)
    try {
        if ($Filter) { return @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $Filter -ErrorAction Stop) }
        return @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop)
    }
    catch { return @() }
}

function Get-CSWHwEvents {
    <#
        Get-WinEvent tolerante. Devuelve objeto { Ok; Events; Error }.
        'Sin eventos' y 'proveedor inexistente' no son errores (Ok = $true, Events vacio).
    #>
    param([Parameter(Mandatory)][hashtable]$Filter, [int]$Days = 30, [int]$Max = 500)
    $f = @{}
    foreach ($k in $Filter.Keys) { $f[$k] = $Filter[$k] }
    if ($Days -gt 0) { $f['StartTime'] = (Get-Date).AddDays(-$Days) }
    $r = [pscustomobject]@{ Ok = $true; Events = @(); Error = '' }
    try { $r.Events = @(Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatching*') { $r.Ok = $false; $r.Error = $_.Exception.Message }
    }
    return $r
}

function Get-CSWHwEventText {
    param($EventRecord)
    $t = ''
    try { $t = [string]$EventRecord.Message } catch { $t = '' }
    if (-not $t) {
        try { $t = (@($EventRecord.Properties) | ForEach-Object { [string]$_.Value }) -join ' ' } catch { $t = '' }
    }
    return $t
}

function Format-CSWHwSize {
    param($Bytes)
    $b = ConvertTo-CSWHwNumber $Bytes
    if ($null -eq $b -or $b -le 0) { return '?' }
    if ($b -ge 1TB) { return ('{0:N1} TB' -f ($b / 1TB)) }
    if ($b -ge 1GB) { return ('{0:N0} GB' -f ($b / 1GB)) }
    return ('{0:N0} MB' -f ($b / 1MB))
}

function Get-CSWHwStore {
    # Almacen de hallazgos por chequeo en el estado compartido (GUI y runspace lo comparten)
    $s = Get-CSWState
    if (-not $s.ContainsKey('HwFindings')) { $s.HwFindings = [hashtable]::Synchronized(@{}) }
    return $s.HwFindings
}

function Save-CSWHwFindings {
    param([Parameter(Mandatory)][string]$Check, $Findings)
    $store = Get-CSWHwStore
    $store[$Check] = @($Findings)
}

# ===========================================================================
# SMART: parsing de atributos crudos e historial
# ===========================================================================
function ConvertFrom-CSWHwSmartData {
    <#
        VendorSpecific de MSStorageDriver_FailurePredictData (512 bytes):
        2 bytes de version y luego hasta 30 bloques de 12 bytes:
          [0] id  [1-2] flags  [3] valor normalizado  [4] peor  [5-10] raw (6 bytes LE)  [11] reservado
    #>
    param($Bytes)
    $attrs = @{}
    if ($null -eq $Bytes) { return $attrs }
    $b = [byte[]]@($Bytes)
    if ($b.Length -lt 14) { return $attrs }
    for ($off = 2; ($off + 12) -le $b.Length -and $off -lt 362; $off += 12) {
        $id = [int]$b[$off]
        if ($id -eq 0 -or $attrs.ContainsKey($id)) { continue }
        $raw32 = [uint64]0
        for ($i = 3; $i -ge 0; $i--) { $raw32 = ($raw32 * 256) + [uint64]$b[$off + 5 + $i] }
        $attrs[$id] = [pscustomobject]@{
            Id      = $id
            Current = [int]$b[$off + 3]
            Worst   = [int]$b[$off + 4]
            Raw8    = [int]$b[$off + 5]
            Raw16   = ([int]$b[$off + 5] + 256 * [int]$b[$off + 6])
            Raw32   = $raw32
        }
    }
    return $attrs
}

function Get-CSWHwInstKey {
    # Normaliza InstanceName de root\wmi / PNPDeviceID para poder compararlos
    param([string]$Name)
    if (-not $Name) { return '' }
    return (($Name.ToUpperInvariant()) -replace '_\d+$', '')
}

function Get-CSWHwSmartHistoryPath { return (Join-Path (Get-CSWDataPath Root) 'HardwareSmartHistory.json') }

function Get-CSWHwSmartHistory {
    $h = @{}
    $p = Get-CSWHwSmartHistoryPath
    if (-not (Test-Path $p)) { return $h }
    try {
        $j = Get-Content -Path $p -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($prop in $j.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
    }
    catch { }
    return $h
}

function Save-CSWHwSmartHistory {
    param([hashtable]$History)
    try {
        $o = New-Object PSObject
        foreach ($k in $History.Keys) { $o | Add-Member -MemberType NoteProperty -Name $k -Value $History[$k] -Force }
        $o | ConvertTo-Json -Depth 4 | Set-Content -Path (Get-CSWHwSmartHistoryPath) -Encoding UTF8 -ErrorAction Stop
    }
    catch { }
}

# ===========================================================================
# 1. Discos
# ===========================================================================
function Get-CSWHwDiskEvents {
    # Eventos de error de disco/sistema de archivos/controladora en los ultimos N dias
    $r = Get-CSWHwEvents -Filter @{ LogName = 'System'; Id = @(7, 51, 153, 55, 98, 137, 129); Level = @(1, 2, 3) } -Days $script:HwEventDays -Max 1000
    $list = New-Object System.Collections.ArrayList
    foreach ($e in $r.Events) {
        $prov = ([string]$e.ProviderName).ToLowerInvariant() -replace '^microsoft-windows-', ''
        $key = "$prov|$($e.Id)"
        if (-not $script:HwDiskEventInfo.ContainsKey($key)) { continue }
        $txt = Get-CSWHwEventText $e
        $disk = $null
        if ($txt -match 'Harddisk(\d+)') { $disk = $Matches[1] }
        [void]$list.Add([pscustomobject]@{ Time = $e.TimeCreated; Provider = $prov; Id = [int]$e.Id; Desc = $script:HwDiskEventInfo[$key]; Disk = $disk })
    }
    return [pscustomobject]@{ Ok = $r.Ok; Error = $r.Error; Events = @($list) }
}

function Format-CSWHwEventGroup {
    param($Events)
    $g = @($Events | Group-Object Desc | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
    return ($g -join '; ')
}

function Get-CSWHwDiskFindings {
    [CmdletBinding()]
    param()
    $cat = 'Disco'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando discos fisicos (estado, contadores de fiabilidad, SMART y eventos)...' -Level Step

    $disks = @()
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object { $n = 0; [void][int]::TryParse([string](Get-CSWHwProp $_ 'DeviceId'), [ref]$n); $n })
    }
    catch { Write-CSWLog "No se pudo consultar Get-PhysicalDisk: $($_.Exception.Message)" -Level Warn }

    # Win32_DiskDrive: indice -> PNPDeviceID (para enlazar con root\wmi)
    $pnpByIndex = @{}
    foreach ($dd in (Get-CSWHwCim -ClassName Win32_DiskDrive)) {
        $pnpByIndex[[string](Get-CSWHwProp $dd 'Index')] = [string](Get-CSWHwProp $dd 'PNPDeviceID')
    }

    # SMART de root\wmi (requiere administrador; las controladoras RAID/USB/NVMe no suelen exponerlo)
    $predict = @{}; $smart = @{}; $smartErr = ''
    try {
        foreach ($p in @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)) {
            $predict[(Get-CSWHwInstKey ([string](Get-CSWHwProp $p 'InstanceName')))] = $p
        }
        foreach ($p in @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictData -ErrorAction Stop)) {
            $smart[(Get-CSWHwInstKey ([string](Get-CSWHwProp $p 'InstanceName')))] = ConvertFrom-CSWHwSmartData (Get-CSWHwProp $p 'VendorSpecific')
        }
    }
    catch { $smartErr = $_.Exception.Message }
    $isAdmin = Test-CSWAdmin
    $noSmartReason = 'La controladora (RAID/USB/NVMe) o la VM no expone SMART por WMI'
    if (-not $isAdmin) { $noSmartReason = 'Se requieren permisos de administrador para leer SMART' }

    $diskEv = Get-CSWHwDiskEvents
    $history = Get-CSWHwSmartHistory
    $historyChanged = $false

    if (-not $disks.Count) {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Discos' -Prueba 'Discos fisicos' -Valor 'No detectados' -Estado 'Sin datos' -Detalle 'Get-PhysicalDisk no devolvio discos (VM o servicio de almacenamiento no disponible)'))
    }

    foreach ($d in $disks) {
        $num = [string](Get-CSWHwProp $d 'DeviceId')
        $name = ([string](Get-CSWHwProp $d 'FriendlyName')).Trim()
        $comp = "Disco $num ($name)"
        $bus = [string](Get-CSWHwProp $d 'BusType')
        $media = [string](Get-CSWHwProp $d 'MediaType')
        $isNvme = ($bus -eq 'NVMe')
        $isSsd = ($media -eq 'SSD' -or $isNvme)
        $serial = ([string](Get-CSWHwProp $d 'SerialNumber')).Trim()
        $fw = ([string](Get-CSWHwProp $d 'FirmwareVersion')).Trim()
        $diskRows = New-Object System.Collections.ArrayList

        [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Identificacion' -Valor ("{0} {1} {2}" -f $media, $bus, (Format-CSWHwSize (Get-CSWHwProp $d 'Size'))) -Estado 'OK' -Detalle ("N/S {0}; firmware {1}" -f $serial, $fw)))

        # Estado general reportado por Windows
        $hs = [string](Get-CSWHwProp $d 'HealthStatus')
        $ops = (@(Get-CSWHwProp $d 'OperationalStatus') | ForEach-Object { [string]$_ }) -join ', '
        if ($hs -eq 'Healthy') {
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Estado de Windows' -Valor 'Correcto' -Estado 'OK' -Detalle "Estado operativo: $ops"))
        }
        elseif (-not $hs -or $hs -eq 'Unknown') {
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Estado de Windows' -Valor 'Desconocido' -Estado 'Sin datos' -Detalle "Estado operativo: $ops"))
        }
        else {
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Estado de Windows' -Valor $hs -Estado 'Fallo' -Detalle "Estado operativo: $ops" -Recomendacion 'Windows marca el disco como no saludable: respaldar los datos de inmediato y reemplazar el disco.'))
        }

        # Contadores de fiabilidad (Get-StorageReliabilityCounter; requiere admin)
        $rc = $null; $rcErr = ''
        try { $rc = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction Stop } catch { $rcErr = $_.Exception.Message }

        # SMART crudo asociado a este disco
        $key = ''
        if ($pnpByIndex.ContainsKey($num)) { $key = Get-CSWHwInstKey $pnpByIndex[$num] }
        $ps = $null; $attrs = $null
        if ($key -and $predict.ContainsKey($key)) { $ps = $predict[$key] }
        if ($key -and $smart.ContainsKey($key)) { $attrs = $smart[$key] }

        # Prediccion de fallo SMART
        if ($null -ne $ps) {
            if ([bool](Get-CSWHwProp $ps 'PredictFailure')) {
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Prediccion de fallo SMART' -Valor 'FALLO INMINENTE' -Estado 'Fallo' -Detalle ("Motivo SMART: {0}" -f (Get-CSWHwProp $ps 'Reason')) -Recomendacion 'El disco predice su propio fallo: respaldar los datos de inmediato y reemplazar el disco.'))
            }
            else {
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Prediccion de fallo SMART' -Valor 'Sin prediccion de fallo' -Estado 'OK'))
            }
        }
        elseif (-not $isNvme) {
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Prediccion de fallo SMART' -Valor 'No disponible' -Estado 'Sin datos' -Detalle $noSmartReason))
        }

        # Temperatura (contador de fiabilidad o atributo SMART 194/190)
        $temp = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'Temperature')
        $tmax = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'TemperatureMax')
        if (($null -eq $temp -or $temp -le 0) -and $null -ne $attrs) {
            foreach ($tid in 194, 190) {
                if ($attrs.ContainsKey($tid)) { $t = $attrs[$tid].Raw8; if ($t -gt 0 -and $t -lt 100) { $temp = [double]$t; break } }
            }
        }
        if ($null -ne $temp -and $temp -gt 0 -and $temp -lt 120) {
            $det = ''
            if ($null -ne $tmax -and $tmax -gt 0) { $det = "Limite/maximo reportado: $tmax C" }
            if ($temp -ge $script:HwDiskTempWarn) {
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Temperatura' -Valor "$temp C" -Estado 'Aviso' -Detalle $det -Recomendacion 'El disco trabaja caliente: mejorar la ventilacion del equipo (o instalar disipador en el SSD NVMe).'))
            }
            else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Temperatura' -Valor "$temp C" -Estado 'OK' -Detalle $det)) }
        }
        else {
            $why = $noSmartReason
            if ($rcErr -and $isAdmin) { $why = Get-CSWHwShortText $rcErr 100 }
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Temperatura' -Valor 'No disponible' -Estado 'Sin datos' -Detalle $why))
        }

        # Desgaste (solo SSD): % de vida consumida
        $wear = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'Wear')
        if ($isSsd) {
            if ($null -ne $wear -and $null -ne $rc) {
                $st = 'OK'; $rec = ''
                if ($wear -ge $script:HwDiskWearFail) { $st = 'Fallo'; $rec = 'El SSD esta al final de su vida util: respaldar los datos y reemplazarlo.' }
                elseif ($wear -ge $script:HwDiskWearWarn) { $st = 'Aviso'; $rec = 'El SSD ha consumido gran parte de su vida util: planificar su reemplazo.' }
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste del SSD' -Valor "$wear %" -Estado $st -Detalle ('Vida restante estimada: {0} %' -f (100 - $wear)) -Recomendacion $rec))
            }
            else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste del SSD' -Valor 'No disponible' -Estado 'Sin datos' -Detalle $noSmartReason)) }
        }

        # Horas de encendido y ciclos
        $poh = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'PowerOnHours')
        if (($null -eq $poh -or $poh -le 0) -and $null -ne $attrs -and $attrs.ContainsKey(9)) { $poh = [double]$attrs[9].Raw32 }
        $ssc = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'StartStopCycleCount')
        if ($null -ne $poh -and $poh -gt 0) {
            $det = ('~{0:N1} anos de uso continuo' -f ($poh / 8760))
            if ($null -ne $ssc -and $ssc -gt 0) { $det += "; ciclos de arranque/parada: $ssc" }
            if (-not $isSsd -and $poh -ge $script:HwDiskHddHoursWarn) {
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Horas de encendido' -Valor ('{0:N0} h' -f $poh) -Estado 'Aviso' -Detalle $det -Recomendacion 'Disco mecanico con muchas horas de uso: considerar migrar a un SSD nuevo.'))
            }
            else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Horas de encendido' -Valor ('{0:N0} h' -f $poh) -Estado 'OK' -Detalle $det)) }
        }

        # Errores de lectura/escritura no corregidos
        if ($null -ne $rc) {
            $ru = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'ReadErrorsUncorrected')
            $wu = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'WriteErrorsUncorrected')
            $rt = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'ReadErrorsTotal')
            $wt = ConvertTo-CSWHwNumber (Get-CSWHwProp $rc 'WriteErrorsTotal')
            if ($null -ne $ru -or $null -ne $wu) {
                $unc = 0; if ($null -ne $ru) { $unc += $ru }; if ($null -ne $wu) { $unc += $wu }
                $det = "Lectura no corregidos: $ru; escritura no corregidos: $wu; totales (incl. corregidos) L:$rt E:$wt"
                if ($unc -gt 0) {
                    [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Errores no corregidos' -Valor "$unc" -Estado 'Fallo' -Detalle $det -Recomendacion 'El disco tiene errores de lectura/escritura no recuperables: respaldar los datos de inmediato y reemplazar el disco.'))
                }
                else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Errores no corregidos' -Valor '0' -Estado 'OK' -Detalle $det)) }
            }
        }

        # Atributos SMART crudos (SATA/ATA)
        if ($null -ne $attrs -and $attrs.Count) {
            $hkey = $serial; if (-not $hkey) { $hkey = "$name#$num" }
            $prev = $null; if ($history.ContainsKey($hkey)) { $prev = $history[$hkey] }

            # 5 - Sectores reasignados (fallo si crecen respecto a la revision anterior)
            if ($attrs.ContainsKey(5)) {
                $v = [double]$attrs[5].Raw32
                $pv = ConvertTo-CSWHwNumber (Get-CSWHwProp $prev 'Reallocated')
                $st = 'OK'; $det = 'Atributo SMART 5'; $rec = ''
                if ($v -gt 0) {
                    if ($null -ne $pv -and $v -gt $pv) { $st = 'Fallo'; $det = "Aumentaron desde $pv (revision anterior)" }
                    elseif ($v -ge $script:HwDiskReallocFail) { $st = 'Fallo'; $det = "Cantidad elevada (umbral $($script:HwDiskReallocFail))" }
                    elseif ($null -ne $pv) { $st = 'Aviso'; $det = 'Estables desde la revision anterior' }
                    else { $st = 'Aviso'; $det = 'Primera revision: no se puede saber si estan creciendo' }
                    if ($st -eq 'Fallo') { $rec = 'La superficie del disco se esta degradando: respaldar los datos de inmediato y reemplazar el disco.' }
                    else { $rec = 'Hay sectores reasignados: repetir la revision en unas semanas y mantener copias de seguridad.' }
                }
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Sectores reasignados' -Valor ([string]$v) -Estado $st -Detalle $det -Recomendacion $rec))
            }
            # 187 / 197 / 198: cualquier valor > 0 es fallo
            $crit = @(
                @{ Id = 187; Name = 'Errores no corregibles reportados'; Raw = 'Raw16' },
                @{ Id = 197; Name = 'Sectores pendientes'; Raw = 'Raw32' },
                @{ Id = 198; Name = 'Sectores no corregibles offline'; Raw = 'Raw32' }
            )
            foreach ($c in $crit) {
                if (-not $attrs.ContainsKey($c.Id)) { continue }
                $v = [double]$attrs[$c.Id].($c.Raw)
                if ($v -gt 0) {
                    [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba $c.Name -Valor ([string]$v) -Estado 'Fallo' -Detalle "Atributo SMART $($c.Id)" -Recomendacion 'El disco tiene sectores ilegibles: respaldar los datos de inmediato y reemplazar el disco.'))
                }
                else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba $c.Name -Valor '0' -Estado 'OK' -Detalle "Atributo SMART $($c.Id)")) }
            }
            $pend = $null; if ($attrs.ContainsKey(197)) { $pend = $attrs[197].Raw32 }
            $realloc = $null; if ($attrs.ContainsKey(5)) { $realloc = $attrs[5].Raw32 }
            $history[$hkey] = [pscustomobject]@{ Reallocated = $realloc; Pending = $pend; Date = (Get-Date).ToString('s'); Model = $name }
            $historyChanged = $true
        }
        elseif (-not $isNvme) {
            [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Atributos SMART (5/187/197/198)' -Valor 'No disponibles' -Estado 'Sin datos' -Detalle $noSmartReason))
        }

        # Eventos de error atribuibles a este disco
        if ($diskEv.Ok) {
            $mine = @($diskEv.Events | Where-Object { $_.Disk -eq $num })
            if ($mine.Count) {
                [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba "Eventos de error ($($script:HwEventDays) dias)" -Valor "$($mine.Count)" -Estado 'Aviso' -Detalle (Format-CSWHwEventGroup $mine) -Recomendacion 'Windows registro errores de este disco: revisar cable/conexion, ejecutar chkdsk y mantener copias de seguridad.'))
            }
            else { [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba "Eventos de error ($($script:HwEventDays) dias)" -Valor '0' -Estado 'OK')) }
        }

        # Veredicto del disco
        $v = Get-CSWHwWorst $diskRows
        $vt = switch ($v) { 'Fallo' { 'Disco con fallo: reemplazar' } 'Aviso' { 'Disco con observaciones' } 'OK' { 'Disco en buen estado' } default { 'No se pudo evaluar' } }
        $rec = ''
        if ($v -eq 'Fallo') { $rec = 'Reemplazar el disco y respaldar los datos de inmediato.' }
        [void]$diskRows.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Veredicto' -Valor $vt -Estado $v -Recomendacion $rec -Summary))
        foreach ($r in $diskRows) { [void]$out.Add($r) }
    }

    # Eventos no atribuibles a un disco concreto (controladora, NTFS...)
    if ($diskEv.Ok) {
        $known = @($disks | ForEach-Object { [string](Get-CSWHwProp $_ 'DeviceId') })
        $other = @($diskEv.Events | Where-Object { $null -eq $_.Disk -or ($known -notcontains $_.Disk) })
        if ($other.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Sistema de discos' -Prueba "Eventos de disco/NTFS/controladora ($($script:HwEventDays) dias)" -Valor "$($other.Count)" -Estado 'Aviso' -Detalle (Format-CSWHwEventGroup $other) -Recomendacion 'Revisar cables SATA/conexion del SSD, actualizar el driver de la controladora y ejecutar chkdsk.'))
        }
        else {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Sistema de discos' -Prueba "Eventos de disco/NTFS/controladora ($($script:HwEventDays) dias)" -Valor '0' -Estado 'OK'))
        }
    }
    else {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Sistema de discos' -Prueba 'Eventos de disco' -Valor 'No disponible' -Estado 'Sin datos' -Detalle (Get-CSWHwShortText $diskEv.Error 120)))
    }

    if ($historyChanged) { Save-CSWHwSmartHistory $history }
    if ($smartErr -and $isAdmin) { Write-CSWLog "SMART por WMI no disponible: $(Get-CSWHwShortText $smartErr 120)" -Level Info }
    return @($out)
}

# ===========================================================================
# 2. RAM
# ===========================================================================
function Get-CSWHwMemoryTypeName {
    param($Module)
    $smb = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $Module 'SMBIOSMemoryType'))
    $map = @{ 18 = 'DDR'; 19 = 'DDR2'; 20 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
    if ($map.ContainsKey($smb)) { return $map[$smb] }
    $mt = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $Module 'MemoryType'))
    $map2 = @{ 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4' }
    if ($map2.ContainsKey($mt)) { return $map2[$mt] }
    return 'Desconocido'
}

function Get-CSWHwWheaEvents {
    <#
        Eventos WHEA-Logger de los ultimos N dias clasificados:
          Fatal: ids 1, 18, 20, 46 ; Corregible: 17, 19, 47 (y otros)
          Categoria: 47/46 -> Memoria ; 17 -> Bus ; 1/18/19/20 segun el texto (memoria, PCI) o Memoria por defecto
    #>
    $r = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger' } -Days $script:HwEventDays -Max 500
    $list = New-Object System.Collections.ArrayList
    foreach ($e in $r.Events) {
        $id = [int]$e.Id
        $fatal = (@(1, 18, 20, 46) -contains $id)
        $txt = Get-CSWHwEventText $e
        $catg = 'Memoria'
        if ($id -eq 47 -or $id -eq 46) { $catg = 'Memoria' }
        elseif ($id -eq 17 -or $txt -match 'PCI') { $catg = 'Bus' }
        elseif ($txt -match 'Memor') { $catg = 'Memoria' }
        elseif ($txt -match 'Processor|Procesador|Cache|Bus/Interconnect|Interconexion') { $catg = 'Procesador' }
        [void]$list.Add([pscustomobject]@{ Time = $e.TimeCreated; Id = $id; Fatal = $fatal; Category = $catg })
    }
    return [pscustomobject]@{ Ok = $r.Ok; Error = $r.Error; Events = @($list) }
}

function Get-CSWHwRamFindings {
    [CmdletBinding()]
    param()
    $cat = 'RAM'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando memoria RAM (modulos, configuracion, uso, pruebas y errores WHEA)...' -Level Step

    $mods = @(Get-CSWHwCim -ClassName Win32_PhysicalMemory)
    $arrays = @(Get-CSWHwCim -ClassName Win32_PhysicalMemoryArray)
    $sysArr = @($arrays | Where-Object { [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'Use')) -eq 3 })
    if (-not $sysArr.Count) { $sysArr = $arrays }

    if (-not $mods.Count) {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Modulos' -Valor 'No detectados' -Estado 'Sin datos' -Detalle 'El firmware no informa los modulos (habitual en maquinas virtuales)'))
    }

    $caps = @(); $speeds = @(); $types = @(); $banks = @()
    foreach ($m in $mods) {
        $loc = ([string](Get-CSWHwProp $m 'DeviceLocator')).Trim()
        $bank = ([string](Get-CSWHwProp $m 'BankLabel')).Trim()
        $capB = ConvertTo-CSWHwNumber (Get-CSWHwProp $m 'Capacity')
        $nom = ConvertTo-CSWHwNumber (Get-CSWHwProp $m 'Speed')
        $cfg = ConvertTo-CSWHwNumber (Get-CSWHwProp $m 'ConfiguredClockSpeed')
        $type = Get-CSWHwMemoryTypeName $m
        $manu = ([string](Get-CSWHwProp $m 'Manufacturer')).Trim()
        $pn = ([string](Get-CSWHwProp $m 'PartNumber')).Trim()
        $caps += $capB; $speeds += $nom; $types += $type; $banks += "$bank $loc"
        $spd = ''
        if ($null -ne $cfg -and $cfg -gt 0) { $spd = "$cfg MT/s" }
        if ($null -ne $nom -and $nom -gt 0) { if ($spd) { $spd += " (nominal $nom)" } else { $spd = "nominal $nom MT/s" } }
        $det = "Fabricante: $manu; P/N: $pn; banco: $bank"
        if ($null -ne $cfg -and $null -ne $nom -and $cfg -gt 0 -and $nom -gt 0 -and $cfg -lt ($nom * 0.9)) {
            $det += '; funciona por debajo de su velocidad nominal (perfil XMP/EXPO desactivado o limite de la placa/CPU)'
        }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente (("RAM {0} {1}" -f $loc, $bank).Trim()) -Prueba 'Modulo' -Valor ("{0} {1} {2}" -f (Format-CSWHwSize $capB), $type, $spd) -Estado 'OK' -Detalle $det))
    }

    # Ranuras
    $slots = 0; foreach ($a in $sysArr) { $n = ConvertTo-CSWHwNumber (Get-CSWHwProp $a 'MemoryDevices'); if ($null -ne $n) { $slots += [int]$n } }
    $maxKB = 0.0; foreach ($a in $sysArr) {
        $mx = ConvertTo-CSWHwNumber (Get-CSWHwProp $a 'MaxCapacityEx'); if ($null -eq $mx -or $mx -le 0) { $mx = ConvertTo-CSWHwNumber (Get-CSWHwProp $a 'MaxCapacity') }
        if ($null -ne $mx) { $maxKB += $mx }
    }
    $totalB = 0.0; foreach ($c in $caps) { if ($null -ne $c) { $totalB += $c } }
    if ($mods.Count) {
        $det = ''
        if ($maxKB -gt 0) { $det = 'Maximo soportado por la placa: ' + (Format-CSWHwSize ($maxKB * 1KB)) }
        $sv = "$($mods.Count) de $slots ocupadas"
        if ($slots -le 0) { $sv = "$($mods.Count) modulo(s); ranuras totales desconocidas" }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Ranuras' -Valor $sv -Estado 'OK' -Detalle $det))

        # Capacidad total
        $gb = $totalB / 1GB
        if ($gb -lt $script:HwRamMinGB) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Capacidad total' -Valor (Format-CSWHwSize $totalB) -Estado 'Aviso' -Detalle 'Insuficiente para Windows 10/11' -Recomendacion 'Ampliar la memoria RAM a 8 GB o mas.'))
        }
        elseif ($gb -lt 8) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Capacidad total' -Valor (Format-CSWHwSize $totalB) -Estado 'OK' -Detalle 'Justa para uso actual; se recomiendan 8 GB o mas'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Capacidad total' -Valor (Format-CSWHwSize $totalB) -Estado 'OK')) }

        # Doble canal probable
        $bankText = ($banks -join ' ').ToUpperInvariant()
        $dual = ''
        if ($mods.Count -eq 1) { $dual = 'Canal simple (un solo modulo)' }
        elseif ($bankText -match 'CHANNEL\s*A' -and $bankText -match 'CHANNEL\s*B') { $dual = 'Doble canal (modulos en canales A y B)' }
        elseif ($mods.Count % 2 -eq 0 -and @($caps | Select-Object -Unique).Count -eq 1) { $dual = 'Doble canal probable (modulos pares e iguales)' }
        else { $dual = 'Indeterminado (configuracion asimetrica)' }
        $det = ''
        if ($mods.Count -eq 1 -and $slots -gt 1) { $det = 'Anadir un segundo modulo igual duplicaria el ancho de banda de memoria' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Modo de canal' -Valor $dual -Estado 'OK' -Detalle $det))

        # Mezcla de modulos distintos
        $uSpeeds = @($speeds | Where-Object { $null -ne $_ -and $_ -gt 0 } | Select-Object -Unique)
        $uCaps = @($caps | Where-Object { $null -ne $_ } | Select-Object -Unique)
        $uTypes = @($types | Select-Object -Unique)
        if ($mods.Count -gt 1 -and ($uSpeeds.Count -gt 1 -or $uCaps.Count -gt 1 -or $uTypes.Count -gt 1)) {
            $det = 'Velocidades: ' + (($uSpeeds | ForEach-Object { "$_" }) -join '/') + '; capacidades: ' + (($uCaps | ForEach-Object { Format-CSWHwSize $_ }) -join '/')
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Modulos mezclados' -Valor 'Si' -Estado 'Aviso' -Detalle $det -Recomendacion 'Hay modulos de distinta velocidad o capacidad: usar pares identicos para evitar inestabilidad y perder doble canal.'))
        }
        elseif ($mods.Count -gt 1) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Modulos mezclados' -Valor 'No' -Estado 'OK' -Detalle 'Todos los modulos son iguales en velocidad y capacidad'))
        }
    }

    # Uso actual y compromiso
    $os = @(Get-CSWHwCim -ClassName Win32_OperatingSystem) | Select-Object -First 1
    if ($null -ne $os) {
        $tv = ConvertTo-CSWHwNumber (Get-CSWHwProp $os 'TotalVisibleMemorySize')
        $fp = ConvertTo-CSWHwNumber (Get-CSWHwProp $os 'FreePhysicalMemory')
        if ($null -ne $tv -and $tv -gt 0 -and $null -ne $fp) {
            $pct = [math]::Round((1 - $fp / $tv) * 100, 0)
            $val = '{0} % ({1} de {2})' -f $pct, (Format-CSWHwSize (($tv - $fp) * 1KB)), (Format-CSWHwSize ($tv * 1KB))
            if ($pct -ge $script:HwRamUseWarn) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Uso de memoria' -Valor $val -Estado 'Aviso' -Recomendacion 'Memoria casi llena: cerrar programas en segundo plano o ampliar la RAM.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Uso de memoria' -Valor $val -Estado 'OK')) }
        }
    }

    # Presion de memoria: compromiso y fallos de pagina duros (3 muestras)
    $samples = @()
    for ($i = 0; $i -lt 3; $i++) {
        $s = @(Get-CSWHwCim -ClassName Win32_PerfFormattedData_PerfOS_Memory) | Select-Object -First 1
        if ($null -ne $s) { $samples += $s }
        if ($i -lt 2) { Start-Sleep -Milliseconds 1000 }
    }
    if ($samples.Count) {
        $last = $samples[-1]
        $cb = ConvertTo-CSWHwNumber (Get-CSWHwProp $last 'CommittedBytes')
        $cl = ConvertTo-CSWHwNumber (Get-CSWHwProp $last 'CommitLimit')
        if ($null -ne $cb -and $null -ne $cl -and $cl -gt 0) {
            $cp = [math]::Round($cb / $cl * 100, 0)
            $val = '{0} % ({1} de {2})' -f $cp, (Format-CSWHwSize $cb), (Format-CSWHwSize $cl)
            if ($cp -ge $script:HwRamCommitWarn) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Memoria comprometida' -Valor $val -Estado 'Aviso' -Detalle 'Cerca del limite (RAM + archivo de paginacion)' -Recomendacion 'El sistema esta cerca de quedarse sin memoria: ampliar RAM o el archivo de paginacion.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Memoria comprometida' -Valor $val -Estado 'OK')) }
        }
        $pi = @($samples | ForEach-Object { ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'PagesInputPersec') } | Where-Object { $null -ne $_ })
        if ($pi.Count) {
            $avg = [math]::Round((($pi | Measure-Object -Average).Average), 0)
            if ($avg -ge $script:HwHardFaultWarn) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Fallos de pagina duros' -Valor "$avg pag/s" -Estado 'Aviso' -Detalle 'Windows esta leyendo memoria desde el disco de forma intensa' -Recomendacion 'Hay presion de memoria: ampliar la RAM mejoraria la fluidez del equipo.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Fallos de pagina duros' -Valor "$avg pag/s" -Estado 'OK' -Detalle 'Media de 3 muestras')) }
        }
    }

    # Archivo de paginacion
    $pf = @(Get-CSWHwCim -ClassName Win32_PageFileUsage)
    if ($pf.Count) {
        $alloc = 0.0; $used = 0.0; $peak = 0.0
        foreach ($p in $pf) {
            $a = ConvertTo-CSWHwNumber (Get-CSWHwProp $p 'AllocatedBaseSize'); if ($null -ne $a) { $alloc += $a }
            $u = ConvertTo-CSWHwNumber (Get-CSWHwProp $p 'CurrentUsage'); if ($null -ne $u) { $used += $u }
            $k = ConvertTo-CSWHwNumber (Get-CSWHwProp $p 'PeakUsage'); if ($null -ne $k) { $peak += $k }
        }
        if ($alloc -gt 0) {
            $pp = [math]::Round($used / $alloc * 100, 0)
            $val = '{0} % ({1:N0} de {2:N0} MB)' -f $pp, $used, $alloc
            $det = 'Pico desde el arranque: {0:N0} MB' -f $peak
            if ($pp -ge $script:HwPagefileWarn) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Archivo de paginacion' -Valor $val -Estado 'Aviso' -Detalle $det -Recomendacion 'Uso alto del archivo de paginacion: la RAM se queda corta para la carga de trabajo.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Archivo de paginacion' -Valor $val -Estado 'OK' -Detalle $det)) }
        }
    }
    else {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Archivo de paginacion' -Valor 'Sin archivo de paginacion' -Estado 'OK' -Detalle 'Puede provocar cierres de programas si se agota la RAM'))
    }

    # Diagnostico de memoria de Windows (1101/1201 sin errores; 1102/1202 errores)
    $md = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -Days 0 -Max 5
    $mdEv = @($md.Events | Where-Object { @(1101, 1102, 1201, 1202) -contains [int]$_.Id } | Sort-Object TimeCreated -Descending)
    if ($mdEv.Count) {
        $l = $mdEv[0]
        $when = $l.TimeCreated.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
        if ([int]$l.Id -eq 1102 -or [int]$l.Id -eq 1202) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Diagnostico de memoria de Windows' -Valor "ERRORES DETECTADOS ($when)" -Estado 'Fallo' -Detalle "Evento $($l.Id)" -Recomendacion 'La prueba de memoria encontro errores: identificar el modulo defectuoso (probar uno a uno) y reemplazarlo.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Diagnostico de memoria de Windows' -Valor "Sin errores ($when)" -Estado 'OK' -Detalle "Evento $($l.Id)")) }
    }
    else {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Diagnostico de memoria de Windows' -Valor 'Nunca ejecutado' -Estado 'Sin datos' -Detalle 'Use la accion "Programar prueba de RAM" si hay cuelgues o pantallazos'))
    }

    # Errores WHEA de memoria
    $wh = Get-CSWHwWheaEvents
    if ($wh.Ok) {
        $mem = @($wh.Events | Where-Object { $_.Category -eq 'Memoria' })
        $fatal = @($mem | Where-Object { $_.Fatal })
        $corr = @($mem | Where-Object { -not $_.Fatal })
        if ($fatal.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba "Errores WHEA de memoria ($($script:HwEventDays) dias)" -Valor "$($fatal.Count) fatales, $($corr.Count) corregidos" -Estado 'Fallo' -Detalle ('Ids: ' + ((@($mem | ForEach-Object { $_.Id } | Select-Object -Unique)) -join ', ')) -Recomendacion 'Errores de hardware fatales: ejecutar la prueba de memoria y reemplazar el modulo defectuoso.'))
        }
        elseif ($corr.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba "Errores WHEA de memoria ($($script:HwEventDays) dias)" -Valor "$($corr.Count) corregidos" -Estado 'Aviso' -Detalle ('Ids: ' + ((@($corr | ForEach-Object { $_.Id } | Select-Object -Unique)) -join ', ')) -Recomendacion 'Hay errores de hardware corregidos: quitar overclock/XMP y ejecutar la prueba de memoria.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba "Errores WHEA de memoria ($($script:HwEventDays) dias)" -Valor '0' -Estado 'OK')) }
    }
    else {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'RAM' -Prueba 'Errores WHEA de memoria' -Valor 'No disponible' -Estado 'Sin datos' -Detalle (Get-CSWHwShortText $wh.Error 120)))
    }
    return @($out)
}

# ===========================================================================
# 3. Bateria
# ===========================================================================
function ConvertFrom-CSWHwChemistry {
    # BatteryStaticData.Chemistry: 4 caracteres ASCII empaquetados en un uint32 (ej. 'LION')
    param($Value)
    $n = ConvertTo-CSWHwNumber $Value
    if ($null -eq $n -or $n -le 0) { return '' }
    try {
        $bytes = [BitConverter]::GetBytes([uint32]$n)
        $s = -join ($bytes | Where-Object { $_ -ge 32 -and $_ -lt 127 } | ForEach-Object { [char]$_ })
        return $s.Trim()
    }
    catch { return '' }
}

function Get-CSWHwBatteryFindings {
    [CmdletBinding()]
    param([switch]$NoReport)
    $cat = 'Bateria'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando bateria (capacidad, desgaste, ciclos y estado)...' -Level Step

    $wb = @(Get-CSWHwCim -ClassName Win32_Battery)
    if (-not $wb.Count) {
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Bateria' -Prueba 'Presencia' -Valor 'Equipo sin bateria' -Estado 'OK' -Detalle 'Equipo de sobremesa o bateria no detectada'))
        return @($out)
    }

    # Datos de root\wmi (por InstanceName)
    $static = @{}; $full = @{}; $cycles = @{}; $status = @{}
    $wmiOk = $false
    foreach ($x in (Get-CSWHwCim -Namespace root\wmi -ClassName BatteryStaticData)) { $static[[string](Get-CSWHwProp $x 'InstanceName')] = $x; $wmiOk = $true }
    foreach ($x in (Get-CSWHwCim -Namespace root\wmi -ClassName BatteryFullChargedCapacity)) { $full[[string](Get-CSWHwProp $x 'InstanceName')] = $x }
    foreach ($x in (Get-CSWHwCim -Namespace root\wmi -ClassName BatteryCycleCount)) { $cycles[[string](Get-CSWHwProp $x 'InstanceName')] = $x }
    foreach ($x in (Get-CSWHwCim -Namespace root\wmi -ClassName BatteryStatus)) { $status[[string](Get-CSWHwProp $x 'InstanceName')] = $x }

    $chemW32 = @{ 1 = 'Otra'; 2 = 'Desconocida'; 3 = 'Plomo-acido'; 4 = 'NiCd'; 5 = 'NiMH'; 6 = 'Litio-ion'; 7 = 'Zinc-aire'; 8 = 'Litio-polimero' }

    $keys = @($static.Keys)
    if (-not $keys.Count) { $keys = @($full.Keys) }
    if (-not $keys.Count) { $keys = @($status.Keys) }

    if (-not $keys.Count) {
        # Solo hay Win32_Battery (sin acceso a root\wmi)
        $i = 0
        foreach ($b in $wb) {
            $i++
            $comp = "Bateria $i ($([string](Get-CSWHwProp $b 'Name')))"
            $chg = Get-CSWHwProp $b 'EstimatedChargeRemaining'
            $ch = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $b 'Chemistry'))
            $chT = ''; if ($chemW32.ContainsKey($ch)) { $chT = $chemW32[$ch] }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Carga actual' -Valor "$chg %" -Estado 'OK' -Detalle "Quimica: $chT"))
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste' -Valor 'No disponible' -Estado 'Sin datos' -Detalle 'El firmware no expone la capacidad de diseno por WMI; ver el informe de bateria'))
        }
    }
    else {
        $i = 0
        foreach ($k in $keys) {
            $i++
            $sd = $null; if ($static.ContainsKey($k)) { $sd = $static[$k] }
            $fc = $null; if ($full.ContainsKey($k)) { $fc = $full[$k] }
            $cc = $null; if ($cycles.ContainsKey($k)) { $cc = $cycles[$k] }
            $bs = $null; if ($status.ContainsKey($k)) { $bs = $status[$k] }
            $manu = ([string](Get-CSWHwProp $sd 'ManufactureName')).Trim()
            $dev = ([string](Get-CSWHwProp $sd 'DeviceName')).Trim()
            $chem = ConvertFrom-CSWHwChemistry (Get-CSWHwProp $sd 'Chemistry')
            $comp = "Bateria $i"
            if ($dev) { $comp += " ($dev)" }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Identificacion' -Valor ("{0} {1}" -f $manu, $dev).Trim() -Estado 'OK' -Detalle ("Quimica: {0}; N/S: {1}" -f $chem, ([string](Get-CSWHwProp $sd 'SerialNumber')).Trim())))

            $design = ConvertTo-CSWHwNumber (Get-CSWHwProp $sd 'DesignedCapacity')
            $fullC = ConvertTo-CSWHwNumber (Get-CSWHwProp $fc 'FullChargedCapacity')
            if ($null -ne $design -and $design -gt 0 -and $null -ne $fullC -and $fullC -gt 0) {
                $wear = [math]::Round((1 - $fullC / $design) * 100, 1)
                if ($wear -lt 0) { $wear = 0 }
                $val = "$wear %"
                $det = ('Capacidad de diseno {0:N0} mWh; carga completa actual {1:N0} mWh ({2:N0} % de la original)' -f $design, $fullC, (100 - $wear))
                if ($wear -gt $script:HwBattWearFail) {
                    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste' -Valor $val -Estado 'Fallo' -Detalle $det -Recomendacion 'La bateria ha perdido mas del 40 % de su capacidad: se recomienda reemplazarla.'))
                }
                elseif ($wear -ge $script:HwBattWearWarn) {
                    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste' -Valor $val -Estado 'Aviso' -Detalle $det -Recomendacion 'La bateria muestra desgaste notable: la autonomia es menor; planificar su reemplazo.'))
                }
                else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste' -Valor $val -Estado 'OK' -Detalle $det)) }
            }
            else {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Desgaste' -Valor 'No disponible' -Estado 'Sin datos' -Detalle 'El firmware no informa la capacidad de diseno o de carga completa'))
            }

            $cyc = ConvertTo-CSWHwNumber (Get-CSWHwProp $cc 'CycleCount')
            if ($null -ne $cyc -and $cyc -gt 0) {
                if ($cyc -ge $script:HwBattCyclesWarn) {
                    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Ciclos de carga' -Valor "$cyc" -Estado 'Aviso' -Detalle "Umbral de aviso: $($script:HwBattCyclesWarn) ciclos" -Recomendacion 'La bateria acumula muchos ciclos: su vida util esta cerca del final.'))
                }
                else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Ciclos de carga' -Valor "$cyc" -Estado 'OK')) }
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Ciclos de carga' -Valor 'No disponible' -Estado 'Sin datos' -Detalle 'El firmware no informa los ciclos')) }

            if ($null -ne $bs) {
                $online = [bool](Get-CSWHwProp $bs 'PowerOnline')
                $charging = [bool](Get-CSWHwProp $bs 'Charging')
                $dis = [bool](Get-CSWHwProp $bs 'Discharging')
                $crit = [bool](Get-CSWHwProp $bs 'Critical')
                $rem = ConvertTo-CSWHwNumber (Get-CSWHwProp $bs 'RemainingCapacity')
                $volt = ConvertTo-CSWHwNumber (Get-CSWHwProp $bs 'Voltage')
                $drate = ConvertTo-CSWHwNumber (Get-CSWHwProp $bs 'DischargeRate')
                $crate = ConvertTo-CSWHwNumber (Get-CSWHwProp $bs 'ChargeRate')
                $state = 'En reposo'
                if ($charging) { $state = 'Cargando' } elseif ($dis) { $state = 'Descargando' }
                if ($online) { $state += ' (conectado a corriente)' } else { $state += ' (en bateria)' }
                $pct = ''
                if ($null -ne $rem -and $null -ne $fullC -and $fullC -gt 0) { $pct = ('{0:N0} %' -f [math]::Min(100, $rem / $fullC * 100)) }
                $det = ('Restante {0:N0} mWh; voltaje {1:N2} V; tasa de descarga {2:N0} mW; tasa de carga {3:N0} mW' -f $rem, ($volt / 1000), $drate, $crate)
                if ($crit) {
                    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Estado actual' -Valor "$state $pct" -Estado 'Aviso' -Detalle $det -Recomendacion 'Bateria en nivel critico: conectar el cargador.'))
                }
                else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Estado actual' -Valor ("$state $pct".Trim()) -Estado 'OK' -Detalle $det)) }
            }
        }
    }

    # Informe de bateria de powercfg
    if (-not $NoReport) {
        try {
            $path = Join-Path (Get-CSWDataPath Reports) ('BatteryReport_{0}_{1:yyyyMMdd_HHmmss}.html' -f $env:COMPUTERNAME, (Get-Date))
            $code = Invoke-CSWExternal -FilePath 'powercfg.exe' -Arguments "/batteryreport /output `"$path`""
            if ($code -eq 0 -and (Test-Path $path)) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Bateria' -Prueba 'Informe de bateria (powercfg)' -Valor $path -Estado 'OK' -Detalle 'Historial de capacidad y autonomia'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Bateria' -Prueba 'Informe de bateria (powercfg)' -Valor 'No generado' -Estado 'Sin datos' -Detalle "powercfg devolvio el codigo $code")) }
        }
        catch { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Bateria' -Prueba 'Informe de bateria (powercfg)' -Valor 'No generado' -Estado 'Sin datos' -Detalle (Get-CSWHwShortText $_.Exception.Message 120))) }
    }
    if (-not $wmiOk) { Write-CSWLog 'root\wmi no expone datos detallados de bateria (permisos o firmware).' -Level Info }
    return @($out)
}

# ===========================================================================
# 4. CPU y termico
# ===========================================================================
function Get-CSWHwThermalZones {
    # Temperaturas ACPI en C. MSAcpi requiere admin; el contador de rendimiento no.
    $zones = New-Object System.Collections.ArrayList
    foreach ($z in (Get-CSWHwCim -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature)) {
        $v = ConvertTo-CSWHwNumber (Get-CSWHwProp $z 'CurrentTemperature')
        if ($null -eq $v) { continue }
        $c = [math]::Round(($v / 10) - 273.15, 1)
        [void]$zones.Add([pscustomobject]@{ Name = (([string](Get-CSWHwProp $z 'InstanceName')) -replace '^.*\\', ''); Celsius = $c })
    }
    if (-not $zones.Count) {
        foreach ($z in (Get-CSWHwCim -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation)) {
            $hp = ConvertTo-CSWHwNumber (Get-CSWHwProp $z 'HighPrecisionTemperature')
            $k = ConvertTo-CSWHwNumber (Get-CSWHwProp $z 'Temperature')
            $c = $null
            if ($null -ne $hp -and $hp -gt 0) { $c = [math]::Round(($hp / 10) - 273.15, 1) }
            elseif ($null -ne $k -and $k -gt 0) { $c = [math]::Round($k - 273.15, 1) }
            if ($null -ne $c) { [void]$zones.Add([pscustomobject]@{ Name = (([string](Get-CSWHwProp $z 'Name')) -replace '^.*\\', ''); Celsius = $c }) }
        }
    }
    # Descarta lecturas imposibles (sensores sin implementar devuelven 0 K o valores fijos)
    return @($zones | Where-Object { $_.Celsius -gt 5 -and $_.Celsius -lt 115 })
}

function Get-CSWHwCpuFindings {
    [CmdletBinding()]
    param()
    $cat = 'CPU'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando procesador (carga, frecuencia, throttling, temperatura y eventos)...' -Level Step

    $cpus = @(Get-CSWHwCim -ClassName Win32_Processor)
    $base = $null
    $i = 0
    foreach ($c in $cpus) {
        $i++
        $comp = 'CPU'; if ($cpus.Count -gt 1) { $comp = "CPU $i" }
        $name = ([string](Get-CSWHwProp $c 'Name')).Trim()
        $cores = Get-CSWHwProp $c 'NumberOfCores'; $thr = Get-CSWHwProp $c 'NumberOfLogicalProcessors'
        $max = ConvertTo-CSWHwNumber (Get-CSWHwProp $c 'MaxClockSpeed'); if ($null -eq $base) { $base = $max }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Modelo' -Valor $name -Estado 'OK' -Detalle "$cores nucleos / $thr hilos; base $max MHz; socket $([string](Get-CSWHwProp $c 'SocketDesignation'))"))
    }
    if (-not $cpus.Count) { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Modelo' -Valor 'No disponible' -Estado 'Sin datos')) }

    # 5 muestras del contador independiente del idioma (via CIM)
    $samples = @()
    for ($k = 0; $k -lt 5; $k++) {
        $s = @(Get-CSWHwCim -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'") | Select-Object -First 1
        if ($null -ne $s) { $samples += $s }
        if ($k -lt 4) { Start-Sleep -Milliseconds 1000 }
    }
    $avgOf = {
        param($prop)
        $v = @($samples | ForEach-Object { ConvertTo-CSWHwNumber (Get-CSWHwProp $_ $prop) } | Where-Object { $null -ne $_ })
        if (-not $v.Count) { return $null }
        return [math]::Round((($v | Measure-Object -Average).Average), 0)
    }
    $load = & $avgOf 'PercentProcessorTime'
    $perf = & $avgOf 'PercentProcessorPerformance'
    $freq = & $avgOf 'ProcessorFrequency'
    $limit = & $avgOf 'PercentPerformanceLimit'
    if ($null -eq $load) {
        $lp = @($cpus | ForEach-Object { ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'LoadPercentage') } | Where-Object { $null -ne $_ })
        if ($lp.Count) { $load = [math]::Round((($lp | Measure-Object -Average).Average), 0) }
    }
    if ($null -ne $load) {
        if ($load -ge $script:HwCpuLoadWarn) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Carga media (5 muestras)' -Valor "$load %" -Estado 'Aviso' -Detalle 'Carga sostenida muy alta durante la revision' -Recomendacion 'La CPU esta saturada: revisar procesos en segundo plano, malware o programas de inicio.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Carga media (5 muestras)' -Valor "$load %" -Estado 'OK')) }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Carga media (5 muestras)' -Valor 'No disponible' -Estado 'Sin datos')) }

    # Frecuencia real y throttling
    if ($null -ne $perf) {
        $bf = $freq; if ($null -eq $bf -or $bf -le 0) { $bf = $base }
        $actual = ''
        if ($null -ne $bf -and $bf -gt 0) { $actual = ('~{0:N0} MHz' -f ($bf * $perf / 100)) }
        $det = "Rendimiento $perf % de la frecuencia base ($bf MHz)"
        if ($null -ne $limit) { $det += "; limite de rendimiento $limit %" }
        # Throttling: con carga relevante la CPU deberia ir cerca o por encima de su base
        if ($null -ne $load -and $load -ge 40 -and $perf -lt 60) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Frecuencia actual / throttling' -Valor $actual -Estado 'Aviso' -Detalle "$det. Con carga la CPU va muy por debajo de su base: posible throttling termico o de energia" -Recomendacion 'Posible throttling: limpiar ventiladores, renovar pasta termica y usar un plan de energia equilibrado o de alto rendimiento.'))
        }
        elseif ($null -ne $limit -and $limit -lt 90) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Frecuencia actual / throttling' -Valor $actual -Estado 'Aviso' -Detalle "$det. El sistema esta limitando el rendimiento (energia o temperatura)" -Recomendacion 'El rendimiento esta limitado: revisar plan de energia, cargador conectado y temperatura.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Frecuencia actual / throttling' -Valor $actual -Estado 'OK' -Detalle $det)) }
    }
    else {
        $cur = $null; if ($cpus.Count) { $cur = Get-CSWHwProp $cpus[0] 'CurrentClockSpeed' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba 'Frecuencia actual / throttling' -Valor "$cur MHz" -Estado 'Sin datos' -Detalle 'Contador de rendimiento del procesador no disponible'))
    }

    # Temperaturas ACPI
    $zones = @(Get-CSWHwThermalZones)
    if ($zones.Count) {
        foreach ($z in $zones) {
            $st = 'OK'; $rec = ''
            if ($z.Celsius -ge $script:HwCpuTempFail) { $st = 'Fallo'; $rec = 'Temperatura critica: limpiar el polvo, revisar ventiladores y renovar la pasta termica.' }
            elseif ($z.Celsius -ge $script:HwCpuTempWarn) { $st = 'Aviso'; $rec = 'Temperatura elevada: limpiar ventiladores y revisar la refrigeracion.' }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Termico' -Prueba "Zona termica $($z.Name)" -Valor "$($z.Celsius) C" -Estado $st -Detalle 'Sensor ACPI (no siempre es el nucleo de la CPU)' -Recomendacion $rec))
        }
    }
    else {
        $why = 'El firmware no expone sensores ACPI'
        if (-not (Test-CSWAdmin)) { $why = 'Requiere administrador o el firmware no expone sensores ACPI' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Termico' -Prueba 'Temperatura ACPI' -Valor 'No disponible' -Estado 'Sin datos' -Detalle $why))
    }

    # Kernel-Processor-Power 37: frecuencia limitada por el firmware
    $kp = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37 } -Days $script:HwEventDays -Max 500
    if ($kp.Ok) {
        $n = @($kp.Events).Count
        if ($n) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba "Limitacion por firmware ($($script:HwEventDays) dias)" -Valor "$n eventos" -Estado 'Aviso' -Detalle ('Kernel-Processor-Power 37; ultimo {0:dd\/MM\/yyyy HH:mm}' -f $kp.Events[0].TimeCreated) -Recomendacion 'El firmware limito la velocidad del procesador: revisar temperatura, cargador original y actualizar BIOS.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba "Limitacion por firmware ($($script:HwEventDays) dias)" -Valor '0' -Estado 'OK')) }
    }

    # WHEA de CPU / bus
    $wh = Get-CSWHwWheaEvents
    if ($wh.Ok) {
        $cb = @($wh.Events | Where-Object { $_.Category -eq 'Procesador' -or $_.Category -eq 'Bus' })
        $fatal = @($cb | Where-Object { $_.Fatal })
        if ($fatal.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba "Errores WHEA CPU/bus ($($script:HwEventDays) dias)" -Valor "$($fatal.Count) fatales de $($cb.Count)" -Estado 'Fallo' -Detalle ('Ids: ' + ((@($cb | ForEach-Object { $_.Id } | Select-Object -Unique)) -join ', ')) -Recomendacion 'Errores fatales de hardware: quitar overclock, actualizar BIOS y revisar CPU/placa/fuente.'))
        }
        elseif ($cb.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba "Errores WHEA CPU/bus ($($script:HwEventDays) dias)" -Valor "$($cb.Count) corregidos" -Estado 'Aviso' -Detalle ('Ids: ' + ((@($cb | ForEach-Object { $_.Id } | Select-Object -Unique)) -join ', ')) -Recomendacion 'Errores de hardware corregidos (CPU o PCIe): actualizar BIOS/drivers de chipset y revisar overclock.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'CPU' -Prueba "Errores WHEA CPU/bus ($($script:HwEventDays) dias)" -Valor '0' -Estado 'OK')) }
    }

    # Kernel-Power 41: apagados inesperados
    $k41 = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 } -Days $script:HwEventDays -Max 200
    if ($k41.Ok) {
        $n = @($k41.Events).Count
        $p = "Apagados inesperados ($($script:HwEventDays) dias)"
        if ($n -ge $script:HwKp41Fail) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba $p -Valor "$n" -Estado 'Fallo' -Detalle ('Kernel-Power 41; ultimo {0:dd\/MM\/yyyy HH:mm}' -f $k41.Events[0].TimeCreated) -Recomendacion 'Apagados inesperados repetidos: revisar fuente de alimentacion, temperatura y RAM.'))
        }
        elseif ($n -ge $script:HwKp41Warn) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba $p -Valor "$n" -Estado 'Aviso' -Detalle ('Kernel-Power 41; ultimo {0:dd\/MM\/yyyy HH:mm}' -f $k41.Events[0].TimeCreated) -Recomendacion 'Hubo apagados inesperados (cortes de luz, cuelgues o fuente): vigilar si se repiten.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba $p -Valor '0' -Estado 'OK')) }
    }
    return @($out)
}

# ===========================================================================
# 5. GPU
# ===========================================================================
function Get-CSWHwGpuVram {
    # VRAM real desde el registro (Win32_VideoController.AdapterRAM se satura en 4 GB)
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

function Get-CSWHwGpuFindings {
    [CmdletBinding()]
    param()
    $cat = 'GPU'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando adaptadores graficos (driver, VRAM, resolucion y reinicios TDR)...' -Level Step

    $vcs = @(Get-CSWHwCim -ClassName Win32_VideoController)
    $vram = Get-CSWHwGpuVram
    if (-not $vcs.Count) { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'GPU' -Prueba 'Adaptadores' -Valor 'No detectados' -Estado 'Sin datos')) }
    foreach ($v in $vcs) {
        $name = ([string](Get-CSWHwProp $v 'Name')).Trim()
        $comp = "GPU ($name)"
        $mem = $null
        if ($vram.ContainsKey($name)) { $mem = $vram[$name] }
        else { $mem = ConvertTo-CSWHwNumber (Get-CSWHwProp $v 'AdapterRAM') }
        $res = ''
        $h = Get-CSWHwProp $v 'CurrentHorizontalResolution'; $vv = Get-CSWHwProp $v 'CurrentVerticalResolution'
        if ($h -and $vv) { $res = "${h}x${vv} @ $(Get-CSWHwProp $v 'CurrentRefreshRate') Hz" }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Adaptador' -Valor ("VRAM {0}" -f (Format-CSWHwSize $mem)) -Estado 'OK' -Detalle ("Resolucion: {0}" -f $(if ($res) { $res } else { 'sin pantalla activa' }))))

        # Driver
        $ver = [string](Get-CSWHwProp $v 'DriverVersion')
        $dd = Get-CSWHwProp $v 'DriverDate'
        $date = $null
        if ($dd -is [datetime]) { $date = $dd }
        elseif ($dd) { try { $date = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$dd) } catch { $date = $null } }
        $err = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $v 'ConfigManagerErrorCode'))
        if ($name -match 'Microsoft Basic Display|Basic Render|Adaptador de pantalla basico') {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Driver' -Valor 'Driver generico de Microsoft' -Estado 'Aviso' -Detalle 'Sin aceleracion grafica ni ajustes del fabricante' -Recomendacion 'Instalar el driver de video del fabricante (Intel/AMD/NVIDIA o del equipo).'))
        }
        elseif ($err -ne 0) {
            $et = 'Codigo ' + $err; if ($script:HwCmErrors.ContainsKey($err)) { $et += ': ' + $script:HwCmErrors[$err] }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Driver' -Valor $ver -Estado 'Fallo' -Detalle $et -Recomendacion 'La tarjeta grafica tiene un error de dispositivo: reinstalar el driver limpio (DDU) y revisar el hardware.'))
        }
        elseif ($null -ne $date) {
            $age = ((Get-Date) - $date).TotalDays
            $det = ('Fecha del driver: {0:dd\/MM\/yyyy} ({1:N1} anos)' -f $date, ($age / 365))
            if ($age -gt $script:HwGpuDriverAgeDays) {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Driver' -Valor $ver -Estado 'Aviso' -Detalle $det -Recomendacion 'Driver de video con mas de 2 anos: actualizarlo desde la web del fabricante.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Driver' -Valor $ver -Estado 'OK' -Detalle $det)) }
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba 'Driver' -Valor $ver -Estado 'Sin datos' -Detalle 'Fecha del driver desconocida')) }
    }

    # TDR: el driver de video dejo de responder y se recupero (Display 4101)
    $tdr = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101 } -Days $script:HwEventDays -Max 200
    $p = "Reinicios del driver de video TDR ($($script:HwEventDays) dias)"
    if ($tdr.Ok) {
        $n = @($tdr.Events).Count
        if ($n -ge $script:HwTdrFail) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'GPU' -Prueba $p -Valor "$n" -Estado 'Fallo' -Detalle ('Display 4101; ultimo {0:dd\/MM\/yyyy HH:mm}' -f $tdr.Events[0].TimeCreated) -Recomendacion 'El driver de video se cuelga con frecuencia: reinstalar el driver limpio y revisar temperatura y estado de la tarjeta grafica.'))
        }
        elseif ($n -gt 0) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'GPU' -Prueba $p -Valor "$n" -Estado 'Aviso' -Detalle ('Display 4101; ultimo {0:dd\/MM\/yyyy HH:mm}' -f $tdr.Events[0].TimeCreated) -Recomendacion 'El driver de video se reinicio alguna vez: actualizar el driver de video.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'GPU' -Prueba $p -Valor '0' -Estado 'OK')) }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'GPU' -Prueba $p -Valor 'No disponible' -Estado 'Sin datos' -Detalle (Get-CSWHwShortText $tdr.Error 120))) }
    return @($out)
}

# ===========================================================================
# 6. Energia y termico
# ===========================================================================
function Get-CSWHwPowerFindings {
    [CmdletBinding()]
    param()
    $cat = 'CPU'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando energia (plan, hibernacion, apagados, ventiladores y alimentacion)...' -Level Step

    # Plan de energia activo (CIM y, si falla, registro)
    $plan = ''
    $pp = @(Get-CSWHwCim -Namespace 'root\cimv2\power' -ClassName Win32_PowerPlan -Filter 'IsActive=True') | Select-Object -First 1
    if ($null -ne $pp) { $plan = [string](Get-CSWHwProp $pp 'ElementName') }
    if (-not $plan) {
        $known = @{
            '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Equilibrado'
            '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'Alto rendimiento'
            'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Economizador'
            'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Maximo rendimiento'
        }
        try {
            $g = [string](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -Name ActivePowerScheme -ErrorAction Stop).ActivePowerScheme
            if ($known.ContainsKey($g.ToLowerInvariant())) { $plan = $known[$g.ToLowerInvariant()] }
            else {
                $fn = ''
                try { $fn = [string](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$g" -Name FriendlyName -ErrorAction Stop).FriendlyName } catch { }
                # Los planes integrados usan '@%SystemRoot%\...,-id,Nombre'; los personalizados texto plano
                if ($fn -match '^@.*,([^,]+)$') { $plan = $Matches[1] }
                elseif ($fn -and $fn -notmatch '^@') { $plan = $fn }
                else { $plan = "Personalizado ($g)" }
            }
        }
        catch { }
    }
    if ($plan) {
        $st = 'OK'; $rec = ''
        if ($plan -match 'Econom|Power saver|Ahorro') { $st = 'Aviso'; $rec = 'El plan de ahorro de energia reduce el rendimiento: usar el plan Equilibrado.' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Plan de energia activo' -Valor $plan -Estado $st -Recomendacion $rec))
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Plan de energia activo' -Valor 'No disponible' -Estado 'Sin datos')) }

    # Hibernacion e inicio rapido
    $hib = $null; $fast = $null
    try { $hib = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction Stop).HibernateEnabled } catch { }
    try { $fast = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch { }
    $hv = 'Desconocido'; if ($null -ne $hib) { if ([int]$hib -eq 1) { $hv = 'Habilitada' } else { $hv = 'Deshabilitada' } }
    $fv = 'desconocido'; if ($null -ne $fast) { if ([int]$fast -eq 1) { $fv = 'habilitado' } else { $fv = 'deshabilitado' } }
    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Hibernacion / inicio rapido' -Valor "Hibernacion: $hv" -Estado 'OK' -Detalle "Inicio rapido: $fv (si esta habilitado, 'Apagar' no reinicia por completo el kernel)"))

    # Ultimo arranque y tipo
    $os = @(Get-CSWHwCim -ClassName Win32_OperatingSystem) | Select-Object -First 1
    $lb = Get-CSWHwProp $os 'LastBootUpTime'
    $bootType = ''
    $kb = Get-CSWHwEvents -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27 } -Days 0 -Max 1
    if (@($kb.Events).Count) {
        try {
            $bt = [int]$kb.Events[0].Properties[0].Value
            $bootType = switch ($bt) { 0 { 'arranque completo' } 1 { 'inicio rapido (hibrido)' } 2 { 'reanudacion desde hibernacion' } default { "tipo $bt" } }
        }
        catch { }
    }
    if ($lb -is [datetime]) {
        $up = (Get-Date) - $lb
        $det = ('Encendido desde hace {0} dias {1} h' -f [int]$up.TotalDays, $up.Hours)
        if ($bootType) { $det += "; tipo: $bootType" }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Ultimo arranque' -Valor ($lb.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)) -Estado 'OK' -Detalle $det))
    }

    # Ultimo apagado: 6006 limpio, 6008/41 inesperado, 1074 iniciado por usuario/proceso
    $sd = Get-CSWHwEvents -Filter @{ LogName = 'System'; Id = @(41, 1074, 6006, 6008) } -Days 0 -Max 30
    $evs = @($sd.Events | Where-Object {
            ($_.Id -eq 41 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power') -or
            ($_.Id -eq 1074 -and $_.ProviderName -eq 'User32') -or
            (($_.Id -eq 6006 -or $_.Id -eq 6008) -and $_.ProviderName -eq 'EventLog')
        } | Sort-Object TimeCreated -Descending)
    if ($evs.Count) {
        $e = $evs[0]
        $when = $e.TimeCreated.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        if ($e.Id -eq 41 -or $e.Id -eq 6008) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Ultimo apagado' -Valor "Inesperado ($when)" -Estado 'Aviso' -Detalle "Evento $($e.Id): el sistema no se apago correctamente" -Recomendacion 'El ultimo apagado fue inesperado: comprobar cortes de luz, cuelgues o fuente de alimentacion.'))
        }
        elseif ($e.Id -eq 1074) {
            $who = ''
            try { $who = '{0}; motivo: {1}' -f [string]$e.Properties[0].Value, [string]$e.Properties[2].Value } catch { $who = Get-CSWHwShortText (Get-CSWHwEventText $e) 120 }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Ultimo apagado' -Valor "Ordenado ($when)" -Estado 'OK' -Detalle (Get-CSWHwShortText $who 140)))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Ultimo apagado' -Valor "Correcto ($when)" -Estado 'OK')) }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Ultimo apagado' -Valor 'Sin registros' -Estado 'Sin datos')) }

    # Ventiladores
    $fans = @(Get-CSWHwCim -ClassName Win32_Fan)
    if ($fans.Count) {
        $i = 0
        foreach ($f in $fans) {
            $i++
            $fs = [string](Get-CSWHwProp $f 'Status')
            if ($fs -and $fs -ne 'OK') {
                [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Termico' -Prueba "Ventilador $i" -Valor $fs -Estado 'Aviso' -Detalle ([string](Get-CSWHwProp $f 'Name')) -Recomendacion 'El ventilador informa un estado anomalo: revisarlo y limpiarlo.'))
            }
            else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Termico' -Prueba "Ventilador $i" -Valor $(if ($fs) { $fs } else { 'Presente' }) -Estado 'OK' -Detalle ([string](Get-CSWHwProp $f 'Name')))) }
        }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Termico' -Prueba 'Ventiladores' -Valor 'No expuestos' -Estado 'Sin datos' -Detalle 'El firmware no informa ventiladores a Windows (habitual)')) }

    # Fuente de alimentacion
    $wb = @(Get-CSWHwCim -ClassName Win32_Battery)
    if ($wb.Count) {
        $bst = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $wb[0] 'BatteryStatus'))
        $src = 'Corriente alterna (cargador conectado)'
        if ($bst -eq 1 -or $bst -eq 4 -or $bst -eq 5) { $src = 'Bateria (cargador desconectado)' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Fuente de alimentacion' -Valor $src -Estado 'OK' -Detalle ("Carga: {0} %" -f (Get-CSWHwProp $wb[0] 'EstimatedChargeRemaining'))))
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Energia' -Prueba 'Fuente de alimentacion' -Valor 'Corriente alterna' -Estado 'OK' -Detalle 'Equipo sin bateria')) }
    return @($out)
}

# ===========================================================================
# 7. Perifericos
# ===========================================================================
function Get-CSWHwPeripheralFindings {
    [CmdletBinding()]
    param()
    $cat = 'Perifericos'
    $out = New-Object System.Collections.ArrayList
    Write-CSWLog 'Analizando dispositivos (errores del Administrador de dispositivos, USB, audio y red)...' -Level Step

    $bad = @(Get-CSWHwCim -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0')
    # 45 = no conectado actualmente: es ruido (dispositivos desenchufados), solo se cuenta.
    # 22 = deshabilitado: casi siempre intencional; se lista como informativo sin penalizar.
    $notPresent = @($bad | Where-Object { [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'ConfigManagerErrorCode')) -eq 45 })
    $disabled = @($bad | Where-Object { [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'ConfigManagerErrorCode')) -eq 22 })
    $real = @($bad | Where-Object { @(22, 45) -notcontains [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $_ 'ConfigManagerErrorCode')) })
    foreach ($d in $disabled) {
        $name = [string](Get-CSWHwProp $d 'Name'); if (-not $name) { $name = [string](Get-CSWHwProp $d 'DeviceID') }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Dispositivo' -Prueba (Get-CSWHwShortText $name 70) -Valor 'Codigo 22' -Estado 'OK' -Detalle 'Deshabilitado manualmente (no se considera fallo)'))
    }
    foreach ($d in $real) {
        $code = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $d 'ConfigManagerErrorCode'))
        $txt = 'Error desconocido'; if ($script:HwCmErrors.ContainsKey($code)) { $txt = $script:HwCmErrors[$code] }
        $name = [string](Get-CSWHwProp $d 'Name'); if (-not $name) { $name = [string](Get-CSWHwProp $d 'DeviceID') }
        $cls = [string](Get-CSWHwProp $d 'PNPClass')
        $id = [string](Get-CSWHwProp $d 'DeviceID')
        $isUsb = ($id -like 'USB*' -or $cls -eq 'USB')
        $comp = 'Dispositivo'; if ($isUsb) { $comp = 'USB' } elseif ($cls) { $comp = $cls }
        # 43 = el hardware informo problemas -> Fallo; resto (driver/configuracion) -> Aviso
        $st = 'Aviso'; $rec = 'Instalar o reinstalar el driver correcto del fabricante.'
        if ($code -eq 43) { $st = 'Fallo'; $rec = 'El dispositivo informa un fallo: reconectarlo, reinstalar su driver y, si persiste, reemplazarlo.' }
        elseif ($code -eq 12) { $rec = 'Conflicto de recursos: actualizar BIOS/chipset o retirar hardware en conflicto.' }
        [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente $comp -Prueba (Get-CSWHwShortText $name 70) -Valor "Codigo $code" -Estado $st -Detalle $txt -Recomendacion $rec))
    }
    $ok = 'Sin errores'
    if ($notPresent.Count -or $disabled.Count) { $ok += " ($($disabled.Count) deshabilitado(s), $($notPresent.Count) desconectado(s))" }
    # Fila resumen (marcada como veredicto: no se duplica en hallazgos ni en contadores)
    $sumSt = Get-CSWHwWorst @($out | Where-Object { $_.Componente -ne 'USB' -and $_.Componente -ne 'Audio' -and $_.Componente -ne 'Red' })
    if ($sumSt -eq 'Sin datos') { $sumSt = 'OK' }
    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Dispositivos' -Prueba 'Administrador de dispositivos' -Valor $(if ($real.Count) { "$($real.Count) con error" } else { $ok }) -Estado $sumSt -Summary))

    # USB
    $usbAll = @(Get-CSWHwCim -ClassName Win32_PnPEntity -Filter "DeviceID LIKE 'USB%'")
    $usbBad = @($real | Where-Object { ([string](Get-CSWHwProp $_ 'DeviceID')) -like 'USB*' -or [string](Get-CSWHwProp $_ 'PNPClass') -eq 'USB' })
    $ctrls = @(Get-CSWHwCim -ClassName Win32_USBController)
    $st = 'OK'; if ($usbBad.Count) { $st = 'Aviso' }
    [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'USB' -Prueba 'Dispositivos USB' -Valor ("{0} con error de {1}" -f $usbBad.Count, $usbAll.Count) -Estado $st -Detalle ("Controladoras USB: {0}" -f $ctrls.Count) -Recomendacion $(if ($usbBad.Count) { 'Probar el dispositivo USB en otro puerto y reinstalar su driver.' } else { '' })))

    # Audio
    $snd = @(Get-CSWHwCim -ClassName Win32_SoundDevice)
    if ($snd.Count) {
        $badS = @($snd | Where-Object { [string](Get-CSWHwProp $_ 'Status') -and [string](Get-CSWHwProp $_ 'Status') -ne 'OK' })
        $names = (@($snd | ForEach-Object { [string](Get-CSWHwProp $_ 'Name') }) -join '; ')
        if ($badS.Count) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Audio' -Prueba 'Dispositivos de audio' -Valor "$($snd.Count) ($($badS.Count) con problemas)" -Estado 'Aviso' -Detalle (Get-CSWHwShortText $names 140) -Recomendacion 'Reinstalar el driver de audio del fabricante.'))
        }
        else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Audio' -Prueba 'Dispositivos de audio' -Valor "$($snd.Count)" -Estado 'OK' -Detalle (Get-CSWHwShortText $names 140))) }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Audio' -Prueba 'Dispositivos de audio' -Valor 'Ninguno' -Estado 'Aviso' -Detalle 'No se detecto hardware de audio' -Recomendacion 'Instalar el driver de audio o comprobar que el audio no este deshabilitado en la BIOS.')) }

    # Red
    $nets = @(Get-CSWHwCim -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' | Where-Object {
            ([string](Get-CSWHwProp $_ 'Name')) -notmatch 'Virtual|Hyper-V|VPN|TAP-|WAN Miniport|Loopback|Bluetooth Device \(Personal|Tailscale|WireGuard|Wintun|ZeroTier|OpenVPN|Npcap|Fortinet|Cisco AnyConnect'
        })
    if ($nets.Count) {
        $conn = 0
        foreach ($n in $nets) {
            $ncs = [int](ConvertTo-CSWHwNumber (Get-CSWHwProp $n 'NetConnectionStatus'))
            $en = Get-CSWHwProp $n 'NetEnabled'
            $stTxt = switch ($ncs) { 2 { 'Conectado' } 7 { 'Cable desconectado / sin red' } 0 { 'Desconectado' } 4 { 'Hardware no presente' } 5 { 'Hardware deshabilitado' } 6 { 'Fallo de hardware' } default { "Estado $ncs" } }
            if ($en -eq $false) { $stTxt = 'Deshabilitado' }
            if ($ncs -eq 2) { $conn++ }
            $st = 'OK'; $rec = ''
            if ($ncs -eq 6) { $st = 'Fallo'; $rec = 'El adaptador de red informa fallo de hardware: reinstalar driver o reemplazar el adaptador.' }
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Red' -Prueba (Get-CSWHwShortText ([string](Get-CSWHwProp $n 'Name')) 70) -Valor $stTxt -Estado $st -Detalle ("MAC {0}" -f (Get-CSWHwProp $n 'MACAddress')) -Recomendacion $rec))
        }
        if (-not $conn) {
            [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Red' -Prueba 'Conectividad' -Valor 'Ningun adaptador fisico conectado' -Estado 'Aviso' -Recomendacion 'Revisar cable de red o conexion Wi-Fi.'))
        }
    }
    else { [void]$out.Add((New-CSWHwFinding -Categoria $cat -Componente 'Red' -Prueba 'Adaptadores de red' -Valor 'Ninguno fisico' -Estado 'Aviso' -Recomendacion 'No hay adaptador de red fisico funcional: instalar su driver.')) }
    return @($out)
}

# ===========================================================================
# Puntuacion e informe HTML
# ===========================================================================
function Get-CSWHwScore {
    param($Findings)
    $all = @($Findings)
    $cats = New-Object System.Collections.ArrayList
    $score = 0.0; $wChecked = 0.0
    foreach ($c in $script:HwCategories) {
        $f = @($all | Where-Object { $_.Categoria -eq $c.Key })
        $checked = ($f.Count -gt 0)
        $estado = 'No revisado'
        $pts = 0.0
        if ($checked) {
            $estado = Get-CSWHwWorst $f
            $pts = [double]$c.Weight
            if ($estado -eq 'Fallo') { $pts = 0 } elseif ($estado -eq 'Aviso') { $pts = $c.Weight / 2 }
            $score += $pts; $wChecked += $c.Weight
        }
        [void]$cats.Add([pscustomobject]@{ Key = $c.Key; Label = $c.Label; Weight = $c.Weight; Estado = $estado; Points = $pts; Checked = $checked })
    }
    $final = 0
    if ($wChecked -gt 0) { $final = [int][math]::Round($score / $wChecked * 100) }
    return [pscustomobject]@{ Score = $final; Partial = ($wChecked -lt 100); Categories = @($cats) }
}

function Get-CSWHwVerdictText {
    param([int]$Score, $Findings)
    $diskFail = @($Findings | Where-Object { $_.Categoria -eq 'Disco' -and $_.Estado -eq 'Fallo' }).Count
    if ($diskFail) { return 'Estado crítico: hay un disco con fallo. Respaldar los datos de inmediato.' }
    if ($Score -ge 90) { return 'Hardware en buen estado.' }
    if ($Score -ge 70) { return 'Estado aceptable con observaciones.' }
    if ($Score -ge 40) { return 'El hardware requiere atención.' }
    return 'Estado crítico: se recomienda intervención urgente.'
}

function Get-CSWHwBadge {
    param([string]$Estado)
    switch ($Estado) {
        'OK' { return "<span class='badge ok'>OK</span>" }
        'Aviso' { return "<span class='badge warn'>Aviso</span>" }
        'Fallo' { return "<span class='badge err'>Fallo</span>" }
        default { return "<span class='muted'>$(ConvertTo-CSWHtmlText $Estado)</span>" }
    }
}

function Update-CSWHwReportSection {
    # Reconstruye la seccion 'HardwareHealth' con todos los hallazgos guardados en la sesion
    $store = Get-CSWHwStore
    $all = @()
    foreach ($k in @($store.Keys)) { $all += @($store[$k]) }
    if (-not $all.Count) { return }
    $sc = Get-CSWHwScore $all
    $color = 'var(--err)'
    if ($sc.Score -ge 80) { $color = 'var(--ok)' } elseif ($sc.Score -ge 50) { $color = 'var(--warn)' }
    $verdict = Get-CSWHwVerdictText -Score $sc.Score -Findings $all
    $sb = New-Object System.Text.StringBuilder
    $label = 'Puntuaci&oacute;n de salud del hardware'
    if ($sc.Partial) {
        $n = @($sc.Categories | Where-Object { $_.Checked }).Count
        $label += " (parcial: $n de $($sc.Categories.Count) componentes revisados)"
    }
    [void]$sb.Append("<div class='scorebox'><div class='gauge' style='--p:$([int]$sc.Score);--c:$color'><div><b>$([int]$sc.Score)</b><small>de 100</small></div></div>")
    [void]$sb.Append("<div class='verdict'><div class='muted' style='font-size:12px;font-weight:600'>$label</div><div class='vtxt'>$(ConvertTo-CSWHtmlText $verdict)</div></div></div>")

    [void]$sb.Append("<div class='kpis'>")
    foreach ($c in $sc.Categories) {
        $kc = 'var(--muted)'; $kcls = 'k-mute'
        switch ($c.Estado) { 'OK' { $kc = 'var(--ok)'; $kcls = 'k-ok' } 'Aviso' { $kc = 'var(--warn)'; $kcls = 'k-warn' } 'Fallo' { $kc = 'var(--err)'; $kcls = 'k-err' } }
        $txt = $c.Estado
        if ($c.Checked -and $c.Estado -ne 'Sin datos') { $txt = '{0}/{1}' -f $c.Points, $c.Weight }
        [void]$sb.Append("<div class='kpi $kcls'><b style='color:$kc'>$(ConvertTo-CSWHtmlText ([string]$txt))</b><span>$(ConvertTo-CSWHtmlText $c.Label) &middot; $(ConvertTo-CSWHtmlText $c.Estado)</span></div>")
    }
    [void]$sb.Append('</div>')

    $issues = @($all | Where-Object { ($_.Estado -eq 'Fallo' -or $_.Estado -eq 'Aviso') -and -not $_.EsVeredicto } | Sort-Object @{ Expression = { if ($_.Estado -eq 'Fallo') { 0 } else { 1 } } }, Categoria)
    [void]$sb.Append("<h3>Hallazgos y recomendaciones</h3>")
    if ($issues.Count) {
        [void]$sb.Append("<table><thead><tr><th style='width:150px'>Componente</th><th style='width:160px'>Prueba</th><th style='width:140px'>Valor</th><th style='width:80px'>Estado</th><th style='width:auto'>Recomendaci&oacute;n</th></tr></thead><tbody>")
        foreach ($f in $issues) {
            $rec = ConvertTo-CSWHtmlText $f.Recomendacion
            if ($f.Detalle) { $rec += "<br><span class='muted'>$(ConvertTo-CSWHtmlText $f.Detalle)</span>" }
            [void]$sb.Append(("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>" -f (ConvertTo-CSWHtmlText $f.Componente), (ConvertTo-CSWHtmlText $f.Prueba), (ConvertTo-CSWHtmlText $f.Valor), (Get-CSWHwBadge $f.Estado), $rec))
        }
        [void]$sb.Append('</tbody></table>')
    }
    else { [void]$sb.Append("<p><span class='badge ok'>OK</span> No se encontraron problemas en el hardware revisado.</p>") }

    # Resumen por disco (veredictos)
    $verd = @($all | Where-Object { $_.EsVeredicto -and $_.Categoria -eq 'Disco' })
    if ($verd.Count) {
        [void]$sb.Append("<h3>Discos</h3><table class='kv'>")
        foreach ($v in $verd) { [void]$sb.Append(("<tr><th>{0}</th><td>{1} {2}</td></tr>" -f (ConvertTo-CSWHtmlText $v.Componente), (Get-CSWHwBadge $v.Estado), (ConvertTo-CSWHtmlText $v.Valor))) }
        [void]$sb.Append('</table>')
    }

    $nodata = @($all | Where-Object { $_.Estado -eq 'Sin datos' })
    if ($nodata.Count) {
        $list = (@($nodata | ForEach-Object { '{0}: {1}' -f $_.Componente, $_.Prueba }) | Select-Object -Unique) -join '; '
        [void]$sb.Append("<p class='muted' style='margin-top:12px'>Sin datos disponibles (no penaliza): $(ConvertTo-CSWHtmlText $list)</p>")
    }
    [void]$sb.Append("<p class='muted'>Revisi&oacute;n realizada el $(Get-Date -Format 'dd\/MM\/yyyy HH:mm'). Pesos: discos 35, RAM 20, bater&iacute;a 15, CPU/t&eacute;rmico 15, gr&aacute;ficos 5, perif&eacute;ricos 10. Un fallo resta todo el peso del componente y un aviso la mitad.</p>")
    Add-CSWReportSection -Id 'HardwareHealth' -Title 'Salud del hardware' -Html $sb.ToString() -Order 20
}

function New-CSWHwCheckResult {
    # Guarda, actualiza el informe y construye el resumen de una accion individual
    param([Parameter(Mandatory)][string]$Check, [Parameter(Mandatory)][string]$Label, $Findings)
    $f = @($Findings)
    Save-CSWHwFindings -Check $Check -Findings $f
    try { Update-CSWHwReportSection } catch { Write-CSWLog "No se pudo actualizar la seccion del informe: $($_.Exception.Message)" -Level Warn }
    $rows = @($f | Where-Object { -not $_.EsVeredicto })
    $nf = @($rows | Where-Object { $_.Estado -eq 'Fallo' }).Count
    $na = @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count
    $nd = @($rows | Where-Object { $_.Estado -eq 'Sin datos' }).Count
    $w = Get-CSWHwWorst $rows
    $extra = ''
    if ($nd) { $extra = "; $nd prueba(s) sin datos" }
    switch ($w) {
        'Fallo' { return (New-CSWResult -Summary ("{0}: FALLO detectado ({1} fallo(s), {2} aviso(s){3})." -f $Label, $nf, $na, $extra) -Status Warn) }
        'Aviso' { return (New-CSWResult -Summary ("{0}: con observaciones ({1} aviso(s){2})." -f $Label, $na, $extra) -Status Warn) }
        'OK' { return (New-CSWResult -Summary ("{0}: correcto{1}." -f $Label, $extra)) }
        default { return (New-CSWResult -Summary ("{0}: no se pudieron obtener datos en este equipo." -f $Label) -Status Warn) }
    }
}

# ===========================================================================
# Acciones
# ===========================================================================
function Test-CSWHwDiskHealth {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwDiskFindings)
    $f
    $label = 'Salud de discos'
    $v = @($f | Where-Object { $_.EsVeredicto })
    if ($v.Count) { $label = "Salud de discos ($($v.Count) disco(s))" }
    New-CSWHwCheckResult -Check 'DiskHealth' -Label $label -Findings $f
}

function Test-CSWHwRamHealth {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwRamFindings)
    $f
    New-CSWHwCheckResult -Check 'RamHealth' -Label 'Salud de la RAM' -Findings $f
}

function Start-CSWHwMemoryTest {
    # Programa el Diagnostico de memoria de Windows (mdsched) para el proximo arranque, sin reiniciar
    [CmdletBinding()]
    param()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not (Test-Path $bcd)) { return (New-CSWResult -Summary 'No se encontro bcdedit.exe.' -Status Error) }
    Write-CSWLog 'Comprobando que el Diagnostico de memoria existe en el gestor de arranque...' -Level Step
    $code = Invoke-CSWExternal -FilePath $bcd -Arguments '/enum {memdiag}'
    if ($code -ne 0) { return (New-CSWResult -Summary 'El gestor de arranque no tiene el Diagnostico de memoria ({memdiag}).' -Status Error) }
    Write-CSWLog 'Programando el Diagnostico de memoria para el proximo arranque...' -Level Step
    $code = Invoke-CSWExternal -FilePath $bcd -Arguments '/bootsequence {memdiag} /addfirst'
    if ($code -ne 0) { return (New-CSWResult -Summary "No se pudo programar la prueba de memoria (bcdedit codigo $code)." -Status Error) }
    Write-CSWLog 'Prueba programada. NO se reinicia automaticamente: reinicie cuando el cliente lo permita.' -Level Ok
    Write-CSWLog 'La prueba tarda 10-30 min; el resultado se ve despues en "Salud de la RAM".' -Level Info
    New-CSWResult -Summary 'Prueba de memoria RAM programada para el proximo reinicio (pendiente de reiniciar).'
}

function Test-CSWHwBatteryHealth {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwBatteryFindings)
    $f
    New-CSWHwCheckResult -Check 'BatteryHealth' -Label 'Salud de la bateria' -Findings $f
}

function Test-CSWHwCpuHealth {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwCpuFindings)
    $f
    New-CSWHwCheckResult -Check 'CpuHealth' -Label 'Salud de la CPU' -Findings $f
}

function Test-CSWHwGpuHealth {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwGpuFindings)
    $f
    New-CSWHwCheckResult -Check 'GpuHealth' -Label 'Salud de los graficos' -Findings $f
}

function Test-CSWHwPowerThermal {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwPowerFindings)
    $f
    New-CSWHwCheckResult -Check 'PowerAndThermal' -Label 'Energia y termico' -Findings $f
}

function Test-CSWHwPeripherals {
    [CmdletBinding()]
    param()
    $f = @(Get-CSWHwPeripheralFindings)
    $f
    New-CSWHwCheckResult -Check 'PeripheralsHealth' -Label 'Perifericos' -Findings $f
}

function Invoke-CSWHwFullHealthCheck {
    [CmdletBinding()]
    param()
    Write-CSWLog '##### REVISION COMPLETA DE SALUD DEL HARDWARE #####' -Level Step
    $checks = @(
        @{ Check = 'DiskHealth'; Fn = 'Get-CSWHwDiskFindings'; Cat = 'Disco'; Label = 'Discos' },
        @{ Check = 'RamHealth'; Fn = 'Get-CSWHwRamFindings'; Cat = 'RAM'; Label = 'RAM' },
        @{ Check = 'BatteryHealth'; Fn = 'Get-CSWHwBatteryFindings'; Cat = 'Bateria'; Label = 'Bateria' },
        @{ Check = 'CpuHealth'; Fn = 'Get-CSWHwCpuFindings'; Cat = 'CPU'; Label = 'CPU' },
        @{ Check = 'GpuHealth'; Fn = 'Get-CSWHwGpuFindings'; Cat = 'GPU'; Label = 'Graficos' },
        @{ Check = 'PowerAndThermal'; Fn = 'Get-CSWHwPowerFindings'; Cat = 'CPU'; Label = 'Energia' },
        @{ Check = 'PeripheralsHealth'; Fn = 'Get-CSWHwPeripheralFindings'; Cat = 'Perifericos'; Label = 'Perifericos' }
    )
    $all = New-Object System.Collections.ArrayList
    foreach ($c in $checks) {
        $f = @()
        try { $f = @(& $c.Fn) }
        catch {
            Write-CSWLog ("Error interno en el chequeo {0}: {1}" -f $c.Label, $_.Exception.Message) -Level Warn
            $f = @(New-CSWHwFinding -Categoria $c.Cat -Componente $c.Label -Prueba 'Chequeo' -Valor 'Error al obtener datos' -Estado 'Sin datos' -Detalle (Get-CSWHwShortText $_.Exception.Message 120))
        }
        Save-CSWHwFindings -Check $c.Check -Findings $f
        foreach ($x in $f) { [void]$all.Add($x) }
    }
    Update-CSWHwReportSection
    $sc = Get-CSWHwScore $all
    foreach ($c in $sc.Categories) { Write-CSWLog ("{0,-14} {1,-10} {2}/{3} pts" -f $c.Label, $c.Estado, $c.Points, $c.Weight) -Level Info }
    @($all)
    $rows = @($all | Where-Object { -not $_.EsVeredicto })
    $nf = @($rows | Where-Object { $_.Estado -eq 'Fallo' }).Count
    $na = @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count
    $verdict = Get-CSWHwVerdictText -Score $sc.Score -Findings $all
    $sum = 'Salud del hardware: {0}/100. {1} ({2} fallo(s), {3} aviso(s))' -f $sc.Score, $verdict, $nf, $na
    if ($nf -or $na) { New-CSWResult -Summary $sum -Status Warn } else { New-CSWResult -Summary $sum }
}

# ===========================================================================
# Registro del modulo
# ===========================================================================
Register-CSWModule -Id 'Hardware' -Name 'Salud de hardware' -Order 15 -Icon 'hardware' `
    -Description 'Revisión profunda de discos, RAM, batería, CPU, gráficos y periféricos con veredicto' -Actions @(
    @{ Id = 'FullHealthCheck'; Name = 'Revisión completa de hardware'; Command = 'Invoke-CSWHwFullHealthCheck'; LongRunning = $true
        Description = 'Ejecuta todas las revisiones de hardware, calcula una puntuación 0-100 y la agrega al informe del cliente' },
    @{ Id = 'DiskHealth'; Name = 'Salud de discos (SMART)'; Command = 'Test-CSWHwDiskHealth'
        Description = 'Estado, SMART, desgaste, temperatura, errores y eventos de cada disco físico' },
    @{ Id = 'RamHealth'; Name = 'Salud de la RAM'; Command = 'Test-CSWHwRamHealth'
        Description = 'Módulos, ranuras, doble canal, uso, presión de memoria, prueba de memoria y errores WHEA' },
    @{ Id = 'ScheduleMemTest'; Name = 'Programar prueba de RAM'; Command = 'Start-CSWHwMemoryTest'; Risk = 'Medium'
        Description = 'Programa el Diagnóstico de memoria de Windows para el próximo reinicio (no reinicia)'
        ConfirmMessage = 'Se programará el Diagnóstico de memoria de Windows para el PRÓXIMO reinicio. El equipo no se reinicia ahora; cuando reinicie, la prueba durará 10-30 minutos antes de entrar a Windows. ¿Continuar?' },
    @{ Id = 'BatteryHealth'; Name = 'Salud de la batería'; Command = 'Test-CSWHwBatteryHealth'
        Description = 'Desgaste, ciclos y estado de la batería; genera el informe de batería de powercfg' },
    @{ Id = 'CpuHealth'; Name = 'Salud de la CPU'; Command = 'Test-CSWHwCpuHealth'
        Description = 'Carga, frecuencia real, throttling, temperaturas ACPI, errores WHEA y apagados inesperados' },
    @{ Id = 'GpuHealth'; Name = 'Salud de los gráficos'; Command = 'Test-CSWHwGpuHealth'
        Description = 'Adaptadores de video, antigüedad del driver, VRAM y reinicios del driver (TDR)' },
    @{ Id = 'PowerAndThermal'; Name = 'Energía y térmico'; Command = 'Test-CSWHwPowerThermal'
        Description = 'Plan de energía, hibernación, último apagado/arranque, ventiladores y fuente de alimentación' },
    @{ Id = 'PeripheralsHealth'; Name = 'Periféricos y dispositivos'; Command = 'Test-CSWHwPeripherals'
        Description = 'Dispositivos con error en el Administrador de dispositivos, USB, audio y red' }
)
Export-ModuleMember -Function *
