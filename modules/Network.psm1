#Requires -Version 5.1
<#
    Cybersutro win - Modulo Red (Network)
    Diagnostico y reparacion de conectividad: ping, test integral, DNS, IP, Winsock,
    puertos, escaneo de subred, WiFi, proxy, velocidad e IP publica.
    Compatible con Windows PowerShell 5.1 y PowerShell 7. Ver docs/CONTRATO.md.
#>

Set-StrictMode -Version 2.0

# ===========================================================================
# Utilidades internas
# ===========================================================================
function ConvertTo-CSWNetBool {
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $Default }
    return ($t -match '^(1|true|\$true|si|s|yes|y)$')
}

function Get-CSWNetErrorText {
    param($ErrorRecord)
    $e = $null
    if ($ErrorRecord -is [System.Exception]) { $e = $ErrorRecord } else { $e = $ErrorRecord.Exception }
    while ($null -ne $e.InnerException) { $e = $e.InnerException }
    return $e.Message
}

function Enable-CSWNetTls {
    try {
        $p = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $p -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }
}

function Format-CSWNetSpeed {
    param($Bps)
    if ($null -eq $Bps) { return '' }
    $v = [double]$Bps
    if ($v -le 0 -or $v -ge 9e18) { return '' }
    if ($v -ge 1e9) { return ('{0:N1} Gbps' -f ($v / 1e9)) }
    return ('{0:N0} Mbps' -f ($v / 1e6))
}

function Test-CSWNetApipa {
    param([string]$Ip)
    return ($Ip -like '169.254.*')
}

function Get-CSWNetAdapters {
    <# Adaptadores con IP habilitada (Win32_NetworkAdapterConfiguration + Win32_NetworkAdapter). #>
    $cfgs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
    $nics = @{}
    foreach ($n in @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue)) { $nics[[int]$n.Index] = $n }
    foreach ($c in $cfgs) {
        $n = $null
        if ($nics.ContainsKey([int]$c.Index)) { $n = $nics[[int]$c.Index] }
        $ips = @($c.IPAddress | Where-Object { $_ })
        $masks = @($c.IPSubnet | Where-Object { $_ })
        $ipv4 = New-Object System.Collections.ArrayList
        $ipv6 = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $ips.Count; $i++) {
            if ($ips[$i] -match '^\d+\.\d+\.\d+\.\d+$') {
                $m = ''; if ($i -lt $masks.Count) { $m = $masks[$i] }
                [void]$ipv4.Add([pscustomobject]@{ Ip = $ips[$i]; Mask = $m })
            }
            else { [void]$ipv6.Add($ips[$i]) }
        }
        $gw = @($c.DefaultIPGateway | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
        $name = ''; $speed = $null; $physical = $false; $status = $null
        if ($n) {
            $name = [string]$n.NetConnectionID
            $speed = $n.Speed
            $physical = [bool]$n.PhysicalAdapter
            if (([string]$c.Description + ' ' + [string]$n.Name) -match 'VMware|VirtualBox|Hyper-V|Virtual|Tailscale|TAP-|WireGuard|ZeroTier|OpenVPN|Fortinet|Npcap|Loopback|VPN|Wintun|Teredo|Bluetooth') { $physical = $false }
            $status = $n.NetConnectionStatus
        }
        if (-not $name) { $name = [string]$c.Description }
        $lease = ''
        if ($c.DHCPEnabled -and $c.DHCPLeaseExpires) { try { $lease = ([datetime]$c.DHCPLeaseExpires).ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) } catch { } }
        [pscustomobject]@{
            Name        = $name
            Description = [string]$c.Description
            Index       = [int]$c.Index
            IfIndex     = [int]$c.InterfaceIndex
            Mac         = [string]$c.MACAddress
            IPv4        = @($ipv4)
            IPv6        = @($ipv6)
            Gateways    = $gw
            Dns         = @($c.DNSServerSearchOrder | Where-Object { $_ })
            DnsSuffix   = [string]$c.DNSDomain
            Dhcp        = [bool]$c.DHCPEnabled
            DhcpServer  = [string]$c.DHCPServer
            LeaseExpires = $lease
            Speed       = $speed
            Physical    = $physical
            Status      = $status
            IsWifi      = ($c.Description -match 'Wi-?Fi|Wireless|WLAN|802\.11' -or $name -match 'Wi-?Fi|WLAN|inalambrica')
        }
    }
}

function Get-CSWNetPrimaryAdapter {
    $all = @(Get-CSWNetAdapters)
    $best = @($all | Where-Object { $_.Gateways.Count -gt 0 -and @($_.IPv4 | Where-Object { -not (Test-CSWNetApipa $_.Ip) }).Count -gt 0 })
    if ($best.Count) {
        # Preferir fisico y el de menor metrica (aproximado por orden de Windows)
        $phys = @($best | Where-Object { $_.Physical })
        if ($phys.Count) { return $phys[0] }
        return $best[0]
    }
    return $null
}

function Test-CSWNetIcmp {
    param([string]$Target, [int]$Count = 3, [int]$TimeoutMs = 1000)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $times = New-Object System.Collections.ArrayList
    $last = ''
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $r = $ping.Send($Target, $TimeoutMs)
                $last = [string]$r.Status
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { [void]$times.Add([int]$r.RoundtripTime) }
            }
            catch { $last = Get-CSWNetErrorText $_ }
        }
    }
    finally { $ping.Dispose() }
    $avg = $null
    if ($times.Count) { $avg = [int](($times | Measure-Object -Average).Average) }
    return [pscustomobject]@{ Target = $Target; Sent = $Count; Received = $times.Count; AvgMs = $avg; LastStatus = $last }
}

function Invoke-CSWNetHttpGet {
    param([string]$Url, [int]$TimeoutMs = 8000, [string]$Method = 'GET')
    Enable-CSWNetTls
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $null
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Method = $Method
        $req.Timeout = $TimeoutMs
        try { $req.ReadWriteTimeout = $TimeoutMs; $req.UserAgent = 'CybersutroWin/1.0' } catch { }
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $sr.Close()
        return [pscustomobject]@{ Ok = $true; Status = [int]$resp.StatusCode; Body = $body; Ms = [int]$sw.ElapsedMilliseconds; Error = '' }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Status = 0; Body = ''; Ms = [int]$sw.ElapsedMilliseconds; Error = (Get-CSWNetErrorText $_) }
    }
    finally { if ($resp) { try { $resp.Close() } catch { } } }
}

function Resolve-CSWNetName {
    <# Resuelve un nombre (opcionalmente contra un servidor DNS concreto). Devuelve IPv4 o $null. #>
    param([string]$Name, [string]$Server = '')
    $haveCmd = [bool](Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)
    if ($haveCmd) {
        try {
            $p = @{ Name = $Name; Type = 'A'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($Server) { $p.Server = $Server }
            $r = @(Resolve-DnsName @p | Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress -match '^\d+\.\d+\.\d+\.\d+$' })
            if ($r.Count) { return @($r | ForEach-Object { $_.IPAddress }) }
            return $null
        }
        catch { return $null }
    }
    if ($Server) { return $null }
    try { return @([System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) }
    catch { return $null }
}

function Get-CSWNetUserHives {
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

function Get-CSWNetCommandOutput {
    <# Ejecuta un comando y devuelve su salida como texto (sin volcarla al log). #>
    # Usa el nucleo: entrada estandar cerrada y tiempo maximo (un netsh/arp colgado no bloquea la GUI)
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds = 60)
    return (Get-CSWExternalOutput -FilePath $FilePath -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds)
}

function Backup-CSWNetConfig {
    <# Guarda la configuracion de red actual en Backups antes de un reset. Devuelve la ruta. #>
    $path = Join-Path (Get-CSWDataPath Backups) ('Red_{0}_{1:yyyyMMdd_HHmmss}.txt' -f $env:COMPUTERNAME, (Get-Date))
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Copia de configuracion de red - $env:COMPUTERNAME - $(Get-Date -Format 'dd\/MM\/yyyy HH:mm:ss')")
    foreach ($cmd in @(
            @('ipconfig.exe', '/all'),
            @('netsh.exe', 'interface ipv4 show config'),
            @('netsh.exe', 'winhttp show proxy'),
            @('route.exe', 'print -4'))) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("===== $($cmd[0]) $($cmd[1]) =====")
        try { [void]$sb.AppendLine((Get-CSWNetCommandOutput -FilePath $cmd[0] -Arguments $cmd[1])) } catch { [void]$sb.AppendLine("Error: $($_.Exception.Message)") }
    }
    Set-Content -Path $path -Value $sb.ToString() -Encoding UTF8
    Write-CSWLog "Copia de la configuracion de red guardada en: $path" -Level Ok

    # Avisar de IPs estaticas: 'netsh int ip reset' las borra
    try {
        foreach ($a in @(Get-CSWNetAdapters)) {
            if (-not $a.Dhcp -and $a.IPv4.Count) {
                $ipTxt = (($a.IPv4 | ForEach-Object { "$($_.Ip)/$($_.Mask)" }) -join ', ')
                Write-CSWLog ("IP ESTATICA en '{0}': {1} | GW {2} | DNS {3}. Puede perderse con el reset: anotela para reconfigurarla." -f $a.Name, $ipTxt, ($a.Gateways -join ','), ($a.Dns -join ',')) -Level Warn
            }
        }
    }
    catch { }
    return $path
}

function Get-CSWNetXmlText {
    param([xml]$Xml, [string]$LocalName)
    $n = $Xml.SelectSingleNode("//*[local-name()='$LocalName']")
    if ($n) { return [string]$n.InnerText }
    return ''
}

function Test-CSWNetWlanService {
    $svc = Get-Service -Name 'WlanSvc' -ErrorAction SilentlyContinue
    if (-not $svc) { return 'El equipo no tiene el servicio WiFi (WLAN AutoConfig): sin adaptador inalambrico.' }
    if ($svc.Status -ne 'Running') { return 'El servicio WiFi (WLAN AutoConfig) esta detenido.' }
    return ''
}

# ===========================================================================
# Ping
# ===========================================================================
function Test-CSWNetPing {
    [CmdletBinding()]
    param([string]$Target = '8.8.8.8', [int]$Count = 4)
    if (-not $Target) { $Target = '8.8.8.8' }
    $Target = $Target.Trim()
    if (-not (Test-CSWHostName $Target)) { return (New-CSWResult -Summary "Host o IP no valido: '$Target'" -Status Error) }
    if ($Count -lt 1) { $Count = 1 }
    if ($Count -gt 100) { $Count = 100 }
    Write-CSWLog "Haciendo ping a $Target ($Count paquetes)..." -Level Step
    $addr = $Target
    if ($Target -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $Target -notmatch ':') {
        $r = Resolve-CSWNetName $Target
        if (-not $r) {
            return (New-CSWResult -Summary "No se pudo resolver el nombre '$Target' (fallo de DNS o nombre incorrecto)." -Status Error)
        }
        $addr = @($r)[0]
        Write-CSWLog "$Target = $addr" -Level Info
    }
    $ping = New-Object System.Net.NetworkInformation.Ping
    $times = New-Object System.Collections.ArrayList
    try {
        for ($i = 1; $i -le $Count; $i++) {
            try {
                $r = $ping.Send($addr, 2000)
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    [void]$times.Add([int]$r.RoundtripTime)
                    $ttl = ''; if ($r.Options) { $ttl = $r.Options.Ttl }
                    Write-CSWLog ("Respuesta de {0}: tiempo={1} ms TTL={2}" -f $r.Address, $r.RoundtripTime, $ttl) -Level Data
                }
                else { Write-CSWLog ("Sin respuesta ({0})" -f $r.Status) -Level Data }
            }
            catch { Write-CSWLog ("Error: {0}" -f (Get-CSWNetErrorText $_)) -Level Data }
            if ($i -lt $Count) { Start-Sleep -Milliseconds 400 }
        }
    }
    finally { $ping.Dispose() }

    $recv = $times.Count
    $lost = [math]::Round((($Count - $recv) / $Count) * 100, 0)
    if (-not $recv) { return (New-CSWResult -Summary "$Target no responde ($Count paquetes perdidos)." -Status Warn) }
    $st = $times | Measure-Object -Average -Minimum -Maximum
    $jitter = 0
    if ($recv -gt 1) {
        $d = 0; for ($i = 1; $i -lt $recv; $i++) { $d += [math]::Abs($times[$i] - $times[$i - 1]) }
        $jitter = [math]::Round($d / ($recv - 1), 1)
    }
    [pscustomobject]@{ Destino = $Target; IP = $addr; Enviados = $Count; Recibidos = $recv; 'Perdida %' = $lost; 'Min ms' = $st.Minimum; 'Media ms' = [math]::Round($st.Average, 0); 'Max ms' = $st.Maximum; 'Jitter ms' = $jitter }
    $sum = "$Target responde: media $([math]::Round($st.Average,0)) ms, perdida $lost%."
    if ($lost -gt 0 -or $st.Average -gt 150) { return (New-CSWResult -Summary "$sum Conexion inestable o lenta." -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Test de conectividad integral (ID obligatorio: Network.ConnectivityTest)
# ===========================================================================
function Test-CSWNetConnectivity {
    [CmdletBinding()]
    param()
    $rows = New-Object System.Collections.ArrayList
    $add = {
        param($Test, $Res, $Detail, $Ms)
        [void]$rows.Add([pscustomobject]@{ Prueba = $Test; Resultado = $Res; Detalle = $Detail; Ms = $Ms })
        $lvl = 'Ok'; if ($Res -eq 'FALLO') { $lvl = 'Error' } elseif ($Res -eq 'AVISO') { $lvl = 'Warn' }
        Write-CSWLog ("[{0}] {1}: {2}" -f $Res, $Test, $Detail) -Level $lvl
    }

    # 1. Adaptador / IP
    Write-CSWLog '1/5 Adaptador de red y direccion IP' -Level Step
    $adapters = @()
    try { $adapters = @(Get-CSWNetAdapters) } catch { Write-CSWLog "No se pudo leer la configuracion IP: $($_.Exception.Message)" -Level Error }
    $primary = Get-CSWNetPrimaryAdapter
    if (-not $primary) {
        $apipa = @($adapters | Where-Object { @($_.IPv4 | Where-Object { Test-CSWNetApipa $_.Ip }).Count })
        if ($apipa.Count) {
            & $add 'Direccion IP' 'FALLO' ("'{0}' tiene IP automatica 169.254.x.x: el router/DHCP no responde" -f $apipa[0].Name) $null
            $rows | Select-Object Prueba, Resultado, Detalle
            return (New-CSWResult -Summary 'Sin conexion: el equipo no obtiene IP del router (DHCP). Revise cable/WiFi o reinicie el router.' -Status Error)
        }
        & $add 'Direccion IP' 'FALLO' 'Ningun adaptador conectado con IP y puerta de enlace' $null
        $rows | Select-Object Prueba, Resultado, Detalle
        return (New-CSWResult -Summary 'Sin conexion de red: no hay ningun adaptador conectado (revise cable, WiFi o modo avion).' -Status Error)
    }
    $myIp = @($primary.IPv4 | Where-Object { -not (Test-CSWNetApipa $_.Ip) })[0].Ip
    $gw = $primary.Gateways[0]
    $conn = 'cable'; if ($primary.IsWifi) { $conn = 'WiFi' }
    & $add 'Direccion IP' 'OK' ("{0} ({1}): IP {2}, gateway {3}, DNS {4}" -f $primary.Name, $conn, $myIp, $gw, ($primary.Dns -join ', ')) $null

    # 2. Gateway
    Write-CSWLog '2/5 Puerta de enlace (router)' -Level Step
    $g = Test-CSWNetIcmp -Target $gw -Count 4 -TimeoutMs 1000
    $gwOk = ($g.Received -gt 0)
    if ($gwOk) {
        $res = 'OK'; if ($g.Received -lt $g.Sent) { $res = 'AVISO' }
        & $add 'Router (gateway)' $res ("{0} responde {1}/{2}, media {3} ms" -f $gw, $g.Received, $g.Sent, $g.AvgMs) $g.AvgMs
    }
    else { & $add 'Router (gateway)' 'FALLO' ("{0} no responde al ping ({1})" -f $gw, $g.LastStatus) $null }

    # 3. Internet por IP
    Write-CSWLog '3/5 Salida a Internet por IP (1.1.1.1 y 8.8.8.8)' -Level Step
    $netOk = $false; $netMs = $null
    foreach ($t in '1.1.1.1', '8.8.8.8') {
        $p = Test-CSWNetIcmp -Target $t -Count 3 -TimeoutMs 1500
        if ($p.Received -gt 0) {
            $netOk = $true; if ($null -eq $netMs) { $netMs = $p.AvgMs }
            $res = 'OK'; if ($p.Received -lt $p.Sent) { $res = 'AVISO' }
            & $add "Internet ($t)" $res ("responde {0}/{1}, media {2} ms" -f $p.Received, $p.Sent, $p.AvgMs) $p.AvgMs
        }
        else { & $add "Internet ($t)" 'FALLO' ("sin respuesta ({0})" -f $p.LastStatus) $null }
    }

    # 4. DNS
    Write-CSWLog '4/5 Resolucion DNS (microsoft.com)' -Level Step
    $dnsOk = $false; $dnsBadServers = New-Object System.Collections.ArrayList
    $servers = @($primary.Dns)
    if ($servers.Count) {
        foreach ($s in $servers) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Resolve-CSWNetName -Name 'microsoft.com' -Server $s
            $ms = [int]$sw.ElapsedMilliseconds
            if ($r) { $dnsOk = $true; & $add "DNS $s" 'OK' ("microsoft.com = {0}" -f (@($r)[0])) $ms }
            else { [void]$dnsBadServers.Add($s); & $add "DNS $s" 'FALLO' 'no resuelve microsoft.com' $ms }
        }
    }
    if (-not $servers.Count -or -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Resolve-CSWNetName -Name 'microsoft.com'
        if ($r) { $dnsOk = $true; & $add 'DNS del sistema' 'OK' ("microsoft.com = {0}" -f (@($r)[0])) ([int]$sw.ElapsedMilliseconds) }
        else { & $add 'DNS del sistema' 'FALLO' 'no resuelve microsoft.com' $null }
    }
    $publicDnsOk = $false
    if (-not $dnsOk -and $netOk) {
        $r = Resolve-CSWNetName -Name 'microsoft.com' -Server '1.1.1.1'
        if ($r) { $publicDnsOk = $true; & $add 'DNS publico 1.1.1.1' 'OK' 'resuelve correctamente (el DNS configurado es el problema)' $null }
        else { & $add 'DNS publico 1.1.1.1' 'FALLO' 'tampoco resuelve (DNS bloqueado por firewall/proveedor?)' $null }
    }

    # 5. Web: sonda NCSI de Windows (solo HTTP: el host msftconnecttest.com no tiene certificado HTTPS valido)
    #    + HTTPS real con validacion de certificado contra www.microsoft.com
    Write-CSWLog '5/5 Navegacion web (sonda NCSI de Windows y HTTPS)' -Level Step
    $httpsOk = $false; $captive = $false; $webOk = $false
    $h = Invoke-CSWNetHttpGet -Url 'http://www.msftconnecttest.com/connecttest.txt' -TimeoutMs 10000
    if ($h.Ok -and $h.Body -match 'Microsoft Connect Test') { $webOk = $true; & $add 'Web (NCSI)' 'OK' ("connecttest.txt correcto en {0} ms" -f $h.Ms) $h.Ms }
    elseif ($h.Ok) { $captive = $true; & $add 'Web (NCSI)' 'AVISO' 'respuesta inesperada: portal cautivo (hotel/wifi publica) o proxy que intercepta' $h.Ms }
    else { & $add 'Web (NCSI)' 'FALLO' $h.Error $h.Ms }
    $s = Invoke-CSWNetHttpGet -Url 'https://www.microsoft.com/' -TimeoutMs 10000 -Method 'HEAD'
    if ($s.Ok) { $httpsOk = $true; & $add 'HTTPS' 'OK' ("www.microsoft.com con certificado valido en {0} ms" -f $s.Ms) $s.Ms }
    else {
        $d = $s.Error
        if ($d -match 'certific|SSL|TLS|confianza|trust') { $d = "$d (fecha/hora incorrecta, antivirus que inspecciona HTTPS o interceptacion)" }
        & $add 'HTTPS' 'FALLO' $d $s.Ms
    }

    $rows | Select-Object Prueba, Resultado, Detalle, Ms

    # Diagnostico final
    if ($httpsOk -and $dnsOk) {
        $extra = ''
        if (-not $gwOk) { $extra = ' (el router no responde a ping, normal en algunos modelos)' }
        if ($dnsBadServers.Count) { return (New-CSWResult -Summary ("Internet funciona, pero el servidor DNS {0} no responde; conviene revisar la configuracion DNS." -f ($dnsBadServers -join ', ')) -Status Warn) }
        $lat = ''; if ($null -ne $netMs) { $lat = ", latencia $netMs ms" }
        return (New-CSWResult -Summary "Conexion a Internet correcta via $conn (IP $myIp$lat)$extra.")
    }
    if (-not $gwOk -and -not $netOk -and -not $httpsOk) {
        return (New-CSWResult -Summary "Fallo en la red local: no hay comunicacion con el router ($gw). Revise cable/WiFi o reinicie el router." -Status Error)
    }
    if (-not $netOk -and -not $httpsOk) {
        return (New-CSWResult -Summary 'El router responde pero no hay salida a Internet: problema del router o del proveedor (ISP).' -Status Error)
    }
    if (-not $dnsOk) {
        if ($publicDnsOk) { return (New-CSWResult -Summary ("Internet funciona por IP pero falla el DNS configurado ({0}). Solucion: cambiar DNS (p.ej. 1.1.1.1/8.8.8.8) o reiniciar el router." -f ($servers -join ', ')) -Status Error) }
        return (New-CSWResult -Summary 'Internet funciona por IP pero no se resuelven nombres (DNS). Pruebe Vaciar DNS o cambiar de servidor DNS.' -Status Error)
    }
    if ($captive) { return (New-CSWResult -Summary 'Hay conexion pero la red intercepta la navegacion (portal cautivo o proxy): abra el navegador para iniciar sesion en la red.' -Status Warn) }
    New-CSWResult -Summary 'Ping y DNS correctos pero falla HTTPS: posible proxy, firewall, antivirus o fecha/hora incorrecta del equipo.' -Status Error
}

# ===========================================================================
# Traceroute (implementacion propia con TTL, mas rapida y estructurada que tracert)
# ===========================================================================
function Test-CSWNetTraceroute {
    [CmdletBinding()]
    param([string]$Target = '8.8.8.8', [int]$MaxHops = 30, [object]$ResolveNames = $true)
    if (-not $Target) { $Target = '8.8.8.8' }
    $Target = $Target.Trim()
    if (-not (Test-CSWHostName $Target)) { return (New-CSWResult -Summary "Host o IP no valido: '$Target'" -Status Error) }
    $resolve = ConvertTo-CSWNetBool $ResolveNames $true
    if ($MaxHops -lt 1 -or $MaxHops -gt 64) { $MaxHops = 30 }
    $addr = $Target
    if ($Target -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        $r = Resolve-CSWNetName $Target
        if (-not $r) { return (New-CSWResult -Summary "No se pudo resolver '$Target'." -Status Error) }
        $addr = @($r)[0]
    }
    Write-CSWLog "Trazando ruta a $Target [$addr], maximo $MaxHops saltos..." -Level Step
    $ping = New-Object System.Net.NetworkInformation.Ping
    $buffer = New-Object byte[] 32
    $rows = New-Object System.Collections.ArrayList
    $reached = $false; $consecutiveTimeouts = 0
    try {
        for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
            $opt = New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)
            $hopIp = ''; $times = New-Object System.Collections.ArrayList; $status = ''
            for ($try = 0; $try -lt 3; $try++) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $rep = $ping.Send($addr, 1000, $buffer, $opt)
                    $ms = [int]$sw.ElapsedMilliseconds
                    $status = [string]$rep.Status
                    if ($rep.Status -eq [System.Net.NetworkInformation.IPStatus]::Success -or $rep.Status -eq [System.Net.NetworkInformation.IPStatus]::TtlExpired) {
                        $hopIp = [string]$rep.Address
                        if ($rep.Status -eq [System.Net.NetworkInformation.IPStatus]::Success -and $rep.RoundtripTime -gt 0) { $ms = [int]$rep.RoundtripTime }
                        [void]$times.Add($ms)
                    }
                }
                catch { $status = Get-CSWNetErrorText $_ }
            }
            $name = ''
            if ($hopIp -and $resolve) {
                try {
                    $task = [System.Net.Dns]::GetHostEntryAsync($hopIp)
                    if ($task.Wait(1500)) { $name = $task.Result.HostName }
                }
                catch { }
            }
            $msTxt = '*'
            if ($times.Count) { $msTxt = (($times | ForEach-Object { "$_" }) -join ' / ') }
            $ipTxt = $hopIp; if (-not $ipTxt) { $ipTxt = '(sin respuesta)' }
            Write-CSWLog ("{0,2}  {1,-15}  {2,-14}  {3}" -f $ttl, $ipTxt, $msTxt, $name) -Level Data
            $avg = $null; if ($times.Count) { $avg = [int](($times | Measure-Object -Average).Average) }
            [void]$rows.Add([pscustomobject]@{ Salto = $ttl; IP = $ipTxt; 'Media ms' = $avg; Nombre = $name })
            if ($hopIp) { $consecutiveTimeouts = 0 } else { $consecutiveTimeouts++ }
            if ($hopIp -eq $addr) { $reached = $true; break }
            if ($consecutiveTimeouts -ge 6) { Write-CSWLog '6 saltos seguidos sin respuesta: se detiene la traza.' -Level Warn; break }
        }
    }
    finally { $ping.Dispose() }

    if ($reached) { return (New-CSWResult -Summary "Ruta a $Target completada en $($rows.Count) saltos.") }
    $lastOk = @($rows | Where-Object { $_.IP -ne '(sin respuesta)' } | Select-Object -Last 1)
    $where = 'ningun salto responde'
    if ($lastOk.Count) { $where = "ultimo salto que responde: $($lastOk[0].IP) (salto $($lastOk[0].Salto))" }
    New-CSWResult -Summary "No se alcanzo $Target; $where. Algunos destinos bloquean ICMP." -Status Warn
}

# ===========================================================================
# Vaciar DNS (ID obligatorio: Network.FlushDns)
# ===========================================================================
function Clear-CSWNetDnsCache {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Vaciando la cache DNS del equipo...' -Level Step
    $before = $null
    if (Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue) {
        try { $before = @(Get-DnsClientCache -ErrorAction Stop).Count; Write-CSWLog "Entradas en cache antes: $before" -Level Info } catch { }
    }
    $okCmd = $false
    if (Get-Command -Name Clear-DnsClientCache -ErrorAction SilentlyContinue) {
        try { Clear-DnsClientCache -ErrorAction Stop; $okCmd = $true; Write-CSWLog 'Clear-DnsClientCache completado.' -Level Ok }
        catch { Write-CSWLog "Clear-DnsClientCache fallo: $($_.Exception.Message)" -Level Warn }
    }
    $code = Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/flushdns'
    if ($code -eq 0 -or $okCmd) {
        $txt = 'Cache DNS vaciada correctamente'
        if ($null -ne $before) { $txt += " ($before entradas eliminadas)" }
        return (New-CSWResult -Summary "$txt.")
    }
    New-CSWResult -Summary "No se pudo vaciar la cache DNS (ipconfig codigo $code)." -Status Error
}

# ===========================================================================
# Configuracion IP
# ===========================================================================
function Get-CSWNetIpConfig {
    [CmdletBinding()]
    param([object]$IncludeVirtual = $true)
    $incVirt = ConvertTo-CSWNetBool $IncludeVirtual $true
    Write-CSWLog 'Leyendo configuracion IP de los adaptadores...' -Level Step
    try { $all = @(Get-CSWNetAdapters) }
    catch { return (New-CSWResult -Summary "No se pudo leer la configuracion de red: $($_.Exception.Message)" -Status Error) }
    if (-not $incVirt) { $all = @($all | Where-Object { $_.Physical }) }
    if (-not $all.Count) { return (New-CSWResult -Summary 'No hay adaptadores de red con IP activa.' -Status Warn) }
    $all = @($all | Sort-Object { if ($_.Gateways.Count) { 0 } else { 1 } }, { if ($_.Physical) { 0 } else { 1 } })

    $wifi = $null
    if (@($all | Where-Object { $_.IsWifi }).Count -and -not (Test-CSWNetWlanService)) {
        try {
            $txt = Get-CSWNetCommandOutput -FilePath 'netsh.exe' -Arguments 'wlan show interfaces'
            $ssid = ''; $bssid = ''; $signal = ''; $radio = ''
            foreach ($l in ($txt -split "`r?`n")) {
                if (-not $ssid -and $l -match '^\s*SSID\s*:\s*(.+)$') { $ssid = $Matches[1].Trim() }
                elseif (-not $bssid -and $l -match '^\s*(AP )?BSSID\s*:\s*(.+)$') { $bssid = $Matches[2].Trim() }
                elseif (-not $signal -and $l -match ':\s*(\d{1,3})\s*%\s*$') { $signal = $Matches[1] }
                if (-not $radio -and $l -match '(802\.11\w+)') { $radio = $Matches[1] }
            }
            if ($ssid) { $wifi = [pscustomobject]@{ Ssid = $ssid; Bssid = $bssid; Signal = $signal; Radio = $radio } }
        }
        catch { }
    }

    $warn = New-Object System.Collections.ArrayList
    foreach ($a in $all) {
        Write-CSWLog ("Adaptador: {0}" -f $a.Name) -Level Step
        $kind = 'Virtual'; if ($a.Physical) { $kind = 'Fisico' }
        if ($a.IsWifi) { $kind += ' WiFi' }
        Write-CSWLog ("  Descripcion  : {0} ({1})" -f $a.Description, $kind) -Level Data
        Write-CSWLog ("  MAC          : {0}" -f $a.Mac) -Level Data
        foreach ($ip in $a.IPv4) {
            Write-CSWLog ("  IPv4         : {0}  mascara {1}" -f $ip.Ip, $ip.Mask) -Level Data
            if (Test-CSWNetApipa $ip.Ip) { [void]$warn.Add("$($a.Name) sin DHCP (169.254)") }
        }
        foreach ($ip in $a.IPv6) { Write-CSWLog ("  IPv6         : {0}" -f $ip) -Level Data }
        Write-CSWLog ("  Gateway      : {0}" -f ($a.Gateways -join ', ')) -Level Data
        Write-CSWLog ("  DNS          : {0}" -f ($a.Dns -join ', ')) -Level Data
        $dh = 'No (IP estatica)'
        if ($a.Dhcp) { $dh = "Si (servidor $($a.DhcpServer), concesion hasta $($a.LeaseExpires))" }
        Write-CSWLog ("  DHCP         : {0}" -f $dh) -Level Data
        if ($a.DnsSuffix) { Write-CSWLog ("  Sufijo DNS   : {0}" -f $a.DnsSuffix) -Level Data }
        $sp = Format-CSWNetSpeed $a.Speed
        if ($sp) { Write-CSWLog ("  Velocidad    : {0}" -f $sp) -Level Data }
        if ($a.IsWifi -and $wifi) {
            Write-CSWLog ("  WiFi         : SSID '{0}', senal {1}%, {2}, AP {3}" -f $wifi.Ssid, $wifi.Signal, $wifi.Radio, $wifi.Bssid) -Level Data
            if ($wifi.Signal -and [int]$wifi.Signal -lt 50) { [void]$warn.Add("senal WiFi debil ($($wifi.Signal)%)") }
        }
        if ($a.Physical -and -not $a.IsWifi -and $a.Gateways.Count -and $null -ne $a.Speed -and [double]$a.Speed -gt 0 -and [double]$a.Speed -lt 1e9 -and [double]$a.Speed -ge 1e6) {
            if ([double]$a.Speed -le 100e6) { [void]$warn.Add("$($a.Name) enlazado a $sp (revise cable o puerto)") }
        }
    }

    $all | ForEach-Object {
        [pscustomobject]@{
            Adaptador = $_.Name
            IPv4      = (($_.IPv4 | ForEach-Object { $_.Ip }) -join ', ')
            Mascara   = (($_.IPv4 | ForEach-Object { $_.Mask }) -join ', ')
            Gateway   = ($_.Gateways -join ', ')
            DNS       = ($_.Dns -join ', ')
            DHCP      = $(if ($_.Dhcp) { 'Si' } else { 'No' })
            MAC       = $_.Mac
            Velocidad = (Format-CSWNetSpeed $_.Speed)
        }
    }

    $p = Get-CSWNetPrimaryAdapter
    $sum = "$($all.Count) adaptador(es) con IP."
    if ($p) {
        $pip = @($p.IPv4 | Where-Object { -not (Test-CSWNetApipa $_.Ip) })[0].Ip
        $sum = "Conexion principal '$($p.Name)': IP $pip, gateway $($p.Gateways[0]), DNS $($p.Dns -join ', ')."
    }
    else { [void]$warn.Add('ningun adaptador tiene puerta de enlace') }
    if ($warn.Count) { return (New-CSWResult -Summary ("$sum Atencion: " + ($warn -join '; ') + '.') -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Renovar IP
# ===========================================================================
function Update-CSWNetIpLease {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Liberando la IP de los adaptadores DHCP (la conexion se cortara unos segundos)...' -Level Step
    [void](Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/release')
    Start-Sleep -Seconds 2
    Write-CSWLog 'Solicitando nueva IP al servidor DHCP...' -Level Step
    $code = Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/renew'
    Start-Sleep -Seconds 2
    $p = $null
    try { $p = Get-CSWNetPrimaryAdapter } catch { }
    if ($p) {
        $pip = @($p.IPv4 | Where-Object { -not (Test-CSWNetApipa $_.Ip) })[0].Ip
        return (New-CSWResult -Summary "IP renovada: '$($p.Name)' tiene IP $pip (gateway $($p.Gateways[0]))." -Status $(if ($code -eq 0) { 'OK' } else { 'Warn' }))
    }
    New-CSWResult -Summary 'Se renovo la IP pero ningun adaptador obtuvo una direccion valida: el router/DHCP no responde.' -Status Error
}

# ===========================================================================
# Reset Winsock + TCP/IP
# ===========================================================================
function Reset-CSWNetStack {
    [CmdletBinding()]
    param()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    [void](Backup-CSWNetConfig)
    $fails = 0
    Write-CSWLog 'Restableciendo catalogo Winsock...' -Level Step
    if ((Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'winsock reset') -ne 0) { $fails++ }
    $log = Join-Path (Get-CSWDataPath Logs) ('netsh_ip_reset_{0:yyyyMMdd_HHmmss}.txt' -f (Get-Date))
    Write-CSWLog 'Restableciendo pila TCP/IP v4...' -Level Step
    if ((Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments ('int ipv4 reset "{0}"' -f $log)) -ne 0) { Write-CSWLog 'Algunos valores no se pudieron restablecer (habitual: "Acceso denegado" en claves protegidas).' -Level Info }
    Write-CSWLog 'Restableciendo pila TCP/IP v6...' -Level Step
    [void](Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'int ipv6 reset')
    if ($fails) { return (New-CSWResult -Summary 'El reset de Winsock fallo; revise el registro. Reinicie el equipo igualmente.' -Status Warn) }
    New-CSWResult -Summary 'Winsock y TCP/IP restablecidos. Es NECESARIO REINICIAR el equipo para aplicar los cambios.' -Status Warn
}

# ===========================================================================
# Reset completo de la red (sin tocar el firewall)
# ===========================================================================
function Reset-CSWNetFull {
    [CmdletBinding()]
    param()
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    [void](Backup-CSWNetConfig)
    $issues = New-Object System.Collections.ArrayList

    Write-CSWLog '1/7 Reset de Winsock' -Level Step
    if ((Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'winsock reset') -ne 0) { [void]$issues.Add('winsock') }
    Write-CSWLog '2/7 Reset de TCP/IP (v4 y v6)' -Level Step
    $log = Join-Path (Get-CSWDataPath Logs) ('netsh_ip_reset_{0:yyyyMMdd_HHmmss}.txt' -f (Get-Date))
    [void](Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments ('int ipv4 reset "{0}"' -f $log))
    [void](Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'int ipv6 reset')
    [void](Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'int tcp reset')
    Write-CSWLog '3/7 Vaciado de cache DNS' -Level Step
    try { if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) { Clear-DnsClientCache -ErrorAction Stop } } catch { }
    [void](Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/flushdns')
    Write-CSWLog '4/7 Vaciado de cache ARP y NetBIOS' -Level Step
    [void](Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'interface ip delete arpcache')
    [void](Invoke-CSWExternal -FilePath 'nbtstat.exe' -Arguments '-R')
    Write-CSWLog '5/7 Reset del proxy del sistema (WinHTTP)' -Level Step
    if ((Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'winhttp reset proxy') -ne 0) { [void]$issues.Add('proxy WinHTTP') }
    Write-CSWLog '6/7 Reinicio de adaptadores fisicos' -Level Step
    try {
        $nics = @(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE AND NetEnabled=TRUE' -ErrorAction Stop)
        foreach ($n in $nics) {
            Write-CSWLog "Reiniciando '$($n.NetConnectionID)'..." -Level Info
            try {
                [void](Invoke-CimMethod -InputObject $n -MethodName Disable -ErrorAction Stop)
                Start-Sleep -Seconds 2
                [void](Invoke-CimMethod -InputObject $n -MethodName Enable -ErrorAction Stop)
            }
            catch { [void]$issues.Add("adaptador $($n.NetConnectionID)"); Write-CSWLog "No se pudo reiniciar: $($_.Exception.Message)" -Level Warn }
        }
    }
    catch { Write-CSWLog "No se pudieron enumerar los adaptadores: $($_.Exception.Message)" -Level Warn }
    Write-CSWLog '7/7 Renovacion de IP' -Level Step
    Start-Sleep -Seconds 5
    [void](Invoke-CSWExternal -FilePath 'ipconfig.exe' -Arguments '/renew')
    Write-CSWLog 'El firewall de Windows NO se ha modificado.' -Level Info

    $sum = 'Reset completo de red realizado (Winsock, TCP/IP, DNS, ARP, proxy WinHTTP, adaptadores). Es NECESARIO REINICIAR el equipo.'
    if ($issues.Count) { $sum += ' Con incidencias en: ' + ($issues -join ', ') + '.' }
    New-CSWResult -Summary $sum -Status Warn
}

# ===========================================================================
# Test de puertos TCP
# ===========================================================================
$script:WellKnownPorts = @{
    20 = 'FTP-datos'; 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'; 110 = 'POP3'; 135 = 'RPC'
    139 = 'NetBIOS'; 143 = 'IMAP'; 389 = 'LDAP'; 443 = 'HTTPS'; 445 = 'SMB'; 465 = 'SMTPS'; 515 = 'LPD'; 587 = 'SMTP-envio'
    631 = 'IPP'; 636 = 'LDAPS'; 993 = 'IMAPS'; 995 = 'POP3S'; 1433 = 'SQL Server'; 1723 = 'PPTP'; 3306 = 'MySQL'
    3389 = 'Escritorio remoto'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM-HTTPS'; 8080 = 'HTTP-alt'
    8443 = 'HTTPS-alt'; 9100 = 'Impresora RAW'
}

function Test-CSWNetPorts {
    [CmdletBinding()]
    param([string]$TargetHost = 'www.microsoft.com', [string]$Ports = '80,443,3389', [int]$TimeoutMs = 2000)
    if (-not $TargetHost) { return (New-CSWResult -Summary 'Indique un host o IP.' -Status Error) }
    $target = $TargetHost.Trim()
    if (-not (Test-CSWHostName $target)) { return (New-CSWResult -Summary "Host o IP no valido: '$target'" -Status Error) }
    $list = New-Object System.Collections.Generic.List[int]
    foreach ($tok in ($Ports -split '[,;\s]+')) {
        if (-not $tok) { continue }
        if ($tok -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($b -lt $a) { $t = $a; $a = $b; $b = $t }
            for ($i = $a; $i -le $b; $i++) { if ($i -ge 1 -and $i -le 65535 -and -not $list.Contains($i)) { $list.Add($i) } }
        }
        elseif ($tok -match '^\d+$') { $i = [int]$tok; if ($i -ge 1 -and $i -le 65535 -and -not $list.Contains($i)) { $list.Add($i) } }
        else { Write-CSWLog "Puerto ignorado (formato no valido): $tok" -Level Warn }
    }
    if ($list.Count -eq 0) { return (New-CSWResult -Summary 'No se indico ningun puerto valido (ej: 80,443,3389 o 8000-8010).' -Status Error) }
    if ($list.Count -gt 1024) { Write-CSWLog 'Se limitara a los primeros 1024 puertos.' -Level Warn; $list = $list.GetRange(0, 1024) }

    $ip = $null
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($target, [ref]$parsed)) { $ip = $parsed }
    else {
        try { $ip = @([System.Net.Dns]::GetHostAddresses($target) | Sort-Object { if ($_.AddressFamily -eq 'InterNetwork') { 0 } else { 1 } })[0] }
        catch { return (New-CSWResult -Summary "No se pudo resolver '$target'." -Status Error) }
    }
    Write-CSWLog ("Probando {0} puerto(s) TCP en {1} [{2}] (timeout {3} ms)..." -f $list.Count, $target, $ip, $TimeoutMs) -Level Step

    $results = New-Object System.Collections.ArrayList
    $batch = 100
    for ($start = 0; $start -lt $list.Count; $start += $batch) {
        $end = [math]::Min($start + $batch, $list.Count) - 1
        $pending = New-Object System.Collections.ArrayList
        for ($i = $start; $i -le $end; $i++) {
            $c = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
            $t = $null
            try { $t = $c.ConnectAsync($ip, $list[$i]) } catch { }
            [void]$pending.Add([pscustomobject]@{ Port = $list[$i]; Client = $c; Task = $t })
        }
        $tasks = @($pending | Where-Object { $_.Task } | ForEach-Object { $_.Task })
        if ($tasks.Count) { try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks, $TimeoutMs) } catch { } }
        foreach ($p in $pending) {
            $state = 'Cerrado o filtrado (sin respuesta)'
            if ($p.Task) {
                if ($p.Task.Status -eq 'RanToCompletion' -and $p.Client.Connected) { $state = 'ABIERTO' }
                elseif ($p.Task.IsFaulted) {
                    $ex = $p.Task.Exception
                    while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
                    if ($ex -is [System.Net.Sockets.SocketException] -and $ex.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { $state = 'Cerrado (rechazado)' }
                    else { $state = "Error: $($ex.Message)" }
                }
            }
            $svc = ''; if ($script:WellKnownPorts.ContainsKey([int]$p.Port)) { $svc = $script:WellKnownPorts[[int]$p.Port] }
            [void]$results.Add([pscustomobject]@{ Puerto = $p.Port; Servicio = $svc; Estado = $state })
            try { $p.Client.Close() } catch { }
        }
    }

    $open = @($results | Where-Object { $_.Estado -eq 'ABIERTO' })
    if ($list.Count -le 50) { $results }
    else {
        $open
        Write-CSWLog ("{0} puertos no abiertos omitidos de la tabla." -f ($results.Count - $open.Count)) -Level Info
    }
    $openTxt = 'ninguno'
    if ($open.Count) { $openTxt = (($open | ForEach-Object { $_.Puerto }) -join ', ') }
    $sum = "$target : $($open.Count) de $($list.Count) puerto(s) abiertos ($openTxt)."
    if (-not $open.Count) { return (New-CSWResult -Summary $sum -Status Warn) }
    New-CSWResult -Summary $sum
}

# ===========================================================================
# Escaneo rapido de la subred local
# ===========================================================================
function Find-CSWNetSubnetHosts {
    [CmdletBinding()]
    param([string]$Subnet = '', [int]$TimeoutMs = 800)
    $myIp = ''; $gw = ''
    $prefix = ''
    if ($Subnet -and $Subnet.Trim()) {
        if ($Subnet.Trim() -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})(\.\d{1,3})?(/\d+)?$') { $prefix = $Matches[1] }
        else { return (New-CSWResult -Summary "Subred no valida: '$Subnet' (ej: 192.168.1 o 192.168.1.0/24)." -Status Error) }
    }
    $p = $null
    try { $p = Get-CSWNetPrimaryAdapter } catch { }
    if ($p) {
        $myIp = @($p.IPv4 | Where-Object { -not (Test-CSWNetApipa $_.Ip) })[0].Ip
        $gw = $p.Gateways[0]
        if (-not $prefix) { $prefix = ($myIp -split '\.')[0..2] -join '.' }
    }
    if (-not $prefix) { return (New-CSWResult -Summary 'No hay adaptador activo con IP: no se puede determinar la subred.' -Status Error) }

    Write-CSWLog "Escaneando $prefix.1-254 (ping asincrono, timeout $TimeoutMs ms)..." -Level Step
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $pings = New-Object System.Collections.ArrayList
    $jobs = New-Object System.Collections.ArrayList
    try {
        for ($i = 1; $i -le 254; $i++) {
            $ip = "$prefix.$i"
            $pg = New-Object System.Net.NetworkInformation.Ping
            [void]$pings.Add($pg)
            $t = $null
            try { $t = $pg.SendPingAsync($ip, $TimeoutMs) } catch { }
            if ($t) { [void]$jobs.Add([pscustomobject]@{ Ip = $ip; Task = $t }) }
        }
        $all = @($jobs | ForEach-Object { $_.Task })
        try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$all, ($TimeoutMs + 4000)) } catch { }
    }
    finally { }

    $found = @{}
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $found[$j.Ip] = [int]$j.Task.Result.RoundtripTime
        }
    }
    foreach ($pg in $pings) { try { $pg.Dispose() } catch { } }

    # Tabla ARP: equipos que no responden a ping (firewall) pero si a ARP
    $macs = @{}
    try {
        $arpArgs = '-a'
        if ($myIp) { $arpArgs = "-a -N $myIp" }
        $arp = Get-CSWNetCommandOutput -FilePath 'arp.exe' -Arguments $arpArgs
        foreach ($l in ($arp -split "`r?`n")) {
            if ($l -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})\s') {
                $aip = $Matches[1]; $mac = $Matches[2].ToUpper()
                if ($aip -like "$prefix.*" -and $mac -ne 'FF-FF-FF-FF-FF-FF' -and $aip -notmatch '\.255$') { $macs[$aip] = $mac }
            }
        }
    }
    catch { }

    $ips = New-Object System.Collections.ArrayList
    foreach ($k in $found.Keys) { [void]$ips.Add($k) }
    foreach ($k in $macs.Keys) { if (-not $found.ContainsKey($k)) { [void]$ips.Add($k) } }
    if ($myIp -and $myIp -like "$prefix.*" -and -not $ips.Contains($myIp)) { [void]$ips.Add($myIp) }

    Write-CSWLog ("{0} equipos detectados; resolviendo nombres..." -f $ips.Count) -Level Info
    $names = @{}
    $dnsJobs = New-Object System.Collections.ArrayList
    foreach ($ip in $ips) {
        try { [void]$dnsJobs.Add([pscustomobject]@{ Ip = $ip; Task = [System.Net.Dns]::GetHostEntryAsync([string]$ip) }) } catch { }
    }
    if ($dnsJobs.Count) {
        try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($dnsJobs | ForEach-Object { $_.Task }), 4000) } catch { }
        foreach ($d in $dnsJobs) {
            if ($d.Task.Status -eq 'RanToCompletion' -and $d.Task.Result.HostName -and $d.Task.Result.HostName -ne $d.Ip) { $names[$d.Ip] = $d.Task.Result.HostName }
        }
    }

    $rows = foreach ($ip in $ips) {
        $note = @()
        if ($ip -eq $myIp) { $note += 'Este equipo' }
        if ($ip -eq $gw) { $note += 'Router / gateway' }
        if (-not $found.ContainsKey($ip) -and $ip -ne $myIp) { $note += 'Solo ARP (no responde a ping)' }
        $ms = $null; if ($found.ContainsKey($ip)) { $ms = $found[$ip] }
        $nm = ''; if ($names.ContainsKey($ip)) { $nm = $names[$ip] } elseif ($ip -eq $myIp) { $nm = $env:COMPUTERNAME }
        $mac = ''; if ($macs.ContainsKey($ip)) { $mac = $macs[$ip] } elseif ($ip -eq $myIp -and $p) { $mac = $p.Mac }
        [pscustomobject]@{ IP = $ip; Nombre = $nm; MAC = $mac; 'Ping ms' = $ms; Nota = ($note -join ', '); Orden = [int](($ip -split '\.')[3]) }
    }
    $rows = @($rows | Sort-Object Orden)
    $rows | Select-Object IP, Nombre, MAC, 'Ping ms', Nota
    New-CSWResult -Summary ("Subred {0}.0/24: {1} dispositivo(s) encontrados en {2:N1} s." -f $prefix, $rows.Count, $sw.Elapsed.TotalSeconds)
}

# ===========================================================================
# WiFi: perfiles, exportacion de claves, informe
# ===========================================================================
function Get-CSWNetWifiProfiles {
    [CmdletBinding()]
    param()
    $svcMsg = Test-CSWNetWlanService
    if ($svcMsg) { return (New-CSWResult -Summary $svcMsg -Status Warn) }
    Write-CSWLog 'Leyendo perfiles WiFi guardados (sin claves)...' -Level Step
    $tmp = Join-Path $env:TEMP ('csw_wifi_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        [void](Get-CSWNetCommandOutput -FilePath 'netsh.exe' -Arguments ('wlan export profile folder="{0}"' -f $tmp))
        $files = @(Get-ChildItem -Path $tmp -Filter '*.xml' -ErrorAction SilentlyContinue)
        if (-not $files.Count) { return (New-CSWResult -Summary 'No hay redes WiFi guardadas en este equipo.' -Status Warn) }
        $rows = foreach ($f in $files) {
            try {
                [xml]$x = Get-Content -Path $f.FullName -Raw
                $mode = Get-CSWNetXmlText $x 'connectionMode'
                $auto = 'Manual'; if ($mode -eq 'auto') { $auto = 'Automatica' }
                [pscustomobject]@{
                    Perfil   = Get-CSWNetXmlText $x 'name'
                    Autenticacion = Get-CSWNetXmlText $x 'authentication'
                    Cifrado  = Get-CSWNetXmlText $x 'encryption'
                    Conexion = $auto
                    Interfaz = (($f.BaseName -split '-')[0])
                }
            }
            catch { }
        }
        $rows = @($rows | Sort-Object Perfil)
        $rows
        $open = @($rows | Where-Object { $_.Autenticacion -eq 'open' })
        if ($open.Count) { Write-CSWLog ("Redes abiertas (sin contrasena) guardadas: {0}" -f (($open | ForEach-Object { $_.Perfil }) -join ', ')) -Level Warn }
        New-CSWResult -Summary "$($rows.Count) red(es) WiFi guardada(s)."
    }
    finally { Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

function Export-CSWNetWifiKeys {
    [CmdletBinding()]
    param([object]$ShowKeys = $false)
    $show = ConvertTo-CSWNetBool $ShowKeys $false
    $svcMsg = Test-CSWNetWlanService
    if ($svcMsg) { return (New-CSWResult -Summary $svcMsg -Status Warn) }
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    $dest = Join-Path (Get-CSWDataPath Backups) ('WiFi_{0}_{1:yyyyMMdd_HHmmss}' -f $env:COMPUTERNAME, (Get-Date))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    # Restringir la carpeta a Administradores y SYSTEM (contiene contrasenas en claro)
    Write-CSWLog 'Restringiendo permisos de la carpeta de copia (solo Administradores y SYSTEM)...' -Level Step
    $acl = Invoke-CSWExternal -FilePath (Join-Path $env:SystemRoot 'System32\icacls.exe') -Arguments ('"{0}" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F' -f $dest) -TimeoutSeconds 60
    if ($acl -ne 0) {
        # Nunca se escriben contrasenas en una carpeta que no se haya podido proteger
        Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
        return (New-CSWResult -Summary "No se pudieron restringir los permisos de la carpeta de copia (icacls codigo $acl); no se exportaron las claves." -Status Error)
    }
    Write-CSWLog 'Exportando perfiles WiFi con sus claves...' -Level Step
    $code = Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments ('wlan export profile key=clear folder="{0}"' -f $dest)
    $files = @(Get-ChildItem -Path $dest -Filter '*.xml' -ErrorAction SilentlyContinue)
    if (-not $files.Count) {
        Remove-Item -Path $dest -Recurse -Force -ErrorAction SilentlyContinue
        return (New-CSWResult -Summary "No se exporto ningun perfil WiFi (netsh codigo $code)." -Status Warn)
    }
    # Las claves NUNCA van al log ni al informe HTML (ambos se entregan al cliente): con ShowKeys
    # se genera ademas un TXT legible dentro de la misma carpeta protegida.
    $plain = New-Object System.Collections.ArrayList
    $rows = foreach ($f in $files) {
        try {
            [xml]$x = Get-Content -Path $f.FullName -Raw
            $key = Get-CSWNetXmlText $x 'keyMaterial'
            $net = Get-CSWNetXmlText $x 'name'
            $shown = '(sin clave)'
            if ($key) { $shown = '******** (en la carpeta protegida)'; [void]$plain.Add(("{0}`t{1}" -f $net, $key)) }
            [pscustomobject]@{ Red = $net; Seguridad = (Get-CSWNetXmlText $x 'authentication'); Clave = $shown }
        }
        catch { }
    }
    $rows | Sort-Object Red
    if ($show -and $plain.Count) {
        $txt = Join-Path $dest 'claves_wifi.txt'
        try {
            Set-Content -LiteralPath $txt -Value (@("Red`tClave") + @($plain)) -Encoding UTF8 -ErrorAction Stop
            Write-CSWLog "Claves en texto legible: $txt (solo Administradores)." -Level Ok
        }
        catch { Write-CSWLog "No se pudo escribir el archivo de claves: $($_.Exception.Message)" -Level Warn }
    }
    Write-CSWLog "Perfiles guardados en: $dest" -Level Ok
    Write-CSWLog "Para restaurar en otro equipo: netsh wlan add profile filename=""<archivo.xml>"" user=all" -Level Info
    Write-CSWLog 'Las claves no se muestran en el registro ni en el informe; estan en la carpeta de copia (solo Administradores).' -Level Info
    New-CSWResult -Summary "$($files.Count) perfil(es) WiFi exportados con clave a $dest (carpeta protegida)."
}

function Get-CSWNetWifiReport {
    [CmdletBinding()]
    param()
    $svcMsg = Test-CSWNetWlanService
    if ($svcMsg) { return (New-CSWResult -Summary $svcMsg -Status Warn) }
    if (-not (Test-CSWAdmin)) { return (New-CSWAdminRequiredResult) }
    Write-CSWLog 'Generando informe WLAN de Windows (ultimos 3 dias de conexiones)...' -Level Step
    $code = Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'wlan show wlanreport'
    $src = Join-Path $env:ProgramData 'Microsoft\Windows\WlanReport\wlan-report-latest.html'
    if (-not (Test-Path $src)) { return (New-CSWResult -Summary "No se pudo generar el informe WiFi (netsh codigo $code)." -Status Error) }
    $dest = Join-Path (Get-CSWDataPath Reports) ('WiFi_{0}_{1:yyyyMMdd_HHmmss}.html' -f $env:COMPUTERNAME, (Get-Date))
    Copy-Item -Path $src -Destination $dest -Force
    $disc = 0
    try {
        $s = (Get-Date).AddDays(-3)
        $disc = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Id = 8003; StartTime = $s } -MaxEvents 500 -ErrorAction Stop).Count
    }
    catch { }
    Write-CSWLog "Informe WiFi guardado en: $dest" -Level Ok
    if ($disc -gt 0) {
        return (New-CSWResult -Summary "Informe WiFi generado ($dest). $disc desconexion(es) WiFi en los ultimos 3 dias." -Status $(if ($disc -gt 10) { 'Warn' } else { 'OK' }))
    }
    New-CSWResult -Summary "Informe WiFi generado: $dest"
}

# ===========================================================================
# Proxy (WinINET por usuario y WinHTTP del sistema)
# ===========================================================================
function Get-CSWNetProxyState {
    $rows = New-Object System.Collections.ArrayList
    foreach ($h in @(Get-CSWNetUserHives)) {
        $path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $k = Get-Item -Path $path -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        $enable = $k.GetValue('ProxyEnable')
        $server = [string]$k.GetValue('ProxyServer')
        $pac = [string]$k.GetValue('AutoConfigURL')
        $override = [string]$k.GetValue('ProxyOverride')
        $auto = ''
        $dcs = Get-Item -Path "$path\Connections" -ErrorAction SilentlyContinue
        if ($dcs) {
            $b = $dcs.GetValue('DefaultConnectionSettings')
            if ($b -is [byte[]] -and $b.Length -gt 8) {
                if ($b[8] -band 8) { $auto = 'Si' } else { $auto = 'No' }
            }
        }
        $pol = Get-Item -Path "$($h.Root)\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        [void]$rows.Add([pscustomobject]@{
                Usuario      = $h.User
                Sid          = $h.Sid
                Activo       = ([int]$enable -eq 1)
                Servidor     = $server
                Excepciones  = $override
                ScriptPAC    = $pac
                AutoDetectar = $auto
                PorDirectiva = [bool]($pol -and $pol.ValueCount -gt 0)
                RegPath      = $path
            })
    }
    return $rows
}

function Get-CSWNetProxy {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Proxy de usuario (WinINET: navegadores y la mayoria de programas)' -Level Step
    $state = @(Get-CSWNetProxyState)
    $issues = New-Object System.Collections.ArrayList
    if ($state.Count) {
        $state | ForEach-Object {
            $act = 'No'; if ($_.Activo) { $act = 'SI' }
            if ($_.Activo -and $_.Servidor) { [void]$issues.Add("$($_.Usuario): proxy $($_.Servidor)") }
            if ($_.ScriptPAC) { [void]$issues.Add("$($_.Usuario): script PAC $($_.ScriptPAC)") }
            if ($_.PorDirectiva) { Write-CSWLog "$($_.Usuario): hay configuracion de proxy por directiva (GPO); puede reaplicarse." -Level Warn }
            [pscustomobject]@{ Usuario = $_.Usuario; 'Proxy activo' = $act; Servidor = $_.Servidor; 'Script PAC' = $_.ScriptPAC; 'Auto detectar' = $_.AutoDetectar; Excepciones = $_.Excepciones }
        } | Write-CSWOutput
    }
    else { Write-CSWLog 'No hay perfiles de usuario cargados.' -Level Info }

    Write-CSWLog 'Proxy del sistema (WinHTTP: servicios, Windows Update)' -Level Step
    $wh = ''
    try { $wh = Get-CSWNetCommandOutput -FilePath 'netsh.exe' -Arguments 'winhttp show proxy' } catch { }
    foreach ($l in ($wh -split "`r?`n")) { if ($l.Trim()) { Write-CSWLog $l.Trim() -Level Data } }
    $whProxy = ''
    if ($wh -match '(?m):\s*(\S+:\d+)\s*$') { $whProxy = $Matches[1]; [void]$issues.Add("WinHTTP: $whProxy") }

    foreach ($v in 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY') {
        $val = [Environment]::GetEnvironmentVariable($v, 'Machine')
        if (-not $val) { $val = [Environment]::GetEnvironmentVariable($v, 'User') }
        if ($val) { Write-CSWLog "Variable de entorno $v = $val" -Level Warn; [void]$issues.Add("$v=$val") }
    }

    if ($issues.Count) { return (New-CSWResult -Summary ('Hay proxy configurado: ' + ($issues -join '; ') + '. Si no es intencionado puede bloquear la navegacion (posible malware).') -Status Warn) }
    New-CSWResult -Summary 'Sin proxy configurado (conexion directa).'
}

$script:WinInetSource = @'
using System;
using System.Runtime.InteropServices;
public static class CSWWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void Refresh() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@

function Clear-CSWNetProxy {
    [CmdletBinding()]
    param()
    $state = @(Get-CSWNetProxyState)
    $backup = Join-Path (Get-CSWDataPath Backups) ('Proxy_{0}_{1:yyyyMMdd_HHmmss}.json' -f $env:COMPUTERNAME, (Get-Date))
    $wh = ''
    try { $wh = Get-CSWNetCommandOutput -FilePath 'netsh.exe' -Arguments 'winhttp show proxy' } catch { }
    try {
        ([pscustomobject]@{ Fecha = (Get-Date).ToString('s'); WinINET = $state; WinHTTP = $wh } | ConvertTo-Json -Depth 4) | Set-Content -Path $backup -Encoding UTF8
        Write-CSWLog "Copia de la configuracion de proxy en: $backup" -Level Ok
    }
    catch { Write-CSWLog "No se pudo guardar la copia del proxy: $($_.Exception.Message)" -Level Warn }

    $changed = 0
    Write-CSWLog 'Desactivando proxy de usuario (WinINET)...' -Level Step
    foreach ($s in $state) {
        if (-not $s.Activo -and -not $s.ScriptPAC -and -not $s.Servidor) { continue }
        try {
            Set-ItemProperty -Path $s.RegPath -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction Stop
            foreach ($n in 'ProxyServer', 'AutoConfigURL') { Remove-ItemProperty -Path $s.RegPath -Name $n -ErrorAction SilentlyContinue }
            $changed++
            Write-CSWLog "Proxy desactivado para $($s.Usuario)." -Level Ok
        }
        catch { Write-CSWLog "No se pudo modificar el proxy de $($s.Usuario): $($_.Exception.Message)" -Level Warn }
        if ($s.PorDirectiva) { Write-CSWLog "$($s.Usuario) tiene proxy por directiva (GPO): puede volver a aplicarse." -Level Warn }
    }
    try {
        if (-not ('CSWWinInet' -as [type])) { Add-Type -TypeDefinition $script:WinInetSource -ErrorAction Stop }
        [CSWWinInet]::Refresh()
    }
    catch { }

    Write-CSWLog 'Restableciendo proxy del sistema (WinHTTP)...' -Level Step
    $code = Invoke-CSWExternal -FilePath 'netsh.exe' -Arguments 'winhttp reset proxy'
    if ($code -ne 0) { return (New-CSWResult -Summary "Proxy de usuario limpiado ($changed perfil/es) pero fallo el reset de WinHTTP (codigo $code)." -Status Warn) }
    New-CSWResult -Summary "Proxy eliminado: $changed perfil(es) de usuario y proxy del sistema (WinHTTP) en conexion directa. Reinicie el navegador."
}

# ===========================================================================
# Test de velocidad aproximado
# ===========================================================================
function Test-CSWNetSpeed {
    [CmdletBinding()]
    param([int]$SizeMB = 25, [object]$Upload = $true)
    if ($SizeMB -lt 1) { $SizeMB = 25 }
    if ($SizeMB -gt 200) { $SizeMB = 200 }
    $doUp = ConvertTo-CSWNetBool $Upload $true
    Enable-CSWNetTls
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }
    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(90)
    try { $client.DefaultRequestHeaders.UserAgent.ParseAdd('CybersutroWin/1.0') } catch { }
    $res = New-Object System.Collections.ArrayList
    try {
        # Latencia HTTP
        Write-CSWLog 'Midiendo latencia con speed.cloudflare.com...' -Level Step
        $lat = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 5; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $r = $client.GetAsync('https://speed.cloudflare.com/__down?bytes=0').GetAwaiter().GetResult()
                $r.Dispose()
                if ($i -gt 0) { [void]$lat.Add($sw.ElapsedMilliseconds) }   # la primera incluye TLS
            }
            catch { }
        }
        $latMs = $null
        if ($lat.Count) { $latMs = [int](($lat | Measure-Object -Minimum).Minimum); Write-CSWLog "Latencia HTTP: $latMs ms" -Level Info }
        else { return (New-CSWResult -Summary 'No se pudo conectar con el servidor de prueba (speed.cloudflare.com): sin Internet o bloqueado.' -Status Error) }

        # Descarga
        $bytes = [int64]$SizeMB * 1000000
        Write-CSWLog "Descargando $SizeMB MB de prueba..." -Level Step
        $url = "https://speed.cloudflare.com/__down?bytes=$bytes"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        [void]$resp.EnsureSuccessStatusCode()
        $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buf = New-Object byte[] 131072
        $total = [int64]0
        $deadline = 45000
        $nextLog = 0.25
        $timedOut = $false
        while ($true) {
            $t = $stream.ReadAsync($buf, 0, $buf.Length)
            if (-not $t.Wait(15000)) { $timedOut = $true; break }
            $n = $t.Result
            if ($n -le 0) { break }
            $total += $n
            if (($total / $bytes) -ge $nextLog) {
                Write-CSWLog ("  {0:N0}% ({1:N1} Mbps)" -f (($total / $bytes) * 100), (($total * 8) / $sw.Elapsed.TotalSeconds / 1e6)) -Level Data
                $nextLog += 0.25
            }
            if ($sw.ElapsedMilliseconds -gt $deadline) { $timedOut = $true; break }
        }
        $secs = $sw.Elapsed.TotalSeconds
        try { $stream.Dispose(); $resp.Dispose() } catch { }
        if ($total -le 0) { return (New-CSWResult -Summary 'La descarga de prueba no recibio datos.' -Status Error) }
        $down = [math]::Round(($total * 8) / $secs / 1e6, 1)
        if ($timedOut) { Write-CSWLog ("Prueba cortada a los {0:N0} s ({1:N1} MB recibidos)." -f $secs, ($total / 1e6)) -Level Warn }
        [void]$res.Add([pscustomobject]@{ Prueba = 'Descarga'; Datos = ('{0:N1} MB' -f ($total / 1e6)); Segundos = [math]::Round($secs, 1); Mbps = $down })
        Write-CSWLog "Descarga: $down Mbps" -Level Ok

        # Subida
        $up = $null
        if ($doUp) {
            $upBytes = [math]::Min(10, [math]::Max(2, [int]($SizeMB / 5))) * 1000000
            Write-CSWLog ("Subiendo {0} MB de prueba..." -f ($upBytes / 1e6)) -Level Step
            try {
                $data = New-Object byte[] $upBytes
                (New-Object System.Random).NextBytes($data)
                $content = New-Object System.Net.Http.ByteArrayContent(, $data)
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $task = $client.PostAsync('https://speed.cloudflare.com/__up', $content)
                if ($task.Wait(60000)) {
                    $r = $task.Result
                    $secs = $sw.Elapsed.TotalSeconds
                    $r.Dispose()
                    $up = [math]::Round(($upBytes * 8) / $secs / 1e6, 1)
                    [void]$res.Add([pscustomobject]@{ Prueba = 'Subida'; Datos = ('{0:N1} MB' -f ($upBytes / 1e6)); Segundos = [math]::Round($secs, 1); Mbps = $up })
                    Write-CSWLog "Subida: $up Mbps" -Level Ok
                }
                else { Write-CSWLog 'La subida supero 60 s; se omite.' -Level Warn }
            }
            catch { Write-CSWLog "No se pudo medir la subida: $(Get-CSWNetErrorText $_)" -Level Warn }
        }
        $res
        $sum = "Velocidad aproximada: bajada $down Mbps"
        if ($null -ne $up) { $sum += ", subida $up Mbps" }
        $sum += ", latencia $latMs ms (servidor Cloudflare)."
        if ($down -lt 10) { return (New-CSWResult -Summary "$sum Velocidad baja." -Status Warn) }
        New-CSWResult -Summary $sum
    }
    catch {
        New-CSWResult -Summary "No se pudo completar el test de velocidad: $(Get-CSWNetErrorText $_)" -Status Error
    }
    finally {
        try { $client.Dispose() } catch { }
    }
}

# ===========================================================================
# IP publica
# ===========================================================================
function Get-CSWNetPublicIp {
    [CmdletBinding()]
    param()
    Write-CSWLog 'Consultando la IP publica...' -Level Step
    $ip4 = ''
    foreach ($u in 'https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com') {
        $r = Invoke-CSWNetHttpGet -Url $u -TimeoutMs 8000
        if ($r.Ok -and $r.Body.Trim() -match '^\d+\.\d+\.\d+\.\d+$') { $ip4 = $r.Body.Trim(); Write-CSWLog "IPv4 publica ($u): $ip4" -Level Ok; break }
        Write-CSWLog "$u no responde: $($r.Error)" -Level Info
    }
    if (-not $ip4) { return (New-CSWResult -Summary 'No se pudo obtener la IP publica (sin acceso a Internet o bloqueado).' -Status Error) }
    $ip6 = ''
    $r6 = Invoke-CSWNetHttpGet -Url 'https://api64.ipify.org' -TimeoutMs 5000
    if ($r6.Ok -and $r6.Body.Trim() -match ':') { $ip6 = $r6.Body.Trim() }
    $isp = ''; $loc = ''
    $ri = Invoke-CSWNetHttpGet -Url "https://ipinfo.io/$ip4/json" -TimeoutMs 6000
    if ($ri.Ok) {
        try {
            $j = $ri.Body | ConvertFrom-Json
            if ($j.PSObject.Properties['org']) { $isp = [string]$j.org }
            $parts = @()
            foreach ($f in 'city', 'region', 'country') { if ($j.PSObject.Properties[$f] -and $j.$f) { $parts += [string]$j.$f } }
            $loc = $parts -join ', '
        }
        catch { }
    }
    $cgnat = ''
    $prim = $null; try { $prim = Get-CSWNetPrimaryAdapter } catch { }
    [pscustomobject]@{ 'IPv4 publica' = $ip4; 'IPv6 publica' = $ip6; Proveedor = $isp; Ubicacion = $loc }
    if ($prim -and $prim.IPv4.Count -and ($prim.IPv4[0].Ip -eq $ip4)) { $cgnat = ' El equipo tiene la IP publica directamente (sin router NAT).' }
    $sum = "IP publica: $ip4"
    if ($isp) { $sum += " ($isp)" }
    New-CSWResult -Summary "$sum.$cgnat"
}

# ===========================================================================
# Registro del modulo
# ===========================================================================
Register-CSWModule -Id 'Network' -Name 'Red' -Order 20 -Icon 'network' `
    -Description 'Diagnóstico y reparación de conectividad, WiFi, proxy y velocidad' -Actions @(
    @{ Id = 'ConnectivityTest'; Name = 'Test de conectividad'; Command = 'Test-CSWNetConnectivity'
        Description = 'Comprueba adaptador, router, salida a Internet, DNS y HTTPS e indica donde falla.' }
    @{ Id = 'Ping'; Name = 'Ping'; Command = 'Test-CSWNetPing'
        Description = 'Prueba de respuesta a un host con estadísticas de latencia, pérdida y jitter.'
        Inputs = @(@{ Name = 'Target'; Label = 'Host o IP'; Default = '8.8.8.8' }, @{ Name = 'Count'; Label = 'Paquetes'; Default = '4' }) }
    @{ Id = 'Traceroute'; Name = 'Traceroute'; Command = 'Test-CSWNetTraceroute'
        Description = 'Muestra los saltos (routers) hasta un destino y donde se corta la ruta.'
        Inputs = @(@{ Name = 'Target'; Label = 'Host o IP'; Default = '8.8.8.8' }, @{ Name = 'ResolveNames'; Label = 'Resolver nombres'; Type = 'Bool'; Default = $true }) }
    @{ Id = 'FlushDns'; Name = 'Vaciar caché DNS'; Command = 'Clear-CSWNetDnsCache'
        Description = 'Vacía la cache DNS del equipo (Clear-DnsClientCache + ipconfig /flushdns).' }
    @{ Id = 'IpConfig'; Name = 'Configuración IP'; Command = 'Get-CSWNetIpConfig'
        Description = 'Adaptadores activos: IP, máscara, gateway, DNS, DHCP, MAC, velocidad de enlace y WiFi.'
        Inputs = @(@{ Name = 'IncludeVirtual'; Label = 'Incluir adaptadores virtuales/VPN'; Type = 'Bool'; Default = $true }) }
    @{ Id = 'RenewIp'; Name = 'Renovar IP'; Command = 'Update-CSWNetIpLease'; Risk = 'Medium'
        Description = 'Libera y renueva la IP por DHCP (ipconfig /release + /renew).'
        ConfirmMessage = 'Se liberará y renovará la IP: la conexión de red (y cualquier sesión remota) se cortará unos segundos. ¿Continuar?' }
    @{ Id = 'ResetStack'; Name = 'Reset Winsock y TCP/IP'; Command = 'Reset-CSWNetStack'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Restablece el catálogo Winsock y la pila TCP/IP (soluciona errores de red persistentes).'
        ConfirmMessage = 'Se restablecerán Winsock y TCP/IP. Las IP ESTÁTICAS se perderán (se guarda copia en Backups) y algunas VPN/antivirus pueden requerir reinstalación. REQUIERE REINICIAR. ¿Continuar?' }
    @{ Id = 'ResetNetwork'; Name = 'Reset completo de red'; Command = 'Reset-CSWNetFull'; Risk = 'High'; ModifiesSystem = $true
        Description = 'Winsock, TCP/IP, DNS, ARP, proxy WinHTTP y reinicio de adaptadores (no toca el firewall).'
        ConfirmMessage = 'Se restablecerá toda la pila de red, el proxy WinHTTP y se reiniciarán los adaptadores (se cortará la conexión). Las IP estáticas se perderán (copia en Backups). REQUIERE REINICIAR. ¿Continuar?' }
    @{ Id = 'PortTest'; Name = 'Test de puertos'; Command = 'Test-CSWNetPorts'
        Description = 'Comprueba si puertos TCP están abiertos, cerrados o filtrados en un host (admite rangos).'
        Inputs = @(@{ Name = 'TargetHost'; Label = 'Host o IP'; Default = 'www.microsoft.com' }, @{ Name = 'Ports'; Label = 'Puertos (ej: 80,443,3389 o 8000-8010)'; Default = '80,443,3389' }) }
    @{ Id = 'SubnetScan'; Name = 'Escanear red local'; Command = 'Find-CSWNetSubnetHosts'; LongRunning = $true
        Description = 'Busca dispositivos en la subred /24 (ping asíncrono + ARP) con nombre y MAC.'
        Inputs = @(@{ Name = 'Subnet'; Label = 'Subred (vacío = automática, ej: 192.168.1)'; Default = '' }) }
    @{ Id = 'WifiProfiles'; Name = 'Redes WiFi guardadas'; Command = 'Get-CSWNetWifiProfiles'
        Description = 'Lista los perfiles WiFi guardados en el equipo (sin mostrar claves).' }
    @{ Id = 'ExportWifiKeys'; Name = 'Exportar claves WiFi'; Command = 'Export-CSWNetWifiKeys'; Risk = 'Medium'
        Description = 'Exporta los perfiles WiFi con sus contraseñas en claro a Backups (carpeta protegida).'
        ConfirmMessage = 'Se exportarán las CONTRASEÑAS WiFi en texto claro a la carpeta de Backups. Trate esos archivos como confidenciales. ¿Continuar?'
        Inputs = @(@{ Name = 'ShowKeys'; Label = 'Crear también un TXT legible con las claves (en la carpeta protegida)'; Type = 'Bool'; Default = $false }) }
    @{ Id = 'WifiReport'; Name = 'Informe WiFi'; Command = 'Get-CSWNetWifiReport'
        Description = 'Genera el informe WLAN de Windows (conexiones, desconexiones y errores) en Informes.' }
    @{ Id = 'ProxyStatus'; Name = 'Ver proxy'; Command = 'Get-CSWNetProxy'
        Description = 'Muestra el proxy de usuario (WinINET), del sistema (WinHTTP) y variables de entorno.' }
    @{ Id = 'ClearProxy'; Name = 'Quitar proxy'; Command = 'Clear-CSWNetProxy'; Risk = 'Medium'; ModifiesSystem = $true
        Description = 'Desactiva el proxy de usuario y restablece WinHTTP a conexión directa (con copia previa).'
        ConfirmMessage = 'Se desactivará el proxy de todos los usuarios cargados y el proxy WinHTTP. En redes de empresa que lo requieran se perderá la navegación. ¿Continuar?' }
    @{ Id = 'SpeedTest'; Name = 'Test de velocidad'; Command = 'Test-CSWNetSpeed'
        Description = 'Mide aproximadamente la velocidad de bajada, subida y latencia (Cloudflare).'
        Inputs = @(@{ Name = 'SizeMB'; Label = 'Tamaño de descarga (MB)'; Type = 'Choice'; Choices = @('10', '25', '50', '100'); Default = '25' },
            @{ Name = 'Upload'; Label = 'Medir también la subida'; Type = 'Bool'; Default = $true }) }
    @{ Id = 'PublicIp'; Name = 'IP pública'; Command = 'Get-CSWNetPublicIp'
        Description = 'Muestra la IP pública (IPv4/IPv6) y el proveedor de Internet.' }
)

Export-ModuleMember -Function *
