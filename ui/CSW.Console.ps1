<#
    Cybersutro win - Modo consola
    Menús numerados construidos dinámicamente a partir de los módulos registrados.
#>

function Show-CSWHeader {
    param([string]$Subtitle = '')
    Clear-Host
    $s = Get-CSWState
    $isAdm = Test-CSWAdmin
    $admin = if ($isAdm) { 'Administrador' } else { 'SIN PRIVILEGIOS' }
    $w = 72
    $line = ([string][char]0x2500) * $w
    Write-Host ''
    Write-Host '   /\   ' -ForegroundColor Cyan -NoNewline
    Write-Host 'CYBERSUTRO' -ForegroundColor Cyan -NoNewline
    Write-Host ' win' -ForegroundColor White -NoNewline
    Write-Host ('  v{0}' -f $s.Version) -ForegroundColor DarkGray
    Write-Host '  |~~|  ' -ForegroundColor Cyan -NoNewline
    Write-Host 'Soporte técnico para Windows' -ForegroundColor Gray
    Write-Host '   \/   ' -ForegroundColor Cyan -NoNewline
    Write-Host ('Equipo: {0}   ' -f $env:COMPUTERNAME) -ForegroundColor Gray -NoNewline
    Write-Host ('[{0}]' -f $admin) -ForegroundColor $(if ($isAdm) { 'Green' } else { 'Red' })
    if ($s.ClientName) { Write-Host ('        Cliente: {0}   Técnico: {1}' -f $s.ClientName, $s.TechName) -ForegroundColor Gray }
    Write-Host $line -ForegroundColor DarkCyan
    if ($Subtitle) { Write-Host "  $Subtitle" -ForegroundColor White; Write-Host $line -ForegroundColor DarkGray }
}
function Wait-CSWKey {
    Write-Host ''
    Write-Host '  Pulse ENTER para continuar…' -ForegroundColor DarkGray -NoNewline
    [void](Read-Host)
}

function Read-CSWInputs {
    param($Action)
    $params = @{}
    foreach ($in in @($Action.Inputs)) {
        $label = if ($in.ContainsKey('Label')) { $in.Label } else { $in.Name }
        $def = if ($in.ContainsKey('Default')) { [string]$in.Default } else { '' }
        $type = if ($in.ContainsKey('Type')) { $in.Type } else { 'Text' }

        if ($type -eq 'Choice') {
            $choices = @($in.Choices)
            Write-Host "  $label" -ForegroundColor White
            for ($i = 0; $i -lt $choices.Count; $i++) { Write-Host ('    {0}) {1}' -f ($i + 1), $choices[$i]) }
            $r = Read-Host '  Opción'
            $n = 0
            if ([int]::TryParse($r, [ref]$n) -and $n -ge 1 -and $n -le $choices.Count) { $params[$in.Name] = $choices[$n - 1] }
            elseif ($def) { $params[$in.Name] = $def }
            else { return $null }
        }
        elseif ($type -eq 'Bool') {
            $r = Read-Host "  $label (s/n)"
            $params[$in.Name] = ($r -match '^(s|si|y|yes)$')
        }
        elseif ($in.Name -match 'Password') {
            $sec = Read-Host "  $label" -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try { $params[$in.Name] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        else {
            $prompt = if ($def) { "  $label [$def]" } else { "  $label" }
            $r = Read-Host $prompt
            if (-not $r) { $r = $def }
            $n = 0
            if ($def -match '^\d+$' -and [int]::TryParse($r, [ref]$n)) { $params[$in.Name] = $n } else { $params[$in.Name] = $r }
        }
    }
    return $params
}

function Invoke-CSWConsoleAction {
    param($Action)
    Show-CSWHeader -Subtitle $Action.Name
    if ($Action.Description) { Write-Host "  $($Action.Description)" -ForegroundColor Gray; Write-Host '' }
    $params = Read-CSWInputs -Action $Action
    if ($null -eq $params) { Write-Host '  Cancelado.' -ForegroundColor Yellow; Wait-CSWKey; return }
    if (-not (Confirm-CSWAction -Action $Action)) { Write-Host '  Cancelado por el usuario.' -ForegroundColor Yellow; Wait-CSWKey; return }
    if ($Action.LongRunning) { Write-Host '  Esta acción puede tardar varios minutos...' -ForegroundColor DarkYellow }
    Write-Host ''
    [void](Invoke-CSWAction -Action $Action -Params $params)
    Wait-CSWKey
}

function Show-CSWModuleMenu {
    param($Module)
    while ($true) {
        Show-CSWHeader -Subtitle ("{0} - {1}" -f $Module.Name, $Module.Description)
        $acts = @($Module.Actions)
        for ($i = 0; $i -lt $acts.Count; $i++) {
            $a = $acts[$i]
            $tag = switch ($a.Risk) { 'High' { '[ALTO] ' } 'Medium' { '[MEDIO]' } default { '       ' } }
            $col = switch ($a.Risk) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'DarkGray' } }
            Write-Host ('  {0,3}) ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
            Write-Host $tag -NoNewline -ForegroundColor $col
            Write-Host (' {0}' -f $a.Name) -NoNewline
            if ($a.LongRunning) { Write-Host '  (largo)' -NoNewline -ForegroundColor DarkGray }
            Write-Host ''
        }
        Write-Host ''
        Write-Host '    ?N) Ayuda de la acción N    0) Volver' -ForegroundColor DarkGray
        $r = Read-Host '  Seleccione'
        if ($r -eq '0' -or $r -eq '') { return }
        if ($r -match '^\?(\d+)$') {
            $n = [int]$Matches[1]
            if ($n -ge 1 -and $n -le $acts.Count) {
                $a = $acts[$n - 1]
                Write-Host ''; Write-Host "  $($a.Name)" -ForegroundColor White
                Write-Host "  $($a.Description)" -ForegroundColor Gray
                Write-Host ("  Riesgo: {0}   Modifica el sistema: {1}" -f $(switch ($a.Risk) { 'High' { 'alto' } 'Medium' { 'medio' } default { 'bajo' } }), $(if ($a.ModifiesSystem) { 'sí' } else { 'no' })) -ForegroundColor Gray
                Wait-CSWKey
            }
            continue
        }
        $n = 0
        if ([int]::TryParse($r, [ref]$n) -and $n -ge 1 -and $n -le $acts.Count) { Invoke-CSWConsoleAction -Action $acts[$n - 1] }
    }
}

function Set-CSWServiceData {
    $s = Get-CSWState
    Show-CSWHeader -Subtitle 'Datos del servicio (aparecen en el informe)'
    $r = Read-Host "  Técnico [$($s.TechName)]"; if ($r) { $s.TechName = $r }
    $r = Read-Host "  Cliente [$($s.ClientName)]"; if ($r) { $s.ClientName = $r }
    $r = Read-Host '  Observaciones (ENTER para mantener)'; if ($r) { $s.Notes = $r }
}

function Start-CSWConsole {
    [CmdletBinding()]
    param()
    $s = Get-CSWState
    $s.GuiMode = $false
    try { $Host.UI.RawUI.WindowTitle = "Cybersutro win v$($s.Version) - $env:COMPUTERNAME" } catch { }

    while ($true) {
        Show-CSWHeader -Subtitle 'Menú principal'
        $mods = @(Get-CSWModule)
        for ($i = 0; $i -lt $mods.Count; $i++) {
            Write-Host ('  {0,3}) ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
            Write-Host ('{0,-30}' -f $mods[$i].Name) -NoNewline -ForegroundColor White
            Write-Host ('{0,3} acciones' -f @($mods[$i].Actions).Count) -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Host '    Q) REPARACIÓN RÁPIDA (limpieza + red + DISM + SFC + informe)' -ForegroundColor Green
        Write-Host '    D) Datos del servicio (técnico, cliente, notas)'
        Write-Host '    R) Generar informe HTML'
        Write-Host '    L) Abrir carpeta de logs e informes'
        Write-Host '    X) Salir'
        Write-Host ''
        $r = (Read-Host '  Seleccione').Trim().ToUpper()
        switch -Regex ($r) {
            '^\d+$' {
                $n = [int]$r
                if ($n -ge 1 -and $n -le $mods.Count) { Show-CSWModuleMenu -Module $mods[$n - 1] }
            }
            '^Q$' {
                Show-CSWHeader -Subtitle 'Reparación rápida'
                foreach ($id in (Get-CSWQuickRepairSteps)) {
                    $a = Get-CSWAction -FullId $id
                    if ($a) { Write-Host "   - $($a.Name)" } else { Write-Host "   - $id (no disponible)" -ForegroundColor DarkGray }
                }
                Write-Host ''
                Write-Host '  Se creará un punto de restauración. Puede tardar 20-40 minutos.' -ForegroundColor Yellow
                $c = Read-Host '  Escriba S para comenzar'
                if ($c -match '^(s|si)$') {
                    $p = Invoke-CSWQuickRepair
                    if ($p) { Start-Process $p }
                    Wait-CSWKey
                }
            }
            '^D$' { Set-CSWServiceData }
            '^R$' { [void](Export-CSWReport -Open); Wait-CSWKey }
            '^L$' { Start-Process explorer.exe (Get-CSWDataPath) }
            '^X$' {
                if (@($s.History).Count -gt 0) {
                    $c = Read-Host '  ¿Generar informe antes de salir? (s/n)'
                    if ($c -match '^(s|si)$') { [void](Export-CSWReport -Open) }
                }
                return
            }
        }
    }
}
