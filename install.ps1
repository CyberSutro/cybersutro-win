<#
    Cybersutro win - Instalador one-liner
    Uso (PowerShell):
        irm https://raw.githubusercontent.com/CyberSutro/cybersutro-win/main/install.ps1 | iex

    Descarga el paquete desde GitHub (solo HTTPS) a una carpeta NUEVA con nombre aleatorio
    dentro de %LOCALAPPDATA%\CybersutroWin (privada del usuario: otro usuario del equipo no
    puede plantar ni modificar archivos ahi) y lo abre como administrador.
    No instala nada en el sistema.

    Opcional (variables de entorno, se leen antes de descargar):
        $env:CSW_VERSION = 'v1.0.0'          # descarga el paquete de ese release en lugar de la rama main
        $env:CSW_SHA256  = '<hash del zip>'  # verifica el SHA256 del zip antes de ejecutar nada
    Ejemplo verificado:
        $env:CSW_VERSION='v1.0.0'; $env:CSW_SHA256='ABC123...'; irm https://raw.githubusercontent.com/CyberSutro/cybersutro-win/main/install.ps1 | iex
#>
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $repo = 'CyberSutro/cybersutro-win'

    $zipUrl = "https://github.com/$repo/archive/refs/heads/main.zip"
    $tag = [string]$env:CSW_VERSION
    if ($tag) {
        if ($tag -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-_]{0,63}$') { Write-Host "  CSW_VERSION no valida: '$tag'" -ForegroundColor Red; return }
        # Paquete fijo publicado como recurso del release (bytes estables -> SHA256 verificable)
        $zipUrl = "https://github.com/$repo/releases/download/$tag/cybersutro-win-$tag.zip"
    }
    $expected = ([string]$env:CSW_SHA256).Trim().ToUpperInvariant()
    if ($expected -and $expected -notmatch '^[0-9A-F]{64}$') { Write-Host '  CSW_SHA256 no es un SHA256 valido (64 caracteres hexadecimales).' -ForegroundColor Red; return }

    # TLS 1.2 (y 1.3 si existe) para Windows PowerShell 5.1
    try {
        $proto = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        try { $proto = $proto -bor [Net.SecurityProtocolType]'Tls13' } catch { }
        [Net.ServicePointManager]::SecurityProtocol = $proto
    }
    catch { }

    if (-not $env:LOCALAPPDATA) { Write-Host '  No se encontro %LOCALAPPDATA%.' -ForegroundColor Red; return }
    $base = Join-Path $env:LOCALAPPDATA 'CybersutroWin'
    $dest = Join-Path $base ('app_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    $zip = Join-Path $dest 'paquete.zip'

    Write-Host ''
    Write-Host '  CYBERSUTRO WIN - descargando...' -ForegroundColor Cyan
    try {
        # Limpieza de descargas anteriores (mas de 1 dia; nunca la que se esta creando)
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -Directory -Filter 'app_*' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        }
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing
        if ($expected) {
            $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($actual -ne $expected) { throw "El SHA256 del paquete no coincide (esperado $expected, obtenido $actual). No se ejecuta nada." }
            Write-Host '  SHA256 verificado.' -ForegroundColor Green
        }
        Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force
        Remove-Item -LiteralPath $zip -Force
    }
    catch {
        Write-Host "  Error al descargar o preparar el paquete: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    $launcher = Get-ChildItem -LiteralPath $dest -Recurse -Filter 'Cybersutro-Win.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $launcher) {
        Write-Host '  No se encontro Cybersutro-Win.ps1 en el paquete.' -ForegroundColor Red
        Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
        return
    }
    Get-ChildItem -LiteralPath $launcher.DirectoryName -Recurse -Include *.ps1, *.psm1 | Unblock-File -ErrorAction SilentlyContinue

    Write-Host "  Listo en $($launcher.DirectoryName). Abriendo (acepte el aviso de UAC)..." -ForegroundColor Green
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe -or $exe -notmatch '(powershell|pwsh)\.exe$') { $exe = 'powershell.exe' }
    try {
        Start-Process -FilePath $exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $launcher.FullName))
    }
    catch {
        Write-Host '  No se concedieron permisos de administrador (UAC cancelado). Vuelva a ejecutar el comando y acepte el aviso.' -ForegroundColor Yellow
    }
}
