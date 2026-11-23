# Contrato de módulos — Cybersutro win

Cada módulo es un archivo `modules/<Nombre>.psm1` independiente. El lanzador importa
primero `core/CSW.Core.psm1` y luego cada módulo con `Import-Module -Global`.
La GUI (WPF) y el menú de consola **se construyen solos** a partir de lo que cada
módulo registra: no hay que tocar la UI para añadir acciones.

## Reglas obligatorias

1. **Compatibilidad**: Windows PowerShell 5.1 y PowerShell 7. Prohibido: `?:` ternario,
   `??`, `?.`, `ForEach-Object -Parallel`, `&&`/`||`, clases `class` de PS, `Get-WmiObject`
   (usar `Get-CimInstance`).
2. **Texto en ASCII** dentro del código (sin tildes ni ñ: "Reparacion", "Diagnostico").
   Al final convertimos a UTF-8 con BOM, pero así evitamos sorpresas en PS 5.1.
3. **Nunca interactuar con el usuario** dentro de una acción: nada de `Read-Host`,
   `Write-Host`, `pause`, `MessageBox`, ni ventanas. Las acciones corren en un runspace
   en segundo plano sin consola. Los datos de entrada llegan como parámetros (ver `Inputs`).
   La confirmación la hace la UI según `Risk`/`ConfirmMessage`.
4. **Salida**:
   - Mensajes de progreso: `Write-CSWLog 'texto' -Level Info|Ok|Warn|Error|Step|Data`.
   - Programas externos (sfc, dism, chkdsk, netsh, winget, ipconfig, ping.exe...):
     `$code = Invoke-CSWExternal -FilePath 'dism.exe' -Arguments '/Online /Cleanup-Image /RestoreHealth'`
     (muestra la salida en vivo en el log; para `sfc.exe` usar `-Unicode`).
   - Datos tabulares: devolver objetos (`[pscustomobject]`) por el pipeline; el núcleo los
     formatea como tabla en el log.
   - **Última línea de toda acción**: `New-CSWResult -Summary 'texto corto' -Status OK|Warn|Error`
     (aparece en el informe HTML del cliente; escribir en español claro para un cliente).
5. Errores esperables: capturarlos y reportarlos con `Write-CSWLog -Level Warn/Error` +
   `New-CSWResult -Status Error`. Errores inesperados pueden lanzarse (el núcleo los captura).
6. Archivos generados (backups, exportaciones): bajo `Get-CSWDataPath Backups` o
   `Get-CSWDataPath Reports`. Nunca escribir en la carpeta de la herramienta.
7. Nombres de funciones: `Verbo-CSW<Modulo><Accion>` (verbo aprobado: Get, Invoke, Reset,
   Clear, Test, Repair, Start, Stop, Export, Backup, Remove, Install, Update, Optimize,
   Show...). Cada función usada como `Command` debe exportarse.
8. Al final del `.psm1`: llamar a `Register-CSWModule` y luego `Export-ModuleMember -Function *`.
9. Detectar disponibilidad (ej. winget no instalado, sin batería, sin impresoras) y
   devolver un resultado `Warn` explicativo en vez de fallar.

10. Secciones en el informe del cliente: una acción puede llamar a
    `Add-CSWReportSection -Id 'HardwareHealth' -Title 'Salud del hardware' -Html $html -Order 20`
    (reemplaza por Id). Todo texto variable debe pasar por `ConvertTo-CSWHtmlText`.
    Clases disponibles: `table`, `.badge .ok/.warn/.err`, `.kpis` + `.kpi` (`<b>` valor, `<span>` etiqueta), `.muted`, `.score`.

11. **Utilidades del núcleo** (úsalas en lugar de reinventarlas):
    - `New-CSWAdminRequiredResult 'detalle'` — resultado uniforme `Error` "Requiere ejecutar como
      administrador (detalle)." cuando falta elevación.
    - `Invoke-CSWExternal ... -TimeoutSeconds 60 -Utf8` — tiempo máximo (devuelve -1) y salida UTF-8
      (winget). La entrada estándar del proceso se cierra: un programa que pregunte S/N no cuelga la GUI.
    - `Get-CSWExternalOutput -FilePath x -Arguments y` — devuelve el texto sin volcarlo al log (60 s máx.).
    - `Format-CSWDate $fecha [-WithTime]` — fechas para el cliente siempre `dd/MM/yyyy` (no usar
      `ToString('dd/MM/yyyy')` sin `InvariantCulture`: en es-CL sale `23-11-2026`).
    - `Test-CSWHostName $host` — valida host/IP antes de usarlo.
12. **Datos de entrada = no confiables**: todo valor que vaya a la línea de comandos de un
    programa externo se valida (regex de ID, letra de unidad `^[A-Za-z]$`, host) o se rechaza si
    contiene comillas. Nunca se escriben contraseñas, claves WiFi ni claves de producto completas
    en el log o el informe (los parámetros cuyo nombre contiene Pass/Secret/Key/Token se ocultan
    en el historial).
13. **Riesgo**: toda acción que borre, reinicie, desinstale, cambie configuración, corte la red o
    exponga secretos es `Medium`/`High` con `ConfirmMessage`; si cambia configuración del sistema,
    `ModifiesSystem = $true`.

## Campos de una acción

| Campo | Tipo | Uso |
|---|---|---|
| `Id` | string | Identificador corto, PascalCase, único en el módulo (`FlushDns`). |
| `Name` | string | Texto del botón/menú (ASCII, corto). |
| `Description` | string | Una frase explicando qué hace (tooltip / ayuda). |
| `Command` | string | Nombre de la función exportada a ejecutar. |
| `Risk` | `Low`/`Medium`/`High` | `Medium`/`High` → la UI pide confirmación. |
| `ConfirmMessage` | string | Texto de confirmación (qué cambiará, si requiere reinicio). |
| `ModifiesSystem` | bool | `$true` → el núcleo crea punto de restauración antes (una vez por sesión). |
| `LongRunning` | bool | `$true` si tarda > 1 min (la UI avisa). |
| `Inputs` | array | Parámetros a pedir: `@{ Name='Target'; Label='Host o IP'; Default='8.8.8.8' }`. Opcional `Type='Choice'` + `Choices=@('a','b')`, o `Type='Bool'`. `Name` = nombre del parámetro de la función. |

## Ejemplo

```powershell
#Requires -Version 5.1
Set-StrictMode -Version 2.0

function Test-CSWNetPing {
    param([string]$Target = '8.8.8.8', [int]$Count = 4)
    Write-CSWLog "Haciendo ping a $Target ($Count paquetes)..." -Level Info
    $code = Invoke-CSWExternal -FilePath 'ping.exe' -Arguments "-n $Count $Target"
    if ($code -eq 0) { New-CSWResult -Summary "$Target responde" }
    else { New-CSWResult -Summary "$Target no responde" -Status Warn }
}

Register-CSWModule -Id 'Network' -Name 'Red' -Order 20 -Icon 'network' `
    -Description 'Diagnostico y reparacion de conectividad' -Actions @(
    @{ Id='Ping'; Name='Ping'; Command='Test-CSWNetPing'; Description='Prueba de respuesta a un host';
       Inputs=@(@{Name='Target';Label='Host o IP';Default='8.8.8.8'}, @{Name='Count';Label='Paquetes';Default='4'}) }
)
Export-ModuleMember -Function *
```

## IDs obligatorios (los usa la "Reparacion rapida")

- `Disk.CleanTemp` — limpia temporales de usuario/Windows sin confirmación extra.
- `Network.FlushDns`
- `Network.ConnectivityTest` — gateway, DNS, Internet en un solo diagnóstico.
- `Repair.DismRestore` — DISM /RestoreHealth.
- `Repair.Sfc` — sfc /scannow.
- `Diagnostics.CriticalEvents` — errores críticos de los últimos 7 días.

## Orden de módulos (campo `Order`)

Diagnostics 10 · Hardware 15 · Network 20 · Repair 30 · Disk 40 · Security 50 · SecurityAudit 55 · Software 60 · PrintServices 70 · UsersBackup 80
