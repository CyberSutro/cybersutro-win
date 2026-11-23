# Auditoría de seguridad y calidad — Cybersutro win

Fecha: 23/11/2026 · Alcance: todo el código (`install.ps1`, `Cybersutro-Win.ps1`, `Iniciar.bat`,
`core/`, `ui/`, los 10 `modules/*.psm1`, `docs/`) · Revisión línea a línea, sin muestreo.
Entorno de pruebas: Windows 11 Pro (es-CL, coma decimal), Windows PowerShell 5.1, sesión **sin**
privilegios de administrador (no se ejecutó ninguna acción Medium/High ni nada que modifique el sistema).
PowerShell 7 no está instalado en el equipo de pruebas: la compatibilidad con PS 7 se revisó por
lectura (sin ternario, `??`, clases ni `Get-WmiObject`; `Checkpoint-Computer` ya tiene alternativa CIM).

## Resumen ejecutivo

La base es sólida: arquitectura modular limpia, `Set-StrictMode 2.0` en todo el código, lectura
defensiva de propiedades, sin colisiones de nombres de función (426 funciones de nivel superior,
todas únicas), sin `Write-Host` en acciones, sin `Get-WmiObject`, sin variables automáticas
sobrescritas, IDs de winget ya validados y los grupos resueltos por SID (independiente del idioma).

Los problemas relevantes eran de **confidencialidad de datos del cliente** (carpeta de datos legible
por cualquier usuario local, contraseñas WiFi que podían acabar en el informe), de **robustez de la
GUI** (un programa externo que preguntara algo colgaba la herramienta y "Detener" no lo
interrumpía), de **formato regional** (fechas `23-11-2026` y formato US en el informe) y de
**coherencia** de resultados para el cliente (dos puntuaciones de seguridad distintas, tres
"salud de disco"). Todo ello está corregido y verificado.

| Severidad | Hallazgos | Corregidos | Parcial | Aceptados | Pendientes |
|---|---|---|---|---|---|
| Crítica | 0 | – | – | – | – |
| Alta | 6 | 5 | 1 | – | – |
| Media | 10 | 10 | – | – | – |
| Baja | 12 | 7 | – | 3 | 2 |
| **Total** | **28** | **22** | **1** | **3** | **2** |

Requiere decisión del dueño: H-05 (firma de código / releases con hash publicado),
H-27 (acciones duplicadas entre módulos) y H-28 (registrar en el historial las acciones detenidas).

## Hallazgos

### Seguridad del propio tool

**H-01 · Alta · Corregido** — `core/CSW.Core.psm1:16` (`Initialize-CSWCore`) y `:63` (`Protect-CSWDataFolder`)
`C:\ProgramData\CybersutroWin` heredaba los permisos de ProgramData (lectura para *Usuarios*):
logs, informes, backups de perfiles completos, clave de producto, copias de red/proxy y hosts eran
legibles por cualquier usuario local del equipo del cliente.
*Corrección:* como administrador, la carpeta queda con herencia deshabilitada, propietario
Administradores y acceso solo para Administradores y SYSTEM (`Set-Acl` vía .NET); los elementos ya
existentes se reinician para heredar (`icacls /reset /T`). Solo se aplica si la ACL no es ya la
correcta (no recorre backups grandes en cada arranque) y tolera fallos (aviso en el log). Sin
privilegios (`-NoElevate`) se usa `%LOCALAPPDATA%\CybersutroWin` (privada del usuario) en lugar de
dejar los datos en ProgramData. Verificado sobre una carpeta de prueba: ACL resultante
`SYSTEM:(OI)(CI)F` + `Administradores:(OI)(CI)F` y archivos hijos heredados.

**H-02 · Alta · Corregido** — `modules/Network.psm1:905` (`Export-CSWNetWifiKeys`)
Con la opción `ShowKeys` las contraseñas WiFi se escribían en el log, en el panel y en el
**informe HTML que se entrega al cliente**. Además, si `icacls` fallaba se exportaban igualmente
las claves a una carpeta sin proteger.
*Corrección:* las claves nunca salen al log/informe (se muestran como `********`). `ShowKeys` ahora
genera un `claves_wifi.txt` dentro de la carpeta protegida. Si `icacls` devuelve error se borra la
carpeta y no se exporta nada.

**H-03 · Alta · Corregido** — `modules/UsersBackup.psm1:714` (`Restore-CSWUsersProfileBackup`)
`manifest.json` del backup (dato externo) se usaba sin validar: un `Relative`/`Folder` con `..\` o
ruta absoluta permitía copiar con robocopy, **como administrador**, a cualquier ruta del sistema.
*Corrección:* solo rutas relativas sin `..` ni caracteres de unidad, carpetas conocidas
(Desktop, Documents…) y perfiles de navegador `Default`/`Profile N`; el resto se ignora con aviso.

**H-04 · Alta · Corregido** — `core/CSW.Core.psm1:538` (`Invoke-CSWExternal`), `:608` (`Get-CSWExternalOutput`), `modules/Network.psm1:192`
Los procesos externos heredaban la entrada estándar: cualquier programa que pidiera confirmación
(S/N) se quedaba esperando para siempre (en la GUI no hay consola) y el botón **Detener** no tenía
efecto porque `ReadLine()` bloquea el hilo. No había tiempos máximos en ninguna llamada.
*Corrección:* la entrada estándar se redirige y se cierra (el programa recibe fin de archivo),
lectura asíncrona con sondeo cada 250 ms (la canalización se puede detener), parámetro
`-TimeoutSeconds` (devuelve -1) y, al detener o agotar el tiempo, se termina el árbol de procesos
con `taskkill /T` invocado por .NET. Por seguridad **no** se matan `sfc`, `dism`, `chkdsk`,
`defrag`, `winmgmt`, `pnputil` ni `cleanmgr` (interrumpirlos puede dañar el sistema); el texto del
diálogo Detener lo indica. `stderr` también se decodifica con la codificación correcta y los
procesos se liberan (`Dispose`). Verificado: código de salida, timeout a 2 s, `set /p` recibe EOF,
y Stop en un runspace corta en ~250 ms sin dejar `ping.exe` vivo.

**H-05 · Alta · Parcial (requiere decisión)** — `install.ps1:22-35`, `README.md`
El one-liner descarga la rama `main` y la ejecuta elevada sin ninguna verificación de integridad
(cadena de suministro: quien controle la rama controla los PCs de los clientes).
*Corrección aplicada:* soporte opcional de releases (`$env:CSW_VERSION` → `archive/refs/tags/<tag>.zip`)
y verificación **SHA256** (`$env:CSW_SHA256`): si no coincide no se ejecuta nada. Documentado en el
README. *Pendiente (dueño):* publicar releases con su hash y, idealmente, firmar los scripts con
Authenticode para poder usar `AllSigned` en lugar de `-ExecutionPolicy Bypass`.

**H-06 · Media · Corregido** — `install.ps1`
Descargaba a una ruta predecible (`%TEMP%\CybersutroWin` + `%TEMP%\CybersutroWin.zip`), borrando
antes la carpeta (ventana de carrera para que otro proceso plante archivos que luego se ejecutan
elevados), no limpiaba si fallaba a mitad y, si el técnico cancelaba UAC, mostraba una excepción.
*Corrección:* carpeta nueva con nombre aleatorio (`app_<guid>`) en `%LOCALAPPDATA%\CybersutroWin`
(no escribible por otros usuarios), limpieza de descargas de más de 1 día, borrado de la carpeta
parcial ante cualquier error, TLS 1.2/1.3, mensaje claro si se cancela UAC. Todo dentro de
`& { }` para no alterar `$ErrorActionPreference` de la sesión del técnico.
*Riesgo residual aceptado:* un malware que ya corra como el mismo usuario podría modificar los
archivos entre la descarga y la elevación; se mitiga con el SHA256 de H-05 y se elimina con firma.

**H-07 · Media · Corregido** — inyección en argumentos de procesos externos
- `modules/Repair.psm1:370` DISM `/Source:"..."`: se rechazan comillas/saltos de línea, se quita la
  barra final (`\"` escaparía la comilla de cierre) y se comprueba que el origen exista.
- `modules/Software.psm1:341` búsqueda winget: se eliminan comillas, acentos graves, `\` y
  caracteres de control antes de entrecomillar.
- `modules/Network.psm1:251/430/704` ping, traceroute y test de puertos: validación de host/IP con
  `Test-CSWHostName` (`core:663`).
- `modules/UsersBackup.psm1:532` desbloquear cuenta: el nombre forma parte de una ruta ADSI; se
  valida con las reglas de nombre de cuenta local.
- Ya correctos (verificados): IDs de winget (`^[A-Za-z0-9][A-Za-z0-9.\-_+]{0,127}$`), letras de unidad
  en CHKDSK/Optimize (`^[A-Za-z]$`), nombres de servicio/usuario escapados en WQL, respuestas S/N de
  `chkdsk` de una lista fija, subred con regex.

**H-08 · Media · Corregido** — `modules/UsersBackup.psm1:1047`
"Backup clave de Windows" guardaba la clave **completa** en texto plano con riesgo Low (sin
confirmación). Ahora es Medium con aviso explícito; el TXT queda en la carpeta protegida (H-01) y en
log/informe solo aparecen los últimos 5 caracteres (ya era así).

**H-09 · Media · Corregido** — clasificación de riesgo
Acciones que cambian configuración o interrumpen servicio estaban en Low o sin `ModifiesSystem`:
`Repair.TimeSync` (habilita el servicio de hora y fija servidores NTP) → Medium + ModifiesSystem;
`PrintServices.RestartSpooler` → Medium; `PrintServices.SetDefault` → Medium;
`UsersBackup.UnlockUser` → Medium; `Network.ClearProxy` y `UsersBackup.EnableUser` → `ModifiesSystem`.
Revisadas las 139 acciones: todas las Medium/High tienen `ConfirmMessage` (comprobado por la prueba
de integridad). Protecciones existentes verificadas: no se deshabilita la cuenta en uso ni el
último administrador; servicios críticos (RpcSs, DcomLaunch…) no se detienen; Bloatware con lista
blanca de protegidos; limpiezas sin seguir uniones/enlaces y respetando archivos en uso.

**H-10 · Baja · Corregido** — `ui/CSW.Console.ps1:52`
La contraseña leída con `-AsSecureString` se convertía con `SecureStringToBSTR` sin liberar el BSTR
(quedaba en memoria no administrada). Ahora `PtrToStringBSTR` + `ZeroFreeBSTR` en `finally`.

**H-11 · Baja · Corregido** — `core/CSW.Core.psm1:419` (`Export-CSWReport`)
Título, versión, estado y duración se insertaban en el HTML sin codificar (datos controlados, pero
se exige que todo dato variable pase por `ConvertTo-CSWHtmlText`). Revisadas también las secciones
de Hardware y SecurityAudit: todo texto variable ya estaba codificado.

**H-12 · Baja · Aceptado** — `modules/Network.psm1` (`Get-CSWNetPublicIp`)
Envía la IP pública del cliente a ipify/ifconfig.me/ipinfo.io y la ubicación aparece en el informe.
Es el propósito explícito de la acción (Low, la ejecuta el técnico a propósito).

**H-13 · Baja · Aceptado** — riesgo Low de `Repair.Sfc`, `Repair.DismRestore` (decisión del dueño)
y `Disk.CleanTemp` (paso de la reparación rápida según el contrato). CleanTemp solo borra en
carpetas temporales, archivos con más de 60 min, sin seguir uniones y excluyendo la carpeta de la
herramienta.

### Correctitud y robustez

**H-14 · Alta · Corregido** — fechas dependientes de la cultura (todos los módulos)
`ToString('dd/MM/yyyy')`, `'{0:dd/MM/yyyy}' -f` y `Get-Date -Format 'dd/MM/yyyy'` usan el separador
de fecha de la cultura: en es-CL salía `23-11-2026` (p. ej. *Parches recientes*). Además
`[string]$fecha` usa la cultura invariante (formato **US** `11/23/2026`) en el "Último arranque"
del informe, y el listado de usuarios/perfiles/drivers usaba `yyyy-MM-dd`.
*Corrección:* `Format-CSWDate` en el núcleo (`core:642`), `InvariantCulture`/barras escapadas en
todos los formatos, `Write-CSWOutput` (`core:143`) convierte cualquier `[datetime]` de las tablas
a `dd/MM/yyyy HH:mm`, y el `ParseExact` de *Pantallazos azules* (`Diagnostics.psm1:786`) usa
`InvariantCulture` (con la cultura actual habría lanzado excepción). Verificado en el informe de la
prueba de humo: 18 fechas `23/11/2026`, 0 con guiones, 0 en formato US.

**H-15 · Media · Corregido** — `core/CSW.Core.psm1:419`
`Export-CSWReport` enumeraba `History`, `LogLines` y `ReportSections` (ArrayList sincronizados)
mientras el runspace de trabajo podía estar escribiendo: al cerrar la GUI con una acción en curso
y pedir el informe podía fallar con "La colección fue modificada". Ahora usa `.ToArray()` (copia
bajo bloqueo).

**H-16 · Media · Corregido** — `core/CSW.Core.psm1:239` (`New-CSWRestorePoint`)
En PowerShell 7 no existe `Checkpoint-Computer`, así que el punto de restauración automático
fallaba siempre; sin privilegios se intentaba igualmente; y si no se había podido cambiar
`SystemRestorePointCreationFrequency` se borraba el valor del cliente igualmente.
*Corrección:* alternativa CIM (`SystemRestore.CreateRestorePoint`), comprobación de administrador,
y restauración del valor original solo si se modificó (distinguiendo "no existía" de "valía X").
`Repair.RestorePointCreate` (`Repair.psm1:656`) reutiliza ahora el núcleo (se elimina el código duplicado).

**H-17 · Media · Corregido** — `modules/Software.psm1:150`
Para decodificar winget se cambiaba `[Console]::OutputEncoding`, que es **global del proceso** (la
GUI y cualquier otra acción concurrente quedaban afectadas si algo fallaba). Ahora
`Invoke-CSWExternal -Utf8`; `winget --version` también pasa por el núcleo con timeout.

**H-18 · Baja · Corregido** — `ui/CSW.Gui.ps1:1508`
El temporizador de la GUI tragaba cualquier excepción (`catch { }`), ocultando fallos al completar
tareas. Ahora se muestra en el registro una vez por error distinto.

**H-19 · Baja · Corregido** — `Diagnostics.psm1`: función muerta `Get-CSWDiagErrorText` eliminada
(única función sin referencias de todo el proyecto).

**H-20 · Baja · Corregido** — `Repair.psm1:923`: `w32tm /stripchart` sin tiempo máximo (servidor
NTP inalcanzable) → `-TimeoutSeconds 30`.

**H-21 · Baja · Corregido** — `Diagnostics.psm1:557-589`: "instalados en los últimos 30 días"
comparaba fechas como texto; ahora usa la fecha real (columna oculta, excluida del CSV).

### Consistencia funcional

**H-22 · Media · Corregido** — `modules/Security.psm1:1210`, `:1346`
`Security.Posture` daba **100/100** mientras `SecurityAudit.FullAudit` daba **80/100 (B)** en el
mismo equipo (la primera solo mira 10 protecciones básicas; la segunda 82 controles, p. ej. RDP sin
NLA). *Decisión:* `Security.Posture` pasa a **"Protecciones activas"** — lista de protecciones
Activa/NO ACTIVA/Sin datos y resumen "N de M activas", **sin puntuación**. La única nota de
seguridad del informe es la de la Auditoría de ciberseguridad (se indica en el log). Se mantiene el
Id `Security.Posture` para no romper referencias.

**H-23 · Media · Corregido** — salud de disco triplicada
`Diagnostics.DiskHealth` eliminada (función y acción). `Disk.DiskHealth` (`Disk.psm1:347`) es ahora
una **vista rápida** que reutiliza el motor de Hardware (`Get-CSWHwDiskFindings`) cuando está
cargado → mismo veredicto por disco que *Salud de hardware > Salud de discos*; si Hardware no está,
usa la lógica propia con los mismos umbrales (el desgaste SSD pasaba de 80 % a 70 %, como Hardware).
`Diagnostics.CriticalEvents` remite a la acción correcta.

**H-24 · Media · Corregido** — `modules/PrintServices.psm1:195`
`gpsvc` (y cualquier servicio "Automático (desencadenador)") salía como detenido: solo se excluían
los que eran a la vez retrasados **y** con desencadenador. Ahora se excluye todo servicio con clave
`TriggerInfo` y los de inicio retrasado si el equipo arrancó hace menos de 10 min. Prueba de humo:
ya solo aparece `Fing.Agent` (detenido real).

**H-25 · Baja · Corregido** — fecha de *Parches recientes* `23-11-2026` → `23/11/2026` (ver H-14).

**H-26 · Baja · Corregido** — mensajes de "requiere administrador"
Había 8 redacciones distintas y *Estado de BitLocker* devolvía `Warn`. Ahora todas las acciones usan
`New-CSWAdminRequiredResult` (`core:654`): estado **Error** y resumen uniforme
"Requiere ejecutar como administrador (detalle)." + indicación en el log. En la auditoría, los
controles sin datos por privilegios dicen "Requiere ejecutar como administrador (…)".

**H-27 · Baja · Pendiente (decisión del dueño)** — acciones solapadas
`Diagnostics.MemoryTest` y `Hardware.ScheduleMemTest` hacen exactamente lo mismo (código
duplicado); `Diagnostics.BatteryReport`/`Thermal` se solapan con `Hardware.BatteryHealth`/`CpuHealth`.
No dan resultados contradictorios, pero recomiendo dejar una sola de cada (propuesta: conservar
las de Hardware y retirar las de Diagnóstico) — afecta a la UI, por eso no se ha tocado.

**H-28 · Baja · Pendiente** — una acción detenida con el botón Detener no queda en el historial ni
en el informe (solo en el registro). Recomendable añadir una fila "Detenida por el técnico".

**H-29 · Baja · Aceptado** — la salida de programas externos se decodifica con la página de
códigos de la consola (`[Console]::OutputEncoding`), igual que antes; correcto en `powershell.exe`
normal. `sfc` (UTF-16) y `winget` (UTF-8) tienen decodificación explícita.

> Recuento: H-25 es la manifestación concreta de H-14 y no se cuenta aparte (28 hallazgos).
> Baja = H-10, 11, 12, 13, 18, 19, 20, 21, 26, 27, 28, 29.

### Verificado sin hallazgos

- Colisiones de nombres de función entre módulos: **ninguna** (426 funciones; helpers con prefijo
  por módulo `CSWDiag`, `CSWHw`, `CSWNet`…). La función anidada `Add-Check` es local y no se exporta.
- Variables automáticas sobrescritas (`$input`, `$matches`, `$args`, `$host`, `$error`, `$profile`,
  `$pid`, `$event`, `$sender`, `$this`): ninguna.
- `Write-Host`/`Read-Host` dentro de acciones: ninguno (solo en lanzador/consola). `Get-WmiObject`: ninguno.
- Dependencia del idioma: grupos por SID (`S-1-5-32-544/545`), auditoría por GUID de subcategoría,
  salidas de SFC/DISM con patrones en español e inglés (DISM con `/English`).
- Contraseñas de crear usuario/restablecer: nunca en log; el historial oculta parámetros
  `Pass|Secret|Key|Token`; BitLocker nunca lee claves de recuperación.
- GUI: confirmación siempre antes de invocar; runspace con estado compartido sincronizado;
  cierre limpio (detiene tarea y cierra runspace de forma asíncrona si hay tarea en curso).

## Resultado de las pruebas

| Prueba | Resultado |
|---|---|
| Parser (15 archivos `.ps1`/`.psm1`) | **0 errores** |
| Caracteres no ASCII en código | **0** en todos los archivos |
| Integridad (core + 10 módulos) | **OK**: 10 módulos, 139 acciones (Low 83 · Medium 32 · High 24; 37 con ModifiesSystem), sin FullId duplicados, todo `Command` existe, todo `Input.Name` es parámetro de su función, toda acción Medium/High tiene `ConfirmMessage`, los 6 pasos de la reparación rápida existen, ninguna función definida dos veces |
| Prueba de humo (`smoke_all.ps1`, solo acciones Low de lectura) | 61 acciones: **39 OK · 16 Warn · 6 Error**; los 6 Error son "Requiere ejecutar como administrador" (WifiReport, DismScanHealth, ComponentAnalyze, ChkdskScan, RestorePointList, BitLocker). Los Warn son observaciones reales del equipo (poco espacio en C:, RDP expuesto, etc.). `gpsvc` ya no aparece; Hotfixes muestra `23/11/2026`; `Security.Posture` → "Protecciones activas: 8 de 8"; `Disk.DiskHealth` usa el motor de Hardware |
| GUI (STA, `-AutoCloseSeconds 8`, captura `audit_gui.png`) | Abre y cierra sin errores; motor de trabajo listo con 10 módulos; 139 acciones |
| `Invoke-CSWExternal` | Código de salida correcto; timeout → -1 a los 2 s; `set /p` recibe EOF (no cuelga); Stop en runspace en ~250 ms sin procesos huérfanos |
| `Protect-CSWDataFolder` (carpeta de prueba) | ACL `SYSTEM` + `Administradores` sin herencia; hijos reiniciados a heredar |

Lista `$deny` de la prueba de humo: no necesitó cambios (la acción eliminada
`Diagnostics.DiskHealth` no estaba en ella; las acciones que pasaron a Medium quedan excluidas
automáticamente por riesgo).

## Archivos modificados

`install.ps1`, `README.md`, `docs/CONTRATO.md` (reglas 11-13: utilidades del núcleo, datos de
entrada no confiables, criterio de riesgo), `core/CSW.Core.psm1`, `ui/CSW.Gui.ps1` (solo lógica y
textos de aviso; ningún cambio visual), `ui/CSW.Console.ps1`, y los módulos `Diagnostics`, `Disk`,
`Hardware`, `Network`, `PrintServices`, `Repair`, `Security`, `SecurityAudit`, `Software`,
`UsersBackup`.
