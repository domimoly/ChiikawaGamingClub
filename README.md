# Chiikawa Gaming Club 🐾

Mini aplicación web en **Flask** creada para la **Evaluación Parcial 2 de Ciberseguridad (EA 2 · OCY1102) | Dominga Ruiz**.

Es un club de juegos con tema Chiikawa (login, muro de mensajes, perfil y selección de club) que **partió con
vulnerabilidades intencionales** (SQL Injection, XSS almacenado, CSRF y ausencia de segundo factor). Todas fueron
**analizadas, corregidas y verificadas con pruebas de penetración**; el detalle completo está en el
[Informe de seguridad](INFORME_SEGURIDAD.md).

> ⚠️ **Uso exclusivamente educativo.** Ejecútala solo en tu computador, en `localhost`. No la publiques en Internet
> ni en una red compartida (ver [Limitaciones conocidas](#limitaciones-conocidas)).

---

## Contenido

- [Resumen de seguridad](#resumen-de-seguridad)
- [Requisitos](#requisitos)
- [Instalación y ejecución](#instalación-y-ejecución)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Rutas de la aplicación](#rutas-de-la-aplicación)
- [Los 3 puntos de entrada de datos](#los-3-puntos-de-entrada-de-datos)
- [Autenticación multifactor (MFA)](#autenticación-multifactor-mfa)
- [Cómo comprobar que el MFA funciona](#cómo-comprobar-que-el-mfa-funciona)
- [Pruebas](#pruebas)
- [Pruebas de penetración](#pruebas-de-penetración)
- [Otras medidas de seguridad](#otras-medidas-de-seguridad)
- [Variables de entorno](#variables-de-entorno)
- [Limitaciones conocidas](#limitaciones-conocidas)

---

## Resumen de seguridad

| Vulnerabilidad | Punto de entrada | Estado | Corrección principal |
|---|---|---|---|
| SQL Injection (A03:2021) | `POST /login` | ✅ Corregida | Consultas parametrizadas, validación por lista blanca, contraseñas con hash (scrypt) |
| XSS almacenado (A03:2021) | `POST /muro` | ✅ Corregida | Escape de toda salida, CSP con nonce, validación de largo y caracteres |
| CSRF (A01:2021) | `POST /unirse-club` | ✅ Corregida | Token CSRF, verificación de `Origin`, cookie `SameSite=Lax`, lista blanca de clubes |
| Sin segundo factor | Todo el sitio | ✅ Implementado | MFA con TOTP (RFC 6238), anti-replay y bloqueo por intentos |

Resultado de las pruebas de penetración (navegador real, Chromium):

| Prueba | Antes | Después |
|---|---|---|
| P1 · SQL Injection en el login | VULNERABLE | **PROTEGIDO** |
| P2 · XSS almacenado en el muro | VULNERABLE | **PROTEGIDO** |
| P3 · CSRF en el cambio de club | VULNERABLE | **PROTEGIDO** |

## Requisitos

- Python 3.10 o superior
- Flask 3.0 o superior (única dependencia de ejecución)
- Para las pruebas: `pytest` y `playwright` (con Chromium) — ver [Pruebas](#pruebas)

## Instalación y ejecución

```bash
cd ChiikawaGamingClub

# (recomendado) entorno virtual
python3 -m venv .venv
source .venv/bin/activate          # En Windows: .venv\Scripts\activate

pip install -r requirements.txt
python3 app.py
```

Abre <http://127.0.0.1:5000> en el navegador.

**Usuarios de prueba**

| Usuario | Contraseña |
|---|---|
| `chiikawa` | `sakura123` |
| `hachiware` | `estrella99` |
| `usagi` | `zanahoria1` |

La base de datos SQLite (`chiikawa.db`) se crea sola la primera vez que se ejecuta `app.py`. Para partir de cero,
basta con borrarla.

## Estructura del proyecto

```
ChiikawaGamingClub/
├── app.py                    # Aplicación completa (rutas, MFA, protecciones, plantillas HTML)
├── requirements.txt          # Dependencias de ejecución (Flask)
├── requirements-dev.txt      # Dependencias de pruebas (pytest, playwright)
├── conftest.py               # Configuración y fixtures de pytest
├── test_seguridad.py         # Pruebas de seguridad: SQLi, XSS, CSRF, MFA, cabeceras, límites
├── test_muro.py              # Pruebas del muro de mensajes
├── pentest/
│   ├── run_pentest.py        # 3 pruebas de penetración con navegador real (Playwright)
│   └── evidencia_pentest.txt # Salida de las pruebas: antes y después de las correcciones
├── INFORME_SEGURIDAD.md      # Informe: análisis, correcciones, MFA, pentest, limitaciones
└── README.md
```

## Rutas de la aplicación

| Ruta | Método | Acceso | Descripción |
|---|---|---|---|
| `/` | GET | Público | Página de inicio |
| `/juego` | GET | Público | Sección de juego |
| `/login` | GET, POST | Público | Primer factor: usuario y contraseña |
| `/mfa` | GET, POST | Contraseña verificada | Segundo factor: código TOTP de 6 dígitos |
| `/mfa/activar` | GET, POST | Contraseña verificada | Alta del autenticador (primera vez) |
| `/muro` | GET, POST | Sesión con MFA completo | Muro de mensajes de los clubes |
| `/perfil` | GET | Sesión con MFA completo | Perfil del jugador |
| `/unirse-club` | POST | Sesión con MFA completo | Cambio de club |
| `/logout` | POST | Sesión | Cierra la sesión (POST con token CSRF) |

## Los 3 puntos de entrada de datos

El análisis siguió cada dato desde que entra por un formulario hasta donde se usa: ¿se valida?, ¿se sanitiza?,
¿llega a SQL?, ¿se imprime en HTML?, ¿la petición es auténtica?

| # | Punto de entrada | Ruta | Falla original | Corrección |
|---|---|---|---|---|
| 1 | Login (`username`, `password`) | `POST /login` | SQL Injection | Consulta parametrizada; `username` con `^[A-Za-z0-9_]{3,32}$`; contraseña ≤ 128; hash scrypt con sal; mensaje de error único; bloqueo de 5 min tras 5 fallos; sesión nueva al autenticar; MFA |
| 2 | Mensaje del muro (`contenido`, `club`) | `POST /muro` | XSS almacenado | Escape con `markupsafe.escape` de todo dato dinámico; CSP con nonce; mensaje obligatorio de máx. 280 caracteres; eliminación de caracteres de control; `club` por lista blanca; token CSRF |
| 3 | Selector de club (`club`) | `POST /unirse-club` | CSRF | Token CSRF en todos los formularios; verificación de `Origin`; cookie `SameSite=Lax`; lista blanca de los 3 clubes (400 si no coincide) |

### Por qué estas defensas

- **SQLi:** con parámetros, la base de datos recibe el SQL y los datos por separado, así que `' OR '1'='1` es solo
  un texto que no coincide con ningún usuario. Se elimina la causa en vez de filtrar caracteres.
- **XSS:** el escape actúa en la salida, donde se conoce el contexto HTML. La CSP (`script-src 'nonce-…'`, sin
  `unsafe-inline`) es una segunda capa: si alguien olvida un `escape()`, el navegador igual bloquea el script.
- **CSRF:** el navegador adjunta la cookie automáticamente, pero no puede hacer que un sitio atacante lea el token
  (política same-origin). `Origin` y `SameSite` son capas adicionales independientes del token.

## Autenticación multifactor (MFA)

Se implementó **TOTP (RFC 6238)**, el mismo mecanismo de Google Authenticator o Microsoft Authenticator, solo con
la librería estándar (`hmac`, `hashlib`, `struct`) y verificado contra los **vectores oficiales del RFC**. Se prefirió
frente a SMS/correo porque no depende de la red telefónica (SIM swapping), no necesita infraestructura externa y
funciona sin conexión.

```
/login (usuario + contraseña)
   │  correcta → estado "pendiente" (todavía SIN sesión válida)
   ▼
¿el jugador ya tiene secreto TOTP?
   ├─ No  → /mfa/activar: se muestra la clave, el jugador la agrega a su app
   │        y escribe un código para confirmar; recién ahí se guarda
   └─ Sí  → /mfa: pide el código de 6 dígitos
   ▼
código válido → sesión completa
```

Decisiones de diseño:

- Tolerancia de ±1 paso (30 s) por desfase de reloj.
- **Anti-replay:** se guarda el último paso aceptado; un código ya usado no sirve de nuevo.
- Bloqueo tras 5 códigos incorrectos; el código debe cumplir `^\d{6}$`.
- `/muro`, `/perfil` y `/unirse-club` exigen MFA completo (`@login_required`): una contraseña robada no da acceso.
- El secreto de alta vive en la sesión y solo se guarda cuando el jugador demuestra tener el autenticador.

## Cómo comprobar que el MFA funciona

El servidor **nunca envía** el código: la app autenticadora lo calcula con la clave y la hora, y el servidor calcula el
suyo por separado. Si coinciden, el algoritmo es el real.

### Opción A: con el teléfono (verificación independiente)

1. Ejecuta `python3 app.py`, abre <http://127.0.0.1:5000> e inicia sesión con `chiikawa` / `sakura123`.
2. En Google Authenticator, Microsoft Authenticator o Authy: **+ → "Ingresar una clave de configuración"**.
3. Pega la clave que muestra la pantalla y elige **"Basada en tiempo"**.
4. Escribe el código de 6 dígitos de la app (cambia cada 30 s) y pulsa **Activar y entrar**.

### Opción B: sin teléfono (desde la terminal)

```bash
# 1) Al activar (primera vez): usa la clave que muestra la pantalla, entre comillas
python3 app.py --totp "XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX"

# 2) En los siguientes inicios de sesión: lee la clave desde la base de datos
python3 app.py --codigo chiikawa
```

Funciona en Windows PowerShell, Linux y macOS. Notas:

- Usa la clave **de la pantalla actual**: si borras las cookies o reinicias el alta, la app genera una nueva.
- Cada código sirve una sola vez; si ya lo usaste, `--codigo` imprime el del siguiente intervalo de 30 s.
- El reloj del computador debe estar en hora.
- Esta opción usa el código de la propia app, por lo que no es una verificación independiente. Para eso usa la
  opción A, una herramienta externa (KeePassXC, Bitwarden, WinAuth) o los vectores del RFC: `pytest -q -k rfc6238`.

### Qué debes ver

| Qué haces | Qué debe pasar |
|---|---|
| Escribir un código inventado (`123456`) | "Código incorrecto o ya usado" |
| Cerrar sesión, volver a entrar y usar **el mismo código** | Rechazado (no se puede reutilizar) |
| Esperar a que cambie el código y usar el nuevo | Entra |
| Iniciar con la contraseña e ir directo a `/muro` o `/perfil` | Te devuelve al login |
| Fallar 5 veces seguidas el código | "Demasiados intentos"; espera 5 minutos |
| Escribir letras o menos de 6 dígitos | "El código debe tener 6 dígitos" |

## Pruebas

```bash
pip install -r requirements-dev.txt
pytest -q                                   # 72 pruebas unitarias y de seguridad
```

Cubren los tres ataques con múltiples variantes (6 payloads SQLi, 4 de XSS) y además: MFA (vectores RFC 6238, replay,
fuerza bruta, acceso solo con contraseña), bloqueo de login, hash de contraseñas y su migración, cabeceras, cookies,
límites de entrada y migración de la base de datos.

## Pruebas de penetración

`pentest/run_pentest.py` levanta la aplicación y la ataca con un navegador real (Chromium vía Playwright).

```bash
playwright install chromium
python3 pentest/run_pentest.py app.py                    # contra la versión corregida
python3 pentest/run_pentest.py app.py --sqli-vulnerable  # reescribe el login como f-string para mostrar el "antes" de P1
```

| Prueba | Procedimiento | Antes | Después |
|---|---|---|---|
| **P1 · SQLi** | Tres payloads en `/login`: `x' OR '1'='1`, `chiikawa' --`, `' OR 1=1 --` | Los 3 entran a `/perfil` | Los 3 rechazados (ni llegan a la base de datos) |
| **P2 · XSS** | `chiikawa` publica `<script>` e `<img onerror>`; `usagi` visita el muro | 5 `alert()` ejecutados, 2 en la víctima | 0 alertas; se muestra como texto |
| **P3 · CSRF** | Página atacante en otro puerto envía `club=Equipo Hackeado` con la víctima autenticada | 302: el club cambió | 403: el club no cambió |

La evidencia completa (tres versiones: login vulnerable, código original y versión corregida) está en
[`pentest/evidencia_pentest.txt`](pentest/evidencia_pentest.txt). El informe incluye además un anexo con las mismas
tres categorías practicadas en el laboratorio de las guías (Kali Linux + Metasploitable 2, DVWA y OWASP ZAP).

## Otras medidas de seguridad

| Falla detectada | Corrección |
|---|---|
| `secret_key` fija y visible en el código | Se lee de `SECRET_KEY` o se genera aleatoria al iniciar |
| `debug=True` (consola con ejecución remota de código) | Apagado por defecto |
| Sin límite de intentos | 5 fallos → bloqueo de 5 min, en login y MFA |
| Fijación de sesión | `session.clear()` al pasar cada etapa |
| Sesión sin vencimiento | Vence a los 30 min |
| Sin cabeceras de seguridad | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`, CSP |
| Cuerpos POST sin límite | `MAX_CONTENT_LENGTH` = 16 KB (responde 413) |
| Contraseñas en texto plano | Hash scrypt con sal; migración automática en `init_db()` |

## Variables de entorno

Todas son opcionales.

| Variable | Efecto |
|---|---|
| `SECRET_KEY` | Clave de sesión fija (si no, se genera una aleatoria en cada arranque) |
| `FLASK_DEBUG=1` | Activa el modo debug (apagado por defecto: expone ejecución remota de código) |
| `COOKIE_SECURE=1` | Marca la cookie como solo-HTTPS (usar cuando haya HTTPS) |

## Limitaciones conocidas

Declaradas para que el alcance sea honesto (detalle en la sección 5 del informe):

1. El alta del MFA ocurre en el primer inicio de sesión: quien conozca la contraseña de una cuenta sin MFA podría
   enrolar su propio autenticador. En producción se haría por un canal verificado.
2. El secreto TOTP se guarda en texto plano en la base de datos (debería cifrarse con una clave externa).
3. El límite de intentos vive en memoria (se reinicia con el servidor; en producción iría en Redis o en la base).
4. Sin HTTPS: pensada para `localhost`. En producción, HTTPS y `COOKIE_SECURE=1`.
5. La sesión de Flask es una cookie firmada, no cifrada.
6. La página de login muestra credenciales de prueba para facilitar la evaluación; deben quitarse fuera del entorno académico.
7. La prueba CSRF usa otro puerto, no otro dominio: lo que se demuestra es el token/`Origin`, no `SameSite`.

---

*Evaluación Parcial 2 · Ciberseguridad (OCY1102). Proyecto con fines académicos.*
