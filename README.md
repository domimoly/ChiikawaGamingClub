# Chiikawa Gaming Club 🐾

Mini app Flask para la Evaluación Parcial 2 de Ciberseguridad (EA 2 - OCY1102).
Partió con vulnerabilidades intencionales (SQLi, XSS, CSRF, sin MFA); **ya están corregidas**.
El análisis, la justificación y las pruebas de penetración están en
[`INFORME_SEGURIDAD.md`](INFORME_SEGURIDAD.md).

**Úsala solo en tu propio computador, en `localhost`. No la subas a Internet.**

## Cómo correrla

```bash
cd ChiikawaGamingClub
pip install -r requirements.txt --break-system-packages   # o usa un venv
python3 app.py
```

Abre `http://127.0.0.1:5000` en el navegador.

Usuario de prueba: `chiikawa` / contraseña: `sakura123`
(o `hachiware` / `estrella99`, `usagi` / `zanahoria1`)

**Verificación en dos pasos (MFA):** tras la contraseña, la primera vez la app muestra una clave para agregar
a una app autenticadora y pide un código para confirmarla; después siempre pide el código de 6 dígitos.
Guía completa para comprobar que funciona: [Cómo comprobar el MFA](#cómo-comprobar-que-el-mfa-funciona).

La base de datos SQLite (`chiikawa.db`) se crea sola la primera vez que
ejecutas `app.py`. Si quieres partir de cero, simplemente bórrala.

## Los 3 puntos de entrada de datos (y cómo quedaron)

| # | Punto de entrada | Ruta | Falla original | Corrección |
|---|---|---|---|---|
| 1 | Login (`username`, `password`) | `POST /login` | SQL Injection | Consulta parametrizada, validación por lista blanca, hash de contraseñas, bloqueo por intentos, MFA |
| 2 | Mensaje del muro (`contenido`, `club`) | `POST /muro` | XSS almacenado | Escape de toda salida, CSP con nonce, validación de largo/caracteres, token CSRF |
| 3 | Selector de club (`club`) | `POST /unirse-club` | CSRF | Token CSRF, verificación de `Origin`, cookie `SameSite`, lista blanca de clubes |

## Cómo comprobar que el MFA funciona

El servidor **nunca envía** el código: la app autenticadora lo calcula sola con la clave y la hora, y el servidor
calcula el suyo por separado. Si coinciden, el algoritmo (TOTP, RFC 6238) es el real.

### Opción A: con el teléfono (prueba independiente)

1. Ejecuta `python3 app.py`, abre `http://127.0.0.1:5000` e inicia sesión con `chiikawa` / `sakura123`.
2. En Google Authenticator, Microsoft Authenticator o Authy: **+ → "Ingresar una clave de configuración"**.
3. Pega la clave que muestra la pantalla y elige **"Basada en tiempo"**.
4. Escribe en "Código" el número de 6 dígitos que muestra la app (cambia cada 30 s) y pulsa **Activar y entrar**.

### Opción B: sin teléfono (desde la terminal)

```powershell
# 1) Al activar (primera vez): usa la clave que muestra la pantalla, entre comillas
python3 app.py --totp "XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX"

# 2) En los siguientes inicios de sesión: lee la clave desde la base de datos
python3 app.py --codigo chiikawa
```

Funciona igual en Windows PowerShell, Linux y macOS. Notas:

- Usa la clave **de la pantalla actual**: si borras las cookies o reinicias el alta, la app genera una nueva.
- Cada código sirve una sola vez. Si ya lo usaste, `--codigo` imprime el del siguiente intervalo de 30 s.
- El reloj del computador debe estar en hora.
- Esta opción calcula el código con el código de la propia app, así que prueba que la app funciona, pero no es una
  verificación independiente. Para eso usa la opción A, o una herramienta externa (KeePassXC, Bitwarden, WinAuth)
  con la misma clave, o los vectores oficiales del RFC: `pytest -q -k rfc6238`.

### Qué debes ver (pruebas manuales)

| Qué haces | Qué debe pasar |
|---|---|
| Escribir un código inventado (`123456`) | "Código incorrecto o ya usado" |
| Cerrar sesión, iniciar de nuevo y usar **el mismo código** de antes | Rechazado (no se puede reutilizar un código) |
| Esperar a que cambie el código y usar el nuevo | Entra |
| Iniciar con la contraseña e ir directo a `/muro` o `/perfil` | Te devuelve al login: con solo la contraseña no hay acceso |
| Fallar 5 veces seguidas el código | "Demasiados intentos"; espera 5 minutos |
| Escribir letras o menos de 6 dígitos | "El código debe tener 6 dígitos" |

Estas mismas comprobaciones están automatizadas en `test_seguridad.py` (sección D, MFA).

## Pruebas

```bash
pip install -r requirements-dev.txt
pytest -q                                   # pruebas unitarias y de seguridad
playwright install chromium
python3 pentest/run_pentest.py app.py       # 3 pruebas de penetración con navegador real
```

La evidencia antes/después de las pruebas de penetración está en `pentest/evidencia_pentest.txt`.

## Variables de entorno (opcionales)

| Variable | Efecto |
|---|---|
| `SECRET_KEY` | Clave de sesión fija (si no, se genera una aleatoria en cada arranque) |
| `FLASK_DEBUG=1` | Activa el modo debug (apagado por defecto: expone ejecución remota de código) |
| `COOKIE_SECURE=1` | Marca la cookie como solo-HTTPS (usar cuando haya HTTPS) |