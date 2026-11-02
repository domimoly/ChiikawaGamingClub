"""
Chiikawa Gaming Club
---------------------
App de práctica para la Evaluación Parcial 2 de Ciberseguridad.

ADVERTENCIA: esta aplicación contiene vulnerabilidades A PROPÓSITO.
Está pensada SOLO para ejecutarse en localhost, con fines educativos.
NO desplegar en Internet ni en una red compartida.

Puntos de entrada de datos (3), cada uno con una falla distinta:
  1. /login            -> SQL Injection (consulta armada con f-string)
  2. /muro              -> XSS almacenado (mensajes del muro, sin escapar)
  3. /unirse-club        -> CSRF (cambia el club del jugador, sin token, solo con la cookie de sesión)

Además, la autenticación NO tiene segundo factor (falta IL 2.3 / MFA).

ESTADO ACTUAL: todas las fallas anteriores fueron corregidas:
  1. /login          -> consulta parametrizada + validación de formato + contraseñas con hash
                        + bloqueo temporal por intentos fallidos
  2. /muro           -> salida escapada (XSS) + validación de largo/caracteres + token CSRF
  3. /unirse-club    -> token CSRF + lista blanca de clubes
  +  MFA (TOTP, RFC 6238) obligatorio después de la contraseña
  +  cabeceras de seguridad (CSP con nonce, X-Frame-Options, etc.), cookies endurecidas
"""

from flask import Flask, request, redirect, url_for, session, g, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from functools import wraps
from urllib.parse import urlsplit
import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import struct
import os
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "chiikawa.db")

app = Flask(__name__)
# La clave de sesión NO va en el código: se lee del entorno. Si no existe, se genera
# una aleatoria por ejecución (las sesiones se invalidan al reiniciar, lo cual es seguro).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,          # el JS de la página no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",         # el navegador no envía la cookie en POST entre sitios
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",  # activar con HTTPS
    PERMANENT_SESSION_LIFETIME=1800,       # 30 min
    MAX_CONTENT_LENGTH=16 * 1024,          # rechaza cuerpos POST gigantes
)

# --- Reglas de validación (lista blanca) ---
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MAX_PASSWORD = 128
MAX_MENSAJE = 280
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # conserva \t y \n
MFA_CODE_RE = re.compile(r"^\d{6}$")
MAX_INTENTOS = 5          # intentos fallidos antes de bloquear
BLOQUEO_SEG = 300         # 5 minutos


# ---------- Base de datos ----------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_time = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS jugadores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            club TEXT NOT NULL DEFAULT 'Sin club',
            totp_secret TEXT,
            totp_ultimo INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Migración: columnas de MFA en bases creadas antes de agregar el segundo factor.
    cols_j = [fila[1] for fila in db.execute("PRAGMA table_info(jugadores)")]
    if "totp_secret" not in cols_j:
        db.execute("ALTER TABLE jugadores ADD COLUMN totp_secret TEXT")
    if "totp_ultimo" not in cols_j:
        db.execute("ALTER TABLE jugadores ADD COLUMN totp_ultimo INTEGER NOT NULL DEFAULT 0")
    # Migración: las contraseñas en texto plano pasan a hash (scrypt con sal, vía Werkzeug).
    for fila in db.execute("SELECT id, password FROM jugadores").fetchall():
        if not fila[1].startswith(("scrypt:", "pbkdf2:")):
            db.execute("UPDATE jugadores SET password = ? WHERE id = ?",
                       (generate_password_hash(fila[1]), fila[0]))
    db.commit()
    db.execute("""
        CREATE TABLE IF NOT EXISTS mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            contenido TEXT NOT NULL,
            club TEXT
        )
    """)
    # Migración: bases creadas antes de que el muro guardara el equipo del mensaje.
    columnas = [fila[1] for fila in db.execute("PRAGMA table_info(mensajes)")]
    if "club" not in columnas:
        db.execute("ALTER TABLE mensajes ADD COLUMN club TEXT")
    db.execute(
        "UPDATE mensajes SET club = "
        "(SELECT club FROM jugadores WHERE jugadores.username = mensajes.autor) "
        "WHERE club IS NULL"
    )
    db.commit()
    if first_time:
        db.executemany(
            "INSERT INTO jugadores (username, password, club) VALUES (?, ?, ?)",
            [
                ("chiikawa", generate_password_hash("sakura123"), "Equipo Usagi"),
                ("hachiware", generate_password_hash("estrella99"), "Equipo Momonga"),
                ("usagi", generate_password_hash("zanahoria1"), "Equipo Usagi"),
            ],
        )
        db.commit()
    db.close()


# =====================================================================
#  SEGURIDAD: CSRF, cabeceras, límite de intentos, MFA (TOTP)
# =====================================================================

# ---------- CSRF ----------
# Cada sesión tiene un token aleatorio. Todo POST debe traerlo en el campo oculto
# "csrf_token"; un sitio externo no puede leerlo (política same-origin), así que
# no puede fabricar un POST válido aunque el navegador envíe la cookie de sesión.

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_field():
    return f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'


@app.before_request
def proteger_csrf():
    g.nonce = secrets.token_urlsafe(16)  # nonce de CSP para esta respuesta
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # Defensa en profundidad: si el navegador manda Origin, debe ser este mismo sitio.
        origen = request.headers.get("Origin")
        if origen and origen != "null" and urlsplit(origen).netloc != request.host:
            abort(403, "Origen no permitido.")
        if origen == "null":
            abort(403, "Origen no permitido.")
        enviado = request.form.get("csrf_token", "").encode("utf-8")
        esperado = session.get("csrf", "").encode("utf-8")
        if not esperado or not hmac.compare_digest(enviado, esperado):
            abort(400, "Token CSRF inválido o ausente. Recarga la página e inténtalo de nuevo.")


# ---------- Cabeceras de seguridad ----------

@app.after_request
def cabeceras_seguridad(resp):
    nonce = g.get("nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'nonce-{nonce}'; "              # solo scripts con el nonce de esta respuesta
        f"style-src 'nonce-{nonce}' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"  # "no-referrer" haría que Chrome envíe Origin: null también en formularios propios
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- Límite de intentos (fuerza bruta) ----------
# En memoria: suficiente para esta app local. En producción iría en Redis/BD.

_intentos = {}  # clave -> [fallos, bloqueado_hasta]


def esta_bloqueado(clave):
    reg = _intentos.get(clave)
    return bool(reg and reg[1] > time.time())


def registrar_fallo(clave):
    reg = _intentos.setdefault(clave, [0, 0.0])
    if reg[1] and reg[1] <= time.time():   # el bloqueo anterior ya venció
        reg[0], reg[1] = 0, 0.0
    reg[0] += 1
    if reg[0] >= MAX_INTENTOS:
        reg[1] = time.time() + BLOQUEO_SEG


def limpiar_intentos(clave):
    _intentos.pop(clave, None)


# ---------- MFA: TOTP (RFC 6238) con la librería estándar ----------

def nuevo_secreto_totp():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")  # 160 bits, 32 caracteres


def totp(secreto, paso=None):
    """Código de 6 dígitos para un paso de 30 s (compatible con Google/Microsoft Authenticator)."""
    paso = int(time.time() // 30) if paso is None else paso
    clave = base64.b32decode(secreto + "=" * (-len(secreto) % 8))
    mac = hmac.new(clave, struct.pack(">Q", paso), hashlib.sha1).digest()
    i = mac[-1] & 0x0F
    numero = (struct.unpack(">I", mac[i:i + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{numero:06d}"


def verificar_totp(secreto, codigo, ultimo_paso):
    """Devuelve el paso aceptado o None. Tolera ±1 paso de desfase de reloj y rechaza
    reutilizar un código ya usado (anti-replay: el paso debe ser mayor al último aceptado)."""
    actual = int(time.time() // 30)
    for paso in (actual - 1, actual, actual + 1):
        if paso > ultimo_paso and hmac.compare_digest(totp(secreto, paso), codigo):
            return paso
    return None


def login_required(vista):
    """Solo deja pasar a sesiones que completaron contraseña Y segundo factor."""
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return vista(*args, **kwargs)
    return envoltura


# ---------- Validación y sanitización de entradas ----------

def limpiar_texto(valor):
    """Normaliza un texto libre: quita caracteres de control y espacios sobrantes.
    (La defensa contra XSS es ESCAPAR al mostrar, no solo limpiar aquí.)"""
    return CONTROL_CHARS_RE.sub("", str(valor)).strip()


# =====================================================================
#  INTERFAZ (UI)
#  Todo lo que está entre este bloque y "Rutas" es solo presentación:
#  plantilla base, CSS, personajes en SVG y curiosidades de Chiikawa.
# =====================================================================

# ---------- Curiosidades de Chiikawa ----------
# tag = etiqueta corta que se muestra como chip; texto = el dato.

TRIVIA = [
    {"tag": "Origen",
     "texto": "Chiikawa nació de un boceto que la ilustradora Nagano publicó en Twitter en mayo de 2017. "
              "El manga empezó a publicarse ahí en 2020 y el anime llegó en 2022."},
    {"tag": "Nombre",
     "texto": "«Chiikawa» viene de «chiisakute kawaii yatsu», que se podría traducir como «cosita pequeña y linda»."},
    {"tag": "Antes de ser famosos",
     "texto": "Al principio, Chiikawa se llamaba Nitori y Hachiware se llamaba Ikeya."},
    {"tag": "Usagi",
     "texto": "Usagi casi no habla en frases: grita cosas como «ura» y «yaha». Aun así, sus amigos lo entienden perfecto."},
    {"tag": "Hachiware",
     "texto": "De los tres amigos, Hachiware es el que más habla. Chiikawa y Usagi se comunican sobre todo con sonidos y caras."},
    {"tag": "Especie",
     "texto": "Nagano nunca definió oficialmente qué animales son. Chiikawa parece un osito y Hachiware un gato, "
              "pero técnicamente son «especie desconocida»."},
    {"tag": "Trabajos",
     "texto": "Para ganarse la vida hacen trabajos como desmalezar y cazar bichos, que les entrega Yoroi-san. "
              "Usagi incluso tiene una certificación de desmalezado nivel 3."},
    {"tag": "Armas",
     "texto": "Chiikawa y Hachiware usan palos de exterminio: rosado el de Chiikawa y azul el de Hachiware. "
              "Usagi prefiere un bastón largo."},
    {"tag": "Momonga",
     "texto": "Momonga es una ardilla voladora (eso significa su nombre en japonés). Actúa lindo para conseguir lo que quiere "
              "y suele imitar los bostezos y el llanto de Chiikawa."},
    {"tag": "La creadora",
     "texto": "Antes de Chiikawa, Nagano ya era una de las creadoras de stickers de LINE más conocidas."},
    {"tag": "Usagi",
     "texto": "Usagi es conocido por ser excéntrico y muy comelón."},
]

# Datos por club (los tres que ofrece el selector del perfil)
CLUBES = {
    "Equipo Usagi": {
        "av": "usagi",
        "lema": "Energía y buen apetito",
        "dato": "Usagi casi no habla en frases: grita cosas como «ura» y «yaha», y sus amigos lo entienden igual. "
                "También es conocido por ser muy comelón.",
    },
    "Equipo Momonga": {
        "av": "momo",
        "lema": "Actuar lindo sí funciona",
        "dato": "Momonga es una ardilla voladora (eso significa su nombre en japonés). Actúa lindo para conseguir lo que "
                "quiere y suele imitar los bostezos y el llanto de Chiikawa.",
    },
    "Equipo Kurimanju": {
        "av": "kuri",
        "lema": "Pequeño y redondito",
        "dato": "Kurimanju es otro personaje del mundo de Chiikawa y aparece como personaje jugable en el juego para "
                "celulares de la franquicia, junto a Chiikawa, Hachiware, Usagi y Momonga. Su nombre recuerda al "
                "kuri manjū, un dulce japonés de castaña.",
    },
}

ELENCO = [
    ("chii", "Chiikawa", "Se asusta y llora con facilidad, pero igual se esfuerza por salir adelante."),
    ("hachi", "Hachiware", "El optimista del grupo y el que más habla."),
    ("usagi", "Usagi", "Energético, impredecible y muy comelón. Su grito de guerra es «yaha»."),
    ("momo", "Momonga", "Una ardilla voladora que actúa lindo para conseguir lo que quiere."),
    ("kuri", "Kurimanju", "Personaje jugable en el juego para celulares de la franquicia."),
]

# Qué personaje representa a cada jugador (si no está, se asigna uno según su nombre)
AVATAR_POR_USUARIO = {"chiikawa": "chii", "hachiware": "hachi", "usagi": "usagi"}
AVATARES = ["chii", "hachi", "usagi"]


def avatar_key(nombre):
    nombre = str(nombre)
    return AVATAR_POR_USUARIO.get(nombre.lower()) or AVATARES[sum(ord(c) for c in nombre) % len(AVATARES)]


def avatar(clave, clase=""):
    """Dibuja un personaje (definido en <symbol> dentro de BASE)."""
    return f'<svg class="av {clase}" viewBox="0 0 100 100" aria-hidden="true"><use href="#a-{clave}"/></svg>'


def trivia_box(titulo="Dato del día", clase="", desplazamiento=0):
    """Tarjeta con una curiosidad y un botón para ver otra (el JS vive en BASE)."""
    inicio = (date.today().toordinal() + desplazamiento) % len(TRIVIA)
    items = [{"t": d["tag"], "x": d["texto"]} for d in TRIVIA]
    datos = html.escape(json.dumps(items, ensure_ascii=False), quote=True)
    d = TRIVIA[inicio]
    return f"""
    <section class="card trivia {clase}" data-trivia="{datos}" data-start="{inicio}">
      <div class="trivia-head">
        <h2>{titulo}</h2>
        <button type="button" class="ghost trivia-next">Otro dato</button>
      </div>
      <p class="chip trivia-tag">{d['tag']}</p>
      <p class="trivia-text" aria-live="polite">{d['texto']}</p>
    </section>
    """


# ---------- Plantilla base ----------
# Se escribe con llaves normales y luego se "escapan" para que BASE.format(content=...)
# siga funcionando igual que antes (el CSS y el JS tienen muchas llaves).

_BASE_RAW = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Chiikawa Gaming Club</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600&family=Nunito:wght@400;700;800&display=swap" rel="stylesheet">
  <style nonce="__NONCE__">
    :root {
      --ink: #4b3a44;
      --ink-soft: #7d6873;
      --pink: #d9487a;
      --blush: #ffd0df;
      --butter: #ffe9a8;
      --sky: #bfe6fa;
      --lav: #e3d6fa;
      --mint: #bdebd8;
      --paper: #fffdfb;
    }
    * { box-sizing: border-box; }
    .sprite { position: absolute; }
    code { font-size: 1.15em; letter-spacing: .06em; background: var(--lav); padding: 3px 10px; border-radius: 8px; display: inline-block; }
    body {
      font-family: 'Nunito', system-ui, sans-serif;
      color: var(--ink);
      background: linear-gradient(170deg, #ffe3ec 0%, #efe4ff 48%, #ddf1ff 100%) fixed;
      max-width: 720px;
      margin: 0 auto;
      padding: 26px 18px 64px;
      min-height: 100vh;
      line-height: 1.55;
    }
    h1, h2 { font-family: 'Fredoka', 'Nunito', sans-serif; font-weight: 600; }
    h2 { font-size: 1.35em; margin: 0 0 8px; line-height: 1.2; }
    p { margin: 0 0 10px; }
    /* Encabezado */
    .top {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 28px;
      margin: 0 0 20px;
    }
    .top-art { position: relative; flex: none; width: 104px; height: 104px; }
    .top-art .top-av { width: 104px; height: 104px; }
    .top-art .pad { position: absolute; width: 56px; right: -16px; bottom: -2px; }
    .top-text { min-width: 0; }
    h1 {
      color: var(--ink);
      font-size: 2.5em;
      line-height: 1.05;
      margin: 0 0 8px;
    }
    .sello {
      display: inline-block;
      background: var(--pink);
      color: #fff;
      font-size: .42em;
      line-height: 1;
      padding: 7px 14px;
      border: 2px solid var(--ink);
      border-radius: 999px;
      box-shadow: 0 3px 0 var(--ink);
      vertical-align: middle;
      transform: rotate(-3deg);
      margin-left: 4px;
    }
    .subtitle { color: var(--ink-soft); margin: 0; max-width: 34ch; }

    /* Navegación */
    nav {
      display: flex;
      justify-content: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 22px;
    }
    nav a {
      background: var(--paper);
      color: var(--ink);
      text-decoration: none;
      padding: 8px 16px;
      border: 2px solid var(--ink);
      border-radius: 999px;
      font-weight: 800;
      font-size: .95em;
      box-shadow: 0 3px 0 rgba(75, 58, 68, .25);
    }
    nav a:hover { background: var(--blush); }
    .logout-form { margin: 0; display: inline; }
    nav .navbtn {
      background: var(--paper);
      color: var(--ink);
      padding: 8px 16px;
      font-size: .95em;
      line-height: 1.55;
      box-shadow: 0 3px 0 rgba(75, 58, 68, .25);
    }
    nav .navbtn:hover { background: var(--blush); }
    nav a[aria-current="page"] { background: var(--butter); }

    /* Tarjetas */
    .card {
      background: var(--paper);
      border: 2px solid var(--ink);
      border-radius: 22px;
      padding: 20px 22px;
      margin: 16px 0;
      box-shadow: 5px 5px 0 var(--blush);
    }
    .card.sky { box-shadow: 5px 5px 0 var(--sky); }
    .card.butter { box-shadow: 5px 5px 0 var(--butter); }
    .card.lav { box-shadow: 5px 5px 0 var(--lav); }

    /* Formularios */
    label { font-weight: 800; color: var(--ink-soft); font-size: .92em; }
    input[type=text], input[type=password], select {
      padding: 10px 12px;
      margin: 6px 0 14px;
      width: 100%;
      border: 2px solid #e8b9ca;
      border-radius: 12px;
      font-family: 'Nunito', sans-serif;
      font-size: 1em;
      color: var(--ink);
      background: #fff;
    }
    input[type=text]:focus, input[type=password]:focus, select:focus {
      outline: 3px solid var(--sky);
      border-color: var(--ink);
    }
    button {
      background: var(--pink);
      border: 2px solid var(--ink);
      color: #fff;
      padding: 9px 22px;
      border-radius: 999px;
      cursor: pointer;
      font-weight: 800;
      font-family: 'Nunito', sans-serif;
      font-size: 1em;
      box-shadow: 0 3px 0 var(--ink);
      transition: transform .12s ease, box-shadow .12s ease;
    }
    button:active { transform: translateY(2px); box-shadow: 0 1px 0 var(--ink); }
    button.ghost {
      background: var(--paper);
      color: var(--ink);
      padding: 6px 14px;
      font-size: .9em;
      box-shadow: 0 2px 0 var(--ink);
    }
    a:focus-visible, button:focus-visible {
      outline: 3px solid var(--ink);
      outline-offset: 3px;
    }

    /* Piezas sueltas */
    .error {
      background: #fff0f3;
      color: #a8325d;
      border-radius: 12px;
      padding: 8px 12px;
      font-size: .92em;
      border: 1.5px solid #ffc9d8;
    }
    .hint { font-size: .85em; color: var(--ink-soft); text-align: center; }
    .badge {
      display: inline-block;
      background: var(--mint);
      color: #1f5b44;
      border: 1.5px solid var(--ink);
      padding: 2px 12px;
      border-radius: 999px;
      font-size: .88em;
      font-weight: 800;
    }
    .chip {
      display: inline-block;
      background: var(--lav);
      border-radius: 999px;
      padding: 2px 12px;
      font-size: .85em;
      font-weight: 800;
      margin: 0 0 8px;
    }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    a.btn {
      display: inline-block;
      background: var(--pink);
      color: #fff;
      text-decoration: none;
      font-weight: 800;
      padding: 9px 22px;
      border: 2px solid var(--ink);
      border-radius: 999px;
      box-shadow: 0 3px 0 var(--ink);
    }
    a.btn.alt { background: var(--paper); color: var(--ink); }

    /* Personajes */
    .av { width: 56px; height: 56px; flex: none; }
    .av.big { width: 88px; height: 88px; }
    .av.xl { width: 108px; height: 108px; }

    /* Inicio */
    .hero {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      background: var(--butter);
      box-shadow: 5px 5px 0 var(--blush);
    }
    .hero h2 { font-size: 1.7em; }
    .hero-art { display: flex; align-items: flex-end; flex: none; }
    .hero-art .av { animation: hop .7s ease both; }
    .hero-art .av:nth-child(2) { animation-delay: .12s; }
    .hero-art .av:nth-child(3) { animation-delay: .24s; }
    @keyframes hop {
      0% { transform: translateY(14px); opacity: 0; }
      55% { transform: translateY(-10px); opacity: 1; }
      100% { transform: translateY(0); opacity: 1; }
    }
    .cast { list-style: none; margin: 0; padding: 0; }
    .cast li {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 10px 0;
      border-top: 2px dashed #ead3dd;
    }
    .cast li:first-child { border-top: none; }
    .cast b { font-family: 'Fredoka', 'Nunito', sans-serif; font-weight: 600; font-size: 1.05em; }
    .cast p { margin: 0; color: var(--ink-soft); }

    /* Curiosidades */
    .trivia-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .trivia-head h2 { margin: 0; }
    .trivia-text { margin: 0; font-size: 1.05em; max-width: 62ch; }
    .trivia.flip .trivia-text, .trivia.flip .trivia-tag { animation: swap .35s ease; }
    @keyframes swap {
      from { opacity: 0; transform: translateY(5px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .trivia.mini { padding: 14px 18px; }
    .trivia.mini h2 { font-size: 1.1em; }
    .trivia.mini .trivia-text { font-size: .98em; }

    /* Muro */
    .composer { display: flex; align-items: flex-start; gap: 14px; }
    .composer form { flex: 1; min-width: 0; }
    .composer h2 { margin-bottom: 10px; }
    .notes { display: flex; flex-direction: column; gap: 10px; margin: 16px 0; }
    .msg-card {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      background: var(--blush);
      border: 2px dashed var(--ink-soft);
      border-radius: 16px;
      padding: 12px 16px;
      overflow-wrap: anywhere;
    }
    .msg-card.n1 { background: #dff1fb; }
    .msg-card.n2 { background: #fff3c4; }
    .msg-card .av { width: 44px; height: 44px; }
    .msg-body { min-width: 0; padding-top: 2px; }
    .msg-body b { font-family: 'Fredoka', 'Nunito', sans-serif; font-weight: 600; }
    .msg-body .chip { margin: 0 0 0 4px; padding: 1px 10px; font-size: .75em; background: rgba(255, 255, 255, .7); }
    .composer select { margin-bottom: 12px; }
    .vacio { text-align: center; padding: 8px 0 2px; }
    .vacio .av { margin: 0 auto 6px; display: block; }

    /* Juego de parejas */
    .memo-bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .memo-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0; }
    .carta {
      aspect-ratio: 1;
      padding: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--lav);
      color: var(--ink);
      border-radius: 16px;
      font-family: 'Fredoka', 'Nunito', sans-serif;
      font-size: 1.8em;
    }
    .carta .cara-frente { display: none; width: 100%; height: 100%; align-items: center; justify-content: center; }
    .carta .av { width: 70%; height: 70%; }
    .carta.abierta, .carta.lista { background: #fff; }
    .carta.abierta .cara-frente, .carta.lista .cara-frente { display: flex; }
    .carta.abierta .cara-atras, .carta.lista .cara-atras { display: none; }
    .carta.lista { background: var(--butter); box-shadow: none; transform: translateY(3px); cursor: default; }
    .memo-fin { min-height: 3.2em; margin: 0; }

    /* Perfil */
    .carnet { display: flex; align-items: center; gap: 18px; }
    .carnet h2 { margin-bottom: 4px; }
    .carnet p { margin: 0; }
    .tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 8px 0 16px; }
    .tile { position: relative; display: block; cursor: pointer; }
    .tile input { position: absolute; opacity: 0; inset: 0; width: 100%; height: 100%; margin: 0; cursor: pointer; }
    .tile-body {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      gap: 4px;
      height: 100%;
      padding: 12px 8px;
      background: #fff;
      border: 2px dashed #d9b8c6;
      border-radius: 16px;
      color: var(--ink);
    }
    .tile-text { display: flex; flex-direction: column; gap: 2px; }
    .tile-body b { font-family: 'Fredoka', 'Nunito', sans-serif; font-weight: 600; }
    .tile-body small { color: var(--ink-soft); font-size: .82em; line-height: 1.3; }
    .tile input:checked + .tile-body { background: var(--butter); border: 2px solid var(--ink); }
    .tile input:focus-visible + .tile-body { outline: 3px solid var(--ink); outline-offset: 3px; }

    @media (max-width: 540px) {
      .top { gap: 22px; }
      .top-art { width: 76px; height: 76px; }
      .top-art .top-av { width: 76px; height: 76px; }
      .top-art .pad { width: 42px; right: -12px; }
      h1 { font-size: 1.8em; }
      .sello { display: table; margin: 6px 0 0; }
      .hero { flex-direction: column-reverse; align-items: flex-start; }
      .tiles { grid-template-columns: 1fr; }
      .tile-body { flex-direction: row; text-align: left; gap: 12px; padding: 10px 12px; }
      .tile-body .av { width: 44px; height: 44px; }
      .carnet .av.big { width: 68px; height: 68px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; transition: none !important; }
    }
  </style>
</head>
<body>
  <svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false">
    <defs>
      <!-- Chiikawa -->
      <symbol id="a-chii" viewBox="0 0 100 100">
        <g stroke="#4b3a44" stroke-width="3" stroke-linejoin="round" stroke-linecap="round">
          <circle cx="27" cy="31" r="11" fill="#fffdfb"/>
          <circle cx="73" cy="31" r="11" fill="#fffdfb"/>
          <ellipse cx="50" cy="61" rx="35" ry="31" fill="#fffdfb"/>
          <path d="M46 66 q4 4 8 0" fill="none" stroke-width="2.5"/>
        </g>
        <circle cx="38" cy="58" r="3.4" fill="#4b3a44"/>
        <circle cx="62" cy="58" r="3.4" fill="#4b3a44"/>
        <ellipse cx="29" cy="67" rx="6" ry="4" fill="#ffb3c6"/>
        <ellipse cx="71" cy="67" rx="6" ry="4" fill="#ffb3c6"/>
      </symbol>
      <!-- Hachiware -->
      <symbol id="a-hachi" viewBox="0 0 100 100">
        <g stroke="#4b3a44" stroke-width="3" stroke-linejoin="round" stroke-linecap="round">
          <path d="M20 46 L24 12 L48 31 Z" fill="#8ecdf0"/>
          <path d="M80 46 L76 12 L52 31 Z" fill="#8ecdf0"/>
          <ellipse cx="50" cy="61" rx="35" ry="31" fill="#fffdfb"/>
        </g>
        <path d="M50 30 C40 32 33 38 31 48 C40 44 46 40 50 30 Z" fill="#8ecdf0"/>
        <path d="M50 30 C60 32 67 38 69 48 C60 44 54 40 50 30 Z" fill="#8ecdf0"/>
        <circle cx="38" cy="60" r="3.6" fill="#4b3a44"/>
        <circle cx="62" cy="60" r="3.6" fill="#4b3a44"/>
        <path d="M42 68 q8 9 16 0 z" fill="#ff9bb0" stroke="#4b3a44" stroke-width="2.5" stroke-linejoin="round"/>
        <ellipse cx="28" cy="68" rx="6" ry="4" fill="#ffb3c6"/>
        <ellipse cx="72" cy="68" rx="6" ry="4" fill="#ffb3c6"/>
      </symbol>
      <!-- Usagi -->
      <symbol id="a-usagi" viewBox="0 0 100 100">
        <g stroke="#4b3a44" stroke-width="3" stroke-linejoin="round" stroke-linecap="round">
          <ellipse cx="33" cy="23" rx="8" ry="19" fill="#ffe27a" transform="rotate(-8 33 23)"/>
          <ellipse cx="67" cy="23" rx="8" ry="19" fill="#ffe27a" transform="rotate(8 67 23)"/>
          <ellipse cx="50" cy="63" rx="34" ry="29" fill="#ffe27a"/>
        </g>
        <circle cx="38" cy="59" r="3.4" fill="#4b3a44"/>
        <circle cx="62" cy="59" r="3.4" fill="#4b3a44"/>
        <path d="M41 67 q9 10 18 0 z" fill="#ff9bb0" stroke="#4b3a44" stroke-width="2.5" stroke-linejoin="round"/>
        <ellipse cx="28" cy="68" rx="6" ry="4" fill="#ffb3c6"/>
        <ellipse cx="72" cy="68" rx="6" ry="4" fill="#ffb3c6"/>
      </symbol>
      <!-- Momonga -->
      <symbol id="a-momo" viewBox="0 0 100 100">
        <g stroke="#4b3a44" stroke-width="3" stroke-linejoin="round" stroke-linecap="round">
          <circle cx="27" cy="36" r="9" fill="#d9c3a5"/>
          <circle cx="73" cy="36" r="9" fill="#d9c3a5"/>
          <path d="M18 62 q-14 10 -5 26 q12 -2 17 -12 z" fill="#d9c3a5"/>
          <path d="M82 62 q14 10 5 26 q-12 -2 -17 -12 z" fill="#d9c3a5"/>
          <ellipse cx="50" cy="60" rx="33" ry="29" fill="#efe3d0"/>
        </g>
        <circle cx="38" cy="57" r="4.5" fill="#4b3a44"/>
        <circle cx="62" cy="57" r="4.5" fill="#4b3a44"/>
        <circle cx="39.6" cy="55.4" r="1.4" fill="#fff"/>
        <circle cx="63.6" cy="55.4" r="1.4" fill="#fff"/>
        <ellipse cx="50" cy="65" rx="3" ry="2.2" fill="#4b3a44"/>
        <ellipse cx="30" cy="67" rx="5.5" ry="3.6" fill="#ffb3c6"/>
        <ellipse cx="70" cy="67" rx="5.5" ry="3.6" fill="#ffb3c6"/>
      </symbol>
      <!-- Kurimanju -->
      <symbol id="a-kuri" viewBox="0 0 100 100">
        <g stroke="#4b3a44" stroke-width="3" stroke-linejoin="round" stroke-linecap="round">
          <ellipse cx="50" cy="62" rx="37" ry="30" fill="#e8b07a"/>
          <path d="M16 58 q34 -38 68 0 q-12 -6 -34 -8 q-22 2 -34 8 z" fill="#b9783f"/>
        </g>
        <circle cx="38" cy="64" r="3.4" fill="#4b3a44"/>
        <circle cx="62" cy="64" r="3.4" fill="#4b3a44"/>
        <path d="M46 71 q4 4 8 0" fill="none" stroke="#4b3a44" stroke-width="2.5" stroke-linecap="round"/>
        <ellipse cx="28" cy="72" rx="6" ry="4" fill="#ffb3c6"/>
        <ellipse cx="72" cy="72" rx="6" ry="4" fill="#ffb3c6"/>
      </symbol>
    </defs>
  </svg>

  <header class="top">
    <div class="top-art" aria-hidden="true">
      <svg class="av top-av" viewBox="0 0 100 100"><use href="#a-chii"/></svg>
      <svg class="pad" viewBox="0 0 64 36">
        <rect x="2" y="3" width="60" height="28" rx="14" fill="#bfe6fa" stroke="#4b3a44" stroke-width="3"/>
        <rect x="17" y="10" width="4" height="14" rx="1" fill="#4b3a44"/>
        <rect x="12" y="15" width="14" height="4" rx="1" fill="#4b3a44"/>
        <circle cx="43" cy="14" r="3.2" fill="#d9487a"/>
        <circle cx="50" cy="20" r="3.2" fill="#d9487a"/>
      </svg>
    </div>
    <div class="top-text">
      <h1>Chiikawa <span class="sello">Gaming Club</span></h1>
      <p class="subtitle">Un club chiquito para jugar, charlar y aprender cosas de Chiikawa.</p>
    </div>
  </header>
  <nav>
    <a href="/">Inicio</a>
    <a href="/muro">Muro</a>
    <a href="/juego">Juego</a>
    <a href="/perfil">Mi perfil</a>
    <form method="post" action="/logout" class="logout-form">
      <input type="hidden" name="csrf_token" value="__CSRF__">
      <button type="submit" class="navbtn">Salir</button>
    </form>
  </nav>
  {content}

  <script nonce="__NONCE__">
    (function () {
      var path = location.pathname.replace(/\\/$/, '') || '/';
      document.querySelectorAll('nav a').forEach(function (a) {
        if (a.getAttribute('href') === path) { a.setAttribute('aria-current', 'page'); }
      });
      document.querySelectorAll('[data-trivia]').forEach(function (box) {
        var items;
        try { items = JSON.parse(box.getAttribute('data-trivia')); } catch (e) { return; }
        var btn = box.querySelector('.trivia-next');
        var tag = box.querySelector('.trivia-tag');
        var txt = box.querySelector('.trivia-text');
        var i = parseInt(box.getAttribute('data-start') || '0', 10);
        if (!btn || !tag || !txt || !items.length) { return; }
        btn.addEventListener('click', function () {
          i = (i + 1) % items.length;
          box.classList.remove('flip');
          void box.offsetWidth;
          box.classList.add('flip');
          tag.textContent = items[i].t;
          txt.textContent = items[i].x;
        });
      });
    })();
  </script>
</body>
</html>
"""

BASE = _BASE_RAW.replace("{", "{{").replace("}", "}}").replace("{{content}}", "{content}")


def page(content):
    """Renderiza la plantilla. El nonce y el token CSRF se insertan en la PLANTILLA (texto
    fijo) antes de incorporar el contenido, así nada que venga del usuario puede alterarlos."""
    return (BASE.replace("__NONCE__", g.nonce)
                .replace("__CSRF__", csrf_token())
                .format(content=content))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(413)
def error_seguridad(e):
    msg = escape(getattr(e, "description", "Solicitud no válida."))
    cuerpo = f'<div class="card"><h2>No se pudo completar</h2><p class="error">⚠️ {msg}</p>' \
             f'<div class="actions"><a class="btn alt" href="/">Volver al inicio</a></div></div>'
    return page(cuerpo), e.code


# ---------- Rutas ----------

@app.route("/")
def home():
    nombre = session.get("username")
    if nombre:
        titulo = f"Hola, {escape(nombre)}"
        texto = "Elige tu equipo, deja un mensaje en el muro y descubre cosas que quizá no sabías de Chiikawa."
        botones = (
            f'<a class="btn" href="{url_for("muro")}">Ir al muro</a>'
            f'<a class="btn alt" href="{url_for("juego")}">Jugar</a>'
            f'<a class="btn alt" href="{url_for("perfil")}">Ver mi perfil</a>'
        )
    else:
        titulo = "Entra al club"
        texto = "Un club para jugar, charlar y aprender sobre Chiikawa. Inicia sesión para escribir en el muro y elegir equipo."
        botones = (
            f'<a class="btn" href="{url_for("login")}">Iniciar sesión</a>'
            f'<a class="btn alt" href="{url_for("juego")}">Jugar</a>'
        )

    filas = "".join(
        f"<li>{avatar(clave)}<div><b>{nombre_p}</b><p>{desc}</p></div></li>"
        for clave, nombre_p, desc in ELENCO
    )

    content = f"""
    <section class="card hero">
      <div class="hero-text">
        <h2>{titulo}</h2>
        <p>{texto}</p>
        <div class="actions">{botones}</div>
      </div>
      <div class="hero-art" aria-hidden="true">
        {avatar("chii", "big")}{avatar("hachi", "big")}{avatar("usagi", "big")}
      </div>
    </section>

    {trivia_box("Dato del día", "sky")}

    <section class="card lav">
      <h2>Quién es quién</h2>
      <ul class="cast">{filas}</ul>
    </section>
    """
    return page(content)


# ---------- Juego: parejas de Chiikawa (todo en el navegador, sin servidor) ----------

JUEGO_HTML = """
<section class="card butter">
  <h2>Parejas Chiikawa</h2>
  <p>Da vuelta las cartas y encuentra las 4 parejas con la menor cantidad de intentos.</p>
  <div class="memo-bar">
    <span>Intentos: <b id="memo-intentos">0</b></span>
    <button type="button" class="ghost" id="memo-reiniciar">Reiniciar</button>
  </div>
  <div class="memo-grid" id="memo-grid"></div>
  <p class="memo-fin" id="memo-fin" role="status"></p>
</section>
<script nonce="__NONCE__">
(function () {
  var claves = ['chii', 'hachi', 'usagi', 'momo'];
  var nombres = {chii: 'Chiikawa', hachi: 'Hachiware', usagi: 'Usagi', momo: 'Momonga'};
  var datos = {
    chii: 'Chiikawa se asusta y llora con facilidad, pero igual se esfuerza.',
    hachi: 'Hachiware es el que más habla de los tres amigos.',
    usagi: 'Usagi grita cosas como «ura» y «yaha».',
    momo: 'Momonga es una ardilla voladora que actúa lindo.'
  };
  var grid = document.getElementById('memo-grid');
  var intEl = document.getElementById('memo-intentos');
  var msg = document.getElementById('memo-fin');
  var abiertas, bloqueo, intentos, parejas;

  function mezclar(a) {
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return a;
  }

  function iniciar() {
    grid.innerHTML = '';
    abiertas = []; bloqueo = false; intentos = 0; parejas = 0;
    intEl.textContent = '0';
    msg.textContent = '';
    mezclar(claves.concat(claves)).forEach(function (k) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'carta';
      b.setAttribute('data-k', k);
      b.setAttribute('aria-label', 'Carta boca abajo');
      b.innerHTML = '<span class="cara-atras">?</span><span class="cara-frente"><svg class="av" viewBox="0 0 100 100" aria-hidden="true"><use href="#a-' + k + '"/></svg></span>';
      b.addEventListener('click', function () { voltear(b); });
      grid.appendChild(b);
    });
  }

  function voltear(b) {
    if (bloqueo || b.classList.contains('abierta') || b.classList.contains('lista')) { return; }
    b.classList.add('abierta');
    b.setAttribute('aria-label', nombres[b.getAttribute('data-k')]);
    abiertas.push(b);
    if (abiertas.length < 2) { return; }
    intentos++;
    intEl.textContent = intentos;
    var a = abiertas[0], c = abiertas[1];
    var k = a.getAttribute('data-k');
    if (k === c.getAttribute('data-k')) {
      a.classList.add('lista'); c.classList.add('lista');
      abiertas = [];
      parejas++;
      msg.textContent = datos[k];
      if (parejas === claves.length) {
        msg.textContent = '¡Las encontraste todas en ' + intentos + ' intentos! ' + datos[k];
      }
    } else {
      bloqueo = true;
      setTimeout(function () {
        a.classList.remove('abierta'); c.classList.remove('abierta');
        a.setAttribute('aria-label', 'Carta boca abajo');
        c.setAttribute('aria-label', 'Carta boca abajo');
        abiertas = []; bloqueo = false;
      }, 800);
    }
  }

  document.getElementById('memo-reiniciar').addEventListener('click', iniciar);
  iniciar();
})();
</script>
"""


@app.route("/juego")
def juego():
    return page(JUEGO_HTML.replace("__NONCE__", g.nonce))


# === PUNTO DE ENTRADA 1: LOGIN (SQLi corregida + validación + hash + límite de intentos) ===
HASH_FALSO = generate_password_hash("contraseña-que-no-existe")  # iguala tiempos si el usuario no existe

MSG_LOGIN_MALO = "Usuario o contraseña incorrectos."  # mismo mensaje siempre: no revela qué falló


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        clave = f"login|{request.remote_addr}|{username.lower()}"

        if esta_bloqueado(clave):
            error = "Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo."
        elif not USERNAME_RE.fullmatch(username) or not password or len(password) > MAX_PASSWORD:
            # Formato inválido: ni siquiera se consulta la base de datos.
            registrar_fallo(clave)
            error = MSG_LOGIN_MALO
        else:
            # Consulta parametrizada: username viaja como DATO, nunca como código SQL.
            user = get_db().execute(
                "SELECT * FROM jugadores WHERE username = ?", (username,)
            ).fetchone()
            # Siempre se calcula un hash (aunque el usuario no exista) para no filtrar por tiempo.
            clave_ok = check_password_hash(user["password"] if user else HASH_FALSO, password)
            if user and clave_ok:
                limpiar_intentos(clave)
                session.clear()  # nueva sesión: evita fijación de sesión
                # Contraseña correcta, pero todavía NO hay sesión: falta el segundo factor.
                session["pendiente"] = user["username"]
                session["pendiente_hasta"] = time.time() + 300
                return redirect(url_for("mfa"))
            registrar_fallo(clave)
            error = MSG_LOGIN_MALO

    form = f"""
    <div class="card">
      <h2>(｡•ᴗ•｡) Iniciar sesión</h2>
      <form method="post">
        {csrf_field()}
        <label for="username">Usuario</label>
        <input type="text" id="username" name="username" placeholder="ej: chiikawa"
               maxlength="32" autocomplete="username" required>
        <label for="password">Contraseña</label>
        <input type="password" id="password" name="password" placeholder="••••••••"
               maxlength="{MAX_PASSWORD}" autocomplete="current-password" required>
        <button type="submit">Entrar 🎮</button>
      </form>
      {f"<p class='error'>⚠️ {escape(error)}</p>" if error else ""}
      <p class="hint">Prueba: chiikawa / sakura123 (después te pedirá el código MFA)</p>
    </div>
    """
    return page(form)


# === SEGUNDO FACTOR (MFA / TOTP) ===
# Etapa 2 del login. Sin esta etapa no existe session["username"], por lo que NINGUNA
# ruta protegida (@login_required: /muro, /perfil, /unirse-club) es accesible.

def _usuario_pendiente():
    nombre = session.get("pendiente")
    if not nombre or session.get("pendiente_hasta", 0) < time.time():
        session.pop("pendiente", None)
        return None
    return get_db().execute("SELECT * FROM jugadores WHERE username = ?", (nombre,)).fetchone()


def _completar_login(nombre):
    session.clear()
    session["username"] = nombre
    session.permanent = True


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    user = _usuario_pendiente()
    if user is None:
        return redirect(url_for("login"))
    if not user["totp_secret"]:
        return redirect(url_for("mfa_activar"))  # primera vez: hay que enrolar el autenticador

    error = None
    if request.method == "POST":
        codigo = request.form.get("codigo", "").replace(" ", "")
        clave = f"mfa|{request.remote_addr}|{user['username']}"
        if esta_bloqueado(clave):
            error = "Demasiados intentos fallidos. Espera unos minutos."
        elif not MFA_CODE_RE.fullmatch(codigo):
            registrar_fallo(clave)
            error = "El código debe tener 6 dígitos."
        else:
            paso = verificar_totp(user["totp_secret"], codigo, user["totp_ultimo"])
            if paso is not None:
                db = get_db()
                db.execute("UPDATE jugadores SET totp_ultimo = ? WHERE id = ?", (paso, user["id"]))
                db.commit()
                limpiar_intentos(clave)
                _completar_login(user["username"])
                return redirect(url_for("perfil"))
            registrar_fallo(clave)
            error = "Código incorrecto o ya usado."

    form = f"""
    <div class="card">
      <h2>Verificación en dos pasos</h2>
      <p>Hola, <b>{escape(user['username'])}</b>. Escribe el código de 6 dígitos de tu app autenticadora.</p>
      <form method="post">
        {csrf_field()}
        <label for="codigo">Código</label>
        <input type="text" id="codigo" name="codigo" inputmode="numeric" pattern="[0-9 ]{{6,7}}"
               maxlength="7" autocomplete="one-time-code" autofocus required>
        <button type="submit">Verificar</button>
      </form>
      {f"<p class='error'>⚠️ {escape(error)}</p>" if error else ""}
    </div>
    """
    return page(form)


@app.route("/mfa/activar", methods=["GET", "POST"])
def mfa_activar():
    user = _usuario_pendiente()
    if user is None:
        return redirect(url_for("login"))
    if user["totp_secret"]:
        return redirect(url_for("mfa"))  # ya tiene MFA: no se puede volver a enrolar

    secreto = session.get("totp_nuevo")
    if not secreto:
        secreto = session["totp_nuevo"] = nuevo_secreto_totp()

    error = None
    if request.method == "POST":
        codigo = request.form.get("codigo", "").replace(" ", "")
        clave = f"mfa|{request.remote_addr}|{user['username']}"
        if esta_bloqueado(clave):
            error = "Demasiados intentos fallidos. Espera unos minutos."
        elif not MFA_CODE_RE.fullmatch(codigo):
            registrar_fallo(clave)
            error = "El código debe tener 6 dígitos."
        else:
            paso = verificar_totp(secreto, codigo, 0)
            if paso is not None:
                db = get_db()
                db.execute("UPDATE jugadores SET totp_secret = ?, totp_ultimo = ? WHERE id = ?",
                           (secreto, paso, user["id"]))
                db.commit()
                limpiar_intentos(clave)
                _completar_login(user["username"])
                return redirect(url_for("perfil"))
            registrar_fallo(clave)
            error = "Código incorrecto. Revisa que tu app tenga la hora automática."

    grupos = " ".join(secreto[i:i + 4] for i in range(0, len(secreto), 4))
    uri = f"otpauth://totp/ChiikawaGamingClub:{user['username']}?secret={secreto}&issuer=ChiikawaGamingClub"
    form = f"""
    <div class="card butter">
      <h2>Activa la verificación en dos pasos</h2>
      <p>1. En tu app autenticadora (Google Authenticator, Microsoft Authenticator, Authy…)
         agrega una cuenta con <b>clave manual</b>, tipo <b>basado en tiempo</b>:</p>
      <p><code>{escape(grupos)}</code></p>
      <p class="hint">O abre este enlace si tu dispositivo lo admite: <a href="{escape(uri)}">agregar cuenta</a></p>
      <p>2. Escribe el código de 6 dígitos que muestra la app para confirmar:</p>
      <form method="post">
        {csrf_field()}
        <label for="codigo">Código</label>
        <input type="text" id="codigo" name="codigo" inputmode="numeric" pattern="[0-9 ]{{6,7}}"
               maxlength="7" autocomplete="one-time-code" required>
        <button type="submit">Activar y entrar</button>
      </form>
      {f"<p class='error'>⚠️ {escape(error)}</p>" if error else ""}
    </div>
    """
    return page(form)


# === PUNTO DE ENTRADA 2: MURO DE MENSAJES (XSS corregido: se escapa al mostrar) ===
@app.route("/muro", methods=["GET", "POST"])
@login_required
def muro():
    db = get_db()
    yo = db.execute(
        "SELECT club FROM jugadores WHERE username = ?", (session["username"],)
    ).fetchone()
    club_actual = yo["club"] if yo and yo["club"] in CLUBES else None

    club_elegido = club_actual
    error = None
    if request.method == "POST":
        # Sanitización: se quitan caracteres de control; luego se valida largo y que no esté vacío.
        contenido = limpiar_texto(request.form.get("contenido", ""))
        # El equipo del mensaje solo puede ser uno de la lista de clubes (lista blanca).
        pedido = request.form.get("club", "")
        club_msg = pedido if pedido in CLUBES else club_actual
        club_elegido = club_msg
        if not contenido:
            error = "Escribe un mensaje antes de publicar."
        elif len(contenido) > MAX_MENSAJE:
            error = f"El mensaje es muy largo (máximo {MAX_MENSAJE} caracteres)."
        else:
            db.execute(
                "INSERT INTO mensajes (autor, contenido, club) VALUES (?, ?, ?)",
                (session["username"], contenido, club_msg),
            )
            db.commit()

    mensajes = db.execute(
        "SELECT autor, contenido, club FROM mensajes ORDER BY id DESC"
    ).fetchall()

    def tarjeta_mensaje(m):
        info = CLUBES.get(m["club"])
        if info:  # el equipo con el que se publicó el mensaje
            av = info["av"]
            color = list(CLUBES).index(m["club"])
            etiqueta = f" <span class='chip'>{escape(m['club'])}</span>"
        else:     # mensajes antiguos o sin equipo
            av = avatar_key(m["autor"])
            color = AVATARES.index(av)
            etiqueta = ""
        # XSS: TODO dato que viene de la base de datos se escapa antes de entrar al HTML.
        return (
            f"<div class='msg-card n{color}'>"
            f"{avatar(av)}"
            f"<div class='msg-body'><b>{escape(m['autor'])}</b>{etiqueta}: {escape(m['contenido'])}</div></div>"
        )

    lista_html = "".join(tarjeta_mensaje(m) for m in mensajes)
    if mensajes:
        lista_html = f"<div class='notes'>{lista_html}</div>"
    else:
        lista_html = (
            "<div class='card vacio'>"
            f"{avatar('chii', 'big')}"
            "<p><b>Todavía no hay mensajes.</b></p>"
            "<p class='hint'>Escribe el primero para tu club.</p>"
            "</div>"
        )

    opciones = "".join(
        f'<option value="{escape(nombre)}"{" selected" if nombre == club_elegido else ""}>{escape(nombre)}</option>'
        for nombre in CLUBES
    )
    av_composer = CLUBES[club_elegido]["av"] if club_elegido else avatar_key(session["username"])

    form = f"""
    <div class="card composer">
      {avatar(av_composer, "big")}
      <form method="post">
        {csrf_field()}
        <h2>Muro del club</h2>
        <label for="club">Publicar como</label>
        <select id="club" name="club">{opciones}</select>
        <label for="contenido">Tu mensaje</label>
        <input type="text" id="contenido" name="contenido" placeholder="Escribe algo para tu club..." required maxlength="{MAX_MENSAJE}">
        <button type="submit">Publicar</button>
        {f"<p class='error'>⚠️ {escape(error)}</p>" if error else ""}
      </form>
    </div>
    {trivia_box("Mientras lees el muro", "mini lav", 3)}
    {lista_html}
    """
    return page(form)


# === PUNTO DE ENTRADA 3: UNIRSE A UN CLUB (CSRF corregido: token + lista blanca) ===
@app.route("/perfil")
@login_required
def perfil():
    db = get_db()
    user = db.execute(
        "SELECT * FROM jugadores WHERE username = ?", (session["username"],)
    ).fetchone()

    # Un tile por club; se marca el club actual y, si no coincide ninguno, se exige elegir uno
    tiles = ""
    for i, (nombre_club, info) in enumerate(CLUBES.items()):
        marcado = "checked" if user["club"] == nombre_club else ""
        requerido = "required" if i == 0 else ""
        tiles += f"""
        <label class="tile">
          <input type="radio" name="club" value="{escape(nombre_club)}" {marcado} {requerido}>
          <span class="tile-body">
            {avatar(info["av"])}
            <span class="tile-text">
              <b>{escape(nombre_club)}</b>
              <small>{escape(info["lema"])}</small>
            </span>
          </span>
        </label>
        """

    info_club = CLUBES.get(user["club"])
    if info_club:
        curiosidad = f"""
        <section class="card sky">
          <h2>Curiosidad de tu club</h2>
          <p class="chip">{escape(user['club'])}</p>
          <p>{escape(info_club['dato'])}</p>
        </section>
        """
    else:
        curiosidad = trivia_box("Curiosidad", "sky", 5)

    content = f"""
    <section class="card carnet butter">
      {avatar(avatar_key(user['username']), "big")}
      <div>
        <h2>Hola, {escape(user['username'])}</h2>
        <p>Tu club actual: <span class="badge">{escape(user['club'])}</span></p>
      </div>
    </section>

    <section class="card">
      <h2>Cambiar de club</h2>
      <form method="post" action="{url_for('unirse_club')}">
        {csrf_field()}
        <div class="tiles">{tiles}</div>
        <button type="submit">Unirme</button>
      </form>
    </section>

    {curiosidad}
    """
    return page(content)


@app.route("/unirse-club", methods=["POST"])
@login_required
def unirse_club():
    # El token CSRF ya se validó en before_request. Aquí se valida el DATO: solo clubes conocidos.
    nuevo_club = request.form.get("club", "")
    if nuevo_club not in CLUBES:
        abort(400, "Club no válido.")
    db = get_db()
    db.execute(
        "UPDATE jugadores SET club = ? WHERE username = ?",
        (nuevo_club, session["username"]),
    )
    db.commit()
    return redirect(url_for("perfil"))


@app.route("/logout", methods=["POST"])  # POST + token: un sitio externo no puede cerrar tu sesión
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "--totp":
        # Utilidad de demostración: genera el código actual de un secreto (como lo haría la app móvil).
        print(totp(sys.argv[2].replace(" ", "")))
        sys.exit(0)
    init_db()
    # debug=True expone la consola interactiva de Werkzeug (ejecución remota de código):
    # solo se activa si se pide explícitamente con FLASK_DEBUG=1.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")