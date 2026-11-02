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
"""

from flask import Flask, request, redirect, url_for, session, g
from markupsafe import escape
from datetime import date
import html
import json
import sqlite3
import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "chiikawa.db")

app = Flask(__name__)
app.secret_key = "clave-super-secreta-cambiar"  # ok para práctica local


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
            club TEXT NOT NULL DEFAULT 'Sin club'
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            contenido TEXT NOT NULL
        )
    """)
    if first_time:
        db.executemany(
            "INSERT INTO jugadores (username, password, club) VALUES (?, ?, ?)",
            [
                ("chiikawa", "sakura123", "Equipo Usagi"),
                ("hachiware", "estrella99", "Equipo Momonga"),
                ("usagi", "zanahoria1", "Equipo Usagi"),
            ],
        )
        db.commit()
    db.close()


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
  <style>
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
    h1 {
      color: var(--ink);
      text-align: center;
      font-size: 2.3em;
      line-height: 1.1;
      margin: 0 0 6px;
    }
    h2 { font-size: 1.35em; margin: 0 0 8px; line-height: 1.2; }
    p { margin: 0 0 10px; }
    .subtitle {
      text-align: center;
      color: var(--ink-soft);
      margin: 0 0 18px;
    }

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
    .vacio { text-align: center; padding: 8px 0 2px; }
    .vacio .av { margin: 0 auto 6px; display: block; }

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
      h1 { font-size: 1.9em; }
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
  <svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">
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

  <h1>Chiikawa Gaming Club</h1>
  <p class="subtitle">pequeño, débil, un poco torpe... pero gamer</p>
  <nav>
    <a href="/">Inicio</a>
    <a href="/muro">Muro</a>
    <a href="/perfil">Mi perfil</a>
    <a href="/logout">Salir</a>
  </nav>
  {content}

  <script>
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


# ---------- Rutas ----------

@app.route("/")
def home():
    nombre = session.get("username")
    if nombre:
        titulo = f"Hola, {escape(nombre)}"
        texto = "Elige tu equipo, deja un mensaje en el muro y descubre cosas que quizá no sabías de Chiikawa."
        botones = (
            f'<a class="btn" href="{url_for("muro")}">Ir al muro</a>'
            f'<a class="btn alt" href="{url_for("perfil")}">Ver mi perfil</a>'
        )
    else:
        titulo = "Entra al club"
        texto = "Un club para jugar, charlar y aprender sobre Chiikawa. Inicia sesión para escribir en el muro y elegir equipo."
        botones = f'<a class="btn" href="{url_for("login")}">Iniciar sesión</a>'

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
    return BASE.format(content=content)


# === PUNTO DE ENTRADA 1: LOGIN (vulnerable a SQL Injection) ===
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- CORREGIDO: consulta parametrizada (prepared statement).
        #     El username y password SIEMPRE se tratan como datos, nunca
        #     como parte del código SQL, sin importar qué caracteres traigan. ---
        db = get_db()
        query = "SELECT * FROM jugadores WHERE username = ? AND password = ?"
        cur = db.execute(query, (username, password))
        user = cur.fetchone()
        # -----------------------------------------------------------------

        if user:
            session["username"] = user["username"]
            # NOTA: no hay segundo factor aquí (falta MFA)
            return redirect(url_for("perfil"))
        else:
            error = "Usuario o contraseña incorrectos."

    form = """
    <div class="card">
      <h2>(｡•ᴗ•｡) Iniciar sesión</h2>
      <form method="post">
        <label>Usuario</label>
        <input type="text" name="username" placeholder="ej: chiikawa">
        <label>Contraseña</label>
        <input type="password" name="password" placeholder="••••••••">
        <button type="submit">Entrar 🎮</button>
      </form>
      {error}
      <p class="hint">Prueba: chiikawa / sakura123</p>
    </div>
    """.format(error=f"<p class='error'>⚠️ {error}</p>" if error else "")
    return BASE.format(content=form)


# === PUNTO DE ENTRADA 2: MURO DE MENSAJES (vulnerable a XSS almacenado) ===
@app.route("/muro", methods=["GET", "POST"])
def muro():
    if "username" not in session:
        return redirect(url_for("login"))

    db = get_db()
    if request.method == "POST":
        contenido = request.form.get("contenido", "")
        db.execute(
            "INSERT INTO mensajes (autor, contenido) VALUES (?, ?)",
            (session["username"], contenido),
        )
        db.commit()

    mensajes = db.execute(
        "SELECT autor, contenido FROM mensajes ORDER BY id DESC"
    ).fetchall()

    # --- VULNERABILIDAD: el contenido se inserta tal cual en el HTML, sin escapar ---
    lista_html = "".join(
        f"<div class='msg-card n{AVATARES.index(avatar_key(m['autor']))}'>"
        f"{avatar(avatar_key(m['autor']))}"
        f"<div class='msg-body'><b>{m['autor']}</b>: {m['contenido']}</div></div>"
        for m in mensajes
    )
    # --------------------------------------------------------------------------
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

    form = f"""
    <div class="card composer">
      {avatar(avatar_key(session["username"]), "big")}
      <form method="post">
        <h2>Muro del club</h2>
        <label for="contenido">Tu mensaje</label>
        <input type="text" id="contenido" name="contenido" placeholder="Escribe algo para tu club...">
        <button type="submit">Publicar</button>
      </form>
    </div>
    {trivia_box("Mientras lees el muro", "mini lav", 3)}
    {lista_html}
    """
    return BASE.format(content=form)


# === PUNTO DE ENTRADA 3: UNIRSE A UN CLUB (vulnerable a CSRF) ===
@app.route("/perfil")
def perfil():
    if "username" not in session:
        return redirect(url_for("login"))
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
          <input type="radio" name="club" value="{nombre_club}" {marcado} {requerido}>
          <span class="tile-body">
            {avatar(info["av"])}
            <span class="tile-text">
              <b>{nombre_club}</b>
              <small>{info["lema"]}</small>
            </span>
          </span>
        </label>
        """

    info_club = CLUBES.get(user["club"])
    if info_club:
        curiosidad = f"""
        <section class="card sky">
          <h2>Curiosidad de tu club</h2>
          <p class="chip">{user['club']}</p>
          <p>{info_club['dato']}</p>
        </section>
        """
    else:
        curiosidad = trivia_box("Curiosidad", "sky", 5)

    content = f"""
    <section class="card carnet butter">
      {avatar(avatar_key(user['username']), "big")}
      <div>
        <h2>Hola, {user['username']}</h2>
        <p>Tu club actual: <span class="badge">{user['club']}</span></p>
      </div>
    </section>

    <section class="card">
      <h2>Cambiar de club</h2>
      <form method="post" action="{url_for('unirse_club')}">
        <div class="tiles">{tiles}</div>
        <button type="submit">Unirme</button>
      </form>
    </section>

    {curiosidad}
    """
    return BASE.format(content=content)


@app.route("/unirse-club", methods=["POST"])
def unirse_club():
    if "username" not in session:
        return redirect(url_for("login"))

    # --- VULNERABILIDAD: cambia el estado del jugador solo con la cookie de sesión,
    #     sin validar ningún token CSRF. Un sitio externo podría enviar este
    #     mismo POST "en nombre" del usuario si este tiene la sesión abierta. ---
    nuevo_club = request.form.get("club", "Sin club")
    db = get_db()
    db.execute(
        "UPDATE jugadores SET club = ? WHERE username = ?",
        (nuevo_club, session["username"]),
    )
    db.commit()
    # --------------------------------------------------------------------------

    return redirect(url_for("perfil"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)