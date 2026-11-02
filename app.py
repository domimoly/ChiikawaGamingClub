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


# ---------- Plantillas (inline para mantener la app en un solo archivo) ----------

BASE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Chiikawa Gaming Club</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Baloo+2:wght@500;700&family=Nunito:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --pink: #ff9eb5;
      --pink-dark: #ff7a9d;
      --lavender: #cdb8f0;
      --mint: #a8e6cf;
      --cream: #fff7f0;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: 'Nunito', sans-serif;
      background: linear-gradient(160deg, #ffe3ec 0%, #f3e6ff 45%, #e3f6ff 100%);
      color: #5a4a52;
      max-width: 640px;
      margin: 0 auto;
      padding: 28px 18px 60px;
      min-height: 100vh;
    }}
    h1 {{
      font-family: 'Baloo 2', cursive;
      color: var(--pink-dark);
      text-align: center;
      font-size: 2.1em;
      margin-bottom: 4px;
      text-shadow: 0 2px 0 #fff;
    }}
    .subtitle {{
      text-align: center;
      color: #a98fae;
      font-size: 0.9em;
      margin-bottom: 18px;
    }}
    nav {{
      display: flex;
      justify-content: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 22px;
    }}
    nav a {{
      background: white;
      color: var(--pink-dark);
      text-decoration: none;
      padding: 8px 16px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.9em;
      box-shadow: 0 2px 5px rgba(255,122,157,.25);
      transition: transform .15s ease;
    }}
    nav a:hover {{ transform: translateY(-2px) scale(1.04); }}
    .card {{
      background: white;
      border-radius: 20px;
      padding: 20px 22px;
      margin: 14px 0;
      box-shadow: 0 4px 14px rgba(200,140,170,.18);
      border: 2px solid #ffe3ec;
    }}
    .card h2 {{
      font-family: 'Baloo 2', cursive;
      color: var(--pink-dark);
      margin-top: 0;
      font-size: 1.3em;
    }}
    label {{ font-weight: 700; color: #a98fae; font-size: .9em; }}
    input[type=text], input[type=password], select {{
      padding: 10px 12px;
      margin: 6px 0 14px;
      width: 100%;
      border: 2px solid #ffd6e3;
      border-radius: 12px;
      font-family: 'Nunito', sans-serif;
      font-size: 1em;
      background: var(--cream);
    }}
    input:focus, select:focus {{
      outline: none;
      border-color: var(--pink);
    }}
    button {{
      background: linear-gradient(135deg, var(--pink), var(--pink-dark));
      border: none;
      color: white;
      padding: 10px 22px;
      border-radius: 999px;
      cursor: pointer;
      font-weight: 700;
      font-family: 'Nunito', sans-serif;
      font-size: 1em;
      box-shadow: 0 3px 8px rgba(255,122,157,.4);
      transition: transform .15s ease;
    }}
    button:hover {{ transform: translateY(-1px) scale(1.03); }}
    .msg-card {{
      background: var(--cream);
      border-radius: 16px;
      padding: 12px 16px;
      margin: 8px 0;
      border-left: 4px solid var(--lavender);
    }}
    .msg-card b {{ color: var(--pink-dark); }}
    .error {{
      background: #fff0f3;
      color: #c0527a;
      border-radius: 12px;
      padding: 8px 12px;
      font-size: .9em;
      border: 1px solid #ffc9d8;
    }}
    .hint {{ font-size: 12px; color: #b9a3c2; text-align: center; }}
    .badge {{
      display: inline-block;
      background: var(--mint);
      color: #2d6a4f;
      padding: 3px 12px;
      border-radius: 999px;
      font-size: .8em;
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <h1>( 'ᴗ' ) Chiikawa Gaming Club</h1>
  <p class="subtitle">pequeño, débil, un poco torpe... pero gamer ✨</p>
  <nav>
    <a href="/">🏠 Inicio</a>
    <a href="/muro">💬 Muro</a>
    <a href="/perfil">🎮 Mi perfil</a>
    <a href="/logout">🚪 Salir</a>
  </nav>
  {content}
</body>
</html>
"""


# ---------- Rutas ----------

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("perfil"))
    return redirect(url_for("login"))


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
        f"<div class='msg-card'><b>{m['autor']}</b>: {m['contenido']}</div>"
        for m in mensajes
    )
    # --------------------------------------------------------------------------
    if not mensajes:
        lista_html = "<p class='hint'>Todavía no hay mensajes... ¡sé el primero! (｡•́︿•̀｡)</p>"

    form = f"""
    <div class="card">
      <h2>💬 Muro del club</h2>
      <form method="post">
        <input type="text" name="contenido" placeholder="Escribe algo para tu club...">
        <button type="submit">Publicar ✨</button>
      </form>
    </div>
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

    content = f"""
    <div class="card">
      <h2>(ﾉ◕ヮ◕)ﾉ Hola, {user['username']}</h2>
      <p>Tu club actual: <span class="badge">{user['club']}</span></p>
      <form method="post" action="{url_for('unirse_club')}">
        <label>Cambiar de club</label>
        <select name="club">
          <option>Equipo Usagi</option>
          <option>Equipo Momonga</option>
          <option>Equipo Kurimanju</option>
        </select>
        <button type="submit">Unirme 🐾</button>
      </form>
    </div>
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
