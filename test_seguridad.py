"""Pruebas de seguridad: cada falla del README queda cubierta por pruebas que fallarían
si la vulnerabilidad volviera. Ejecutar:  pytest -q

  A. SQL Injection          D. MFA (TOTP)
  B. XSS almacenado         E. Contraseñas, sesión y cabeceras
  C. CSRF                   F. Validación de entradas
"""
import base64
import re

import pytest

import app as chiikawa
from conftest import db_fila, login, paso_valido, post, token


# ───────────────────────── A. SQL Injection ─────────────────────────

PAYLOADS_SQLI = [
    "x' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "chiikawa' --",
    "'; DROP TABLE jugadores; --",
    "x' UNION SELECT 1,2,3,4,5,6 --",
]


@pytest.mark.parametrize("payload", PAYLOADS_SQLI)
def test_sqli_en_usuario_y_password_no_da_acceso(client, payload):
    r = post(client, "/login", username=payload, password=payload)
    assert r.status_code == 200 and "incorrectos" in r.get_data(as_text=True)
    assert client.get("/perfil").status_code == 302       # sigue sin sesión
    with client.session_transaction() as s:
        assert "pendiente" not in s and "username" not in s


def test_sqli_con_usuario_valido_y_password_inyectada(client):
    r = post(client, "/login", username="chiikawa", password="x' OR '1'='1")
    assert "incorrectos" in r.get_data(as_text=True)


def test_sqli_no_destruye_la_tabla(client):
    post(client, "/login", username="'; DROP TABLE jugadores; --", password="x")
    assert db_fila("SELECT COUNT(*) AS n FROM jugadores")["n"] == 3


def test_mensaje_de_error_no_distingue_usuario_inexistente(client):
    a = post(client, "/login", username="noexiste", password="loquesea").get_data(as_text=True)
    b = post(client, "/login", username="chiikawa", password="mala-clave").get_data(as_text=True)
    assert "Usuario o contraseña incorrectos." in a and "Usuario o contraseña incorrectos." in b


# ───────────────────────── B. XSS almacenado ─────────────────────────

PAYLOADS_XSS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
]


@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_xss_en_mensaje_se_escapa(client, payload):
    login(client)
    post(client, "/muro", contenido=payload, club="Equipo Usagi")
    html = client.get("/muro").get_data(as_text=True)
    assert payload not in html                          # nunca aparece tal cual
    assert "&lt;" in html                               # aparece como texto escapado


def test_xss_no_hay_scripts_sin_nonce(client):
    login(client)
    post(client, "/muro", contenido="<script>alert('XSS')</script>", club="Equipo Usagi")
    html = client.get("/muro").get_data(as_text=True)
    assert len(re.findall(r"<script\b", html)) == len(re.findall(r'<script nonce="[^"]+"', html))


def test_xss_en_nombre_de_club_de_la_base_se_escapa(client):
    login(client)
    db = chiikawa.sqlite3.connect(chiikawa.DB_PATH)
    db.execute("UPDATE jugadores SET club = '<img src=x onerror=alert(1)>' WHERE username = 'chiikawa'")
    db.commit()
    db.close()
    assert "<img src=x onerror" not in client.get("/perfil").get_data(as_text=True)


def test_csp_con_nonce_y_sin_unsafe_inline(client):
    r = client.get("/login")
    csp = r.headers["Content-Security-Policy"]
    nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in r.get_data(as_text=True)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp


# ───────────────────────── C. CSRF ─────────────────────────

def test_csrf_unirse_club_sin_token_es_rechazado(client):
    login(client)
    antes = db_fila("SELECT club FROM jugadores WHERE username='chiikawa'")["club"]
    r = client.post("/unirse-club", data={"club": "Equipo Momonga"})   # lo que haría el HTML atacante
    assert r.status_code == 400
    assert db_fila("SELECT club FROM jugadores WHERE username='chiikawa'")["club"] == antes


def test_csrf_token_falso_es_rechazado(client):
    login(client)
    r = client.post("/unirse-club", data={"club": "Equipo Momonga", "csrf_token": "falso"})
    assert r.status_code == 400


def test_csrf_origen_externo_es_rechazado_aunque_el_token_sea_valido(client):
    login(client)
    r = client.post("/unirse-club", data={"club": "Equipo Momonga", "csrf_token": token(client)},
                    headers={"Origin": "http://sitio-malicioso.example"})
    assert r.status_code == 403


def test_csrf_origen_null_es_rechazado(client):
    login(client)
    r = client.post("/unirse-club", data={"club": "Equipo Momonga", "csrf_token": token(client)},
                    headers={"Origin": "null"})
    assert r.status_code == 403


def test_csrf_con_token_valido_funciona(client):
    login(client)
    r = post(client, "/unirse-club", club="Equipo Momonga")
    assert r.status_code == 302
    assert db_fila("SELECT club FROM jugadores WHERE username='chiikawa'")["club"] == "Equipo Momonga"


def test_csrf_la_ruta_hackeada_del_readme_ya_no_funciona(client):
    login(client)
    r = post(client, "/unirse-club", club="Equipo Hackeado")      # token válido, club inventado
    assert r.status_code == 400
    assert db_fila("SELECT club FROM jugadores WHERE username='chiikawa'")["club"] != "Equipo Hackeado"


def test_csrf_muro_sin_token_es_rechazado(client):
    login(client)
    assert client.post("/muro", data={"contenido": "hola"}).status_code == 400
    assert db_fila("SELECT COUNT(*) AS n FROM mensajes")["n"] == 0


def test_csrf_login_sin_token_es_rechazado(client):
    assert client.post("/login", data={"username": "chiikawa", "password": "sakura123"}).status_code == 400


def test_csrf_logout_es_post_y_exige_token(client):
    login(client)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    assert client.get("/perfil").status_code == 200       # la sesión sigue viva
    assert post(client, "/logout").status_code == 302
    assert client.get("/perfil").status_code == 302


def test_csrf_el_token_cambia_entre_sesiones(client):
    t1 = token(client)
    with chiikawa.app.test_client() as otro:
        assert token(otro) != t1


# ───────────────────────── D. MFA (TOTP) ─────────────────────────

def test_totp_vectores_oficiales_rfc6238():
    secreto = base64.b32encode(b"12345678901234567890").decode()
    # RFC 6238 (SHA-1), últimos 6 dígitos de los códigos de 8 dígitos publicados.
    assert chiikawa.totp(secreto, 59 // 30) == "287082"
    assert chiikawa.totp(secreto, 1111111109 // 30) == "081804"
    assert chiikawa.totp(secreto, 1234567890 // 30) == "005924"
    assert chiikawa.totp(secreto, 2000000000 // 30) == "279037"


def test_mfa_contrasena_sola_no_da_acceso_a_nada(client):
    post(client, "/login", username="chiikawa", password="sakura123")
    for ruta in ("/perfil", "/muro"):
        r = client.get(ruta)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.post("/unirse-club", data={"club": "Equipo Usagi", "csrf_token": token(client)}).status_code == 302


def test_mfa_primer_login_pide_activar_autenticador(client):
    r = post(client, "/login", username="chiikawa", password="sakura123")
    assert r.headers["Location"].endswith("/mfa")
    assert client.get("/mfa").headers["Location"].endswith("/mfa/activar")
    assert "clave manual" in client.get("/mfa/activar").get_data(as_text=True)


def test_mfa_activacion_con_codigo_correcto_guarda_secreto_y_entra(client):
    login(client)
    assert client.get("/perfil").status_code == 200
    assert db_fila("SELECT totp_secret FROM jugadores WHERE username='chiikawa'")["totp_secret"]


def test_mfa_activacion_con_codigo_incorrecto_no_guarda_nada(client):
    post(client, "/login", username="chiikawa", password="sakura123")
    client.get("/mfa/activar")
    r = post(client, "/mfa/activar", codigo="000000")
    assert "incorrecto" in r.get_data(as_text=True)
    assert db_fila("SELECT totp_secret FROM jugadores WHERE username='chiikawa'")["totp_secret"] is None
    assert client.get("/perfil").status_code == 302


def test_mfa_codigo_incorrecto_rechazado_y_correcto_aceptado(client):
    login(client)
    post(client, "/logout")
    post(client, "/login", username="chiikawa", password="sakura123")
    assert client.get("/mfa").status_code == 200
    r = post(client, "/mfa", codigo="123456")
    assert "incorrecto" in r.get_data(as_text=True) and client.get("/perfil").status_code == 302
    fila = db_fila("SELECT totp_secret, totp_ultimo FROM jugadores WHERE username='chiikawa'")
    post(client, "/mfa", codigo=chiikawa.totp(fila["totp_secret"], paso_valido(fila["totp_secret"], fila["totp_ultimo"])))
    assert client.get("/perfil").status_code == 200


def test_mfa_codigo_no_numerico_se_rechaza(client):
    login(client)
    post(client, "/logout")
    post(client, "/login", username="chiikawa", password="sakura123")
    for malo in ("abcdef", "12345", "1234567", "' OR 1=1", "<script>"):
        assert "debe tener 6 dígitos" in post(client, "/mfa", codigo=malo).get_data(as_text=True)


def test_mfa_no_permite_reutilizar_un_codigo(client):
    login(client)                                          # consume el código del paso actual
    secreto = db_fila("SELECT totp_secret, totp_ultimo FROM jugadores WHERE username='chiikawa'")
    usado = chiikawa.totp(secreto["totp_secret"], secreto["totp_ultimo"])
    post(client, "/logout")
    post(client, "/login", username="chiikawa", password="sakura123")
    r = post(client, "/mfa", codigo=usado)                 # replay del mismo código
    assert "incorrecto o ya usado" in r.get_data(as_text=True)
    assert client.get("/perfil").status_code == 302


def test_mfa_bloqueo_por_fuerza_bruta(client):
    login(client)
    post(client, "/logout")
    post(client, "/login", username="chiikawa", password="sakura123")
    for _ in range(chiikawa.MAX_INTENTOS):
        post(client, "/mfa", codigo="000000")
    r = post(client, "/mfa", codigo="000000")
    assert "Demasiados intentos" in r.get_data(as_text=True)


def test_mfa_no_se_puede_reenrolar_si_ya_tiene_autenticador(client):
    login(client)
    post(client, "/logout")
    post(client, "/login", username="chiikawa", password="sakura123")
    assert client.get("/mfa/activar").headers["Location"].endswith("/mfa")


def test_mfa_sin_pasar_por_login_redirige(client):
    assert client.get("/mfa").status_code == 302
    assert client.get("/mfa/activar").status_code == 302


def test_mfa_estado_pendiente_no_sirve_como_sesion(client):
    post(client, "/login", username="chiikawa", password="sakura123")
    with client.session_transaction() as s:
        assert "username" not in s and s["pendiente"] == "chiikawa"


# ───────────────────────── E. Contraseñas, sesión y cabeceras ─────────────────────────

def test_contrasenas_guardadas_con_hash(client):
    for fila in chiikawa.sqlite3.connect(chiikawa.DB_PATH).execute("SELECT password FROM jugadores"):
        assert fila[0].startswith("scrypt:") and "sakura123" not in fila[0]


def test_migracion_convierte_contrasenas_en_texto_plano_a_hash(tmp_path, monkeypatch):
    ruta = tmp_path / "vieja.db"
    db = chiikawa.sqlite3.connect(ruta)
    db.executescript("""CREATE TABLE jugadores (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, club TEXT NOT NULL DEFAULT 'Sin club');
        INSERT INTO jugadores (username, password, club) VALUES ('usagi', 'zanahoria1', 'Equipo Usagi');""")
    db.commit(); db.close()
    monkeypatch.setattr(chiikawa, "DB_PATH", str(ruta))
    chiikawa.init_db()
    clave = chiikawa.sqlite3.connect(ruta).execute("SELECT password FROM jugadores").fetchone()[0]
    assert clave.startswith("scrypt:") and chiikawa.check_password_hash(clave, "zanahoria1")


def test_bloqueo_de_login_por_fuerza_bruta(client):
    for _ in range(chiikawa.MAX_INTENTOS):
        post(client, "/login", username="chiikawa", password="mala")
    r = post(client, "/login", username="chiikawa", password="sakura123")   # aun con la clave correcta
    assert "Demasiados intentos" in r.get_data(as_text=True)
    with client.session_transaction() as s:
        assert "pendiente" not in s


def test_login_cambia_la_sesion_contra_fijacion(client):
    token(client)
    with client.session_transaction() as s:
        antes = s["csrf"]
    post(client, "/login", username="chiikawa", password="sakura123", csrf_token=antes)
    with client.session_transaction() as s:
        assert "csrf" not in s or s["csrf"] != antes


def test_cookie_de_sesion_httponly_y_samesite(client):
    cookie = client.get("/login").headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_cabeceras_de_seguridad(client):
    h = client.get("/login").headers
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert h["Referrer-Policy"] == "same-origin" and h["Cache-Control"] == "no-store"


def test_clave_secreta_no_esta_en_el_codigo():
    assert chiikawa.app.secret_key != "clave-super-secreta-cambiar" and len(chiikawa.app.secret_key) >= 32


def test_rutas_protegidas_sin_sesion_redirigen_al_login(client):
    for ruta in ("/muro", "/perfil"):
        r = client.get(ruta)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_modo_debug_apagado_por_defecto():
    assert chiikawa.app.debug is False


# ───────────────────────── F. Validación de entradas ─────────────────────────

@pytest.mark.parametrize("usuario", ["", "ab", "a" * 33, "con espacio", "ñandú", "a;b", "a\x00b"])
def test_login_rechaza_usuarios_con_formato_invalido(client, usuario):
    r = post(client, "/login", username=usuario, password="sakura123")
    assert "incorrectos" in r.get_data(as_text=True)


def test_login_rechaza_password_gigante(client):
    r = post(client, "/login", username="chiikawa", password="a" * 10_000)
    assert r.status_code in (200, 413) and client.get("/perfil").status_code == 302


def test_muro_rechaza_mensaje_demasiado_largo(client):
    login(client)
    r = post(client, "/muro", contenido="a" * (chiikawa.MAX_MENSAJE + 1), club="Equipo Usagi")
    assert "muy largo" in r.get_data(as_text=True)
    assert db_fila("SELECT COUNT(*) AS n FROM mensajes")["n"] == 0


def test_muro_acepta_mensaje_en_el_limite(client):
    login(client)
    post(client, "/muro", contenido="a" * chiikawa.MAX_MENSAJE, club="Equipo Usagi")
    assert db_fila("SELECT COUNT(*) AS n FROM mensajes")["n"] == 1


def test_muro_elimina_caracteres_de_control(client):
    login(client)
    post(client, "/muro", contenido="ho\x00la\x07", club="Equipo Usagi")
    assert db_fila("SELECT contenido FROM mensajes")["contenido"] == "hola"


def test_muro_conserva_tildes_y_emojis(client):
    login(client)
    post(client, "/muro", contenido="¡Hola, ñandú! 🐰", club="Equipo Usagi")
    assert "¡Hola, ñandú! 🐰" in client.get("/muro").get_data(as_text=True)


def test_cuerpo_post_gigante_es_rechazado(client):
    r = client.post("/login", data={"username": "a", "password": "x" * 100_000, "csrf_token": token(client)})
    assert r.status_code == 413
