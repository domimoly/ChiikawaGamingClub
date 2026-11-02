"""Fixtures y ayudantes compartidos por los tests.

    client(...)                -> cliente Flask con una base SQLite temporal (aislada de chiikawa.db)
    db_fila(sql)                -> una fila (sqlite3.Row) de la base de datos de prueba actual
    token(client)                -> token CSRF vigente en la sesión del cliente (lo crea si no existe)
    post(client, url, **data)     -> POST incluyendo automáticamente el token CSRF
    login(client, user, pwd)       -> login COMPLETO: contraseña + (activar o resolver) el segundo factor
    paso_valido(secreto, ultimo)    -> un paso TOTP válido y aún no usado, para pruebas de MFA
"""
import re
import time

import pytest

import app as chiikawa


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(chiikawa, "DB_PATH", str(tmp_path / "test.db"))
    chiikawa.init_db()
    chiikawa.app.config["TESTING"] = True
    with chiikawa.app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def _reiniciar_bloqueo_de_intentos():
    """_intentos (fuerza bruta en login/MFA) vive en memoria, fuera de la base de
    datos de prueba, así que sin esto un test que agota intentos a propósito
    (para probar el bloqueo) deja bloqueados a los tests que corren después."""
    chiikawa._intentos.clear()
    yield
    chiikawa._intentos.clear()


def db_fila(sql):
    db = chiikawa.sqlite3.connect(chiikawa.DB_PATH)
    db.row_factory = chiikawa.sqlite3.Row
    fila = db.execute(sql).fetchone()
    db.close()
    return fila


def token(client):
    """Token CSRF de la sesión actual del cliente (lo crea si todavía no existe,
    igual que hace el servidor la primera vez que renderiza un formulario)."""
    with client.session_transaction() as s:
        if "csrf" not in s:
            s["csrf"] = chiikawa.secrets.token_urlsafe(32)
        return s["csrf"]


def post(client, url, **data):
    """POST con el token CSRF correcto ya incluido, para no repetirlo en cada test."""
    data["csrf_token"] = token(client)
    return client.post(url, data=data)


def paso_valido(secreto, ultimo):
    """Un paso TOTP (ventana de 30s) que verificar_totp() aceptaría ahora mismo:
    mayor al último paso ya usado (anti-replay) y dentro de la tolerancia de ±1."""
    actual = int(time.time() // 30)
    for paso in (actual - 1, actual, actual + 1):
        if paso > ultimo:
            return paso
    return actual + 1


def login(client, user="chiikawa", pwd="sakura123"):
    """Hace el login de punta a punta: contraseña y luego el segundo factor.

    Si el jugador todavía no tiene MFA activado, lo activa en el momento
    (como lo haría un jugador real la primera vez). Si ya lo tiene, resuelve
    el desafío /mfa con el código correcto. Devuelve la última respuesta.
    """
    r = post(client, "/login", username=user, password=pwd)
    if r.status_code != 302:
        return r  # credenciales inválidas u otro resultado: nada más que hacer

    fila = db_fila(f"SELECT totp_secret, totp_ultimo FROM jugadores WHERE username = '{user}'")

    if fila and fila["totp_secret"]:
        codigo = chiikawa.totp(fila["totp_secret"], paso_valido(fila["totp_secret"], fila["totp_ultimo"]))
        return post(client, "/mfa", codigo=codigo)

    html = client.get("/mfa/activar").get_data(as_text=True)
    secreto = re.search(r"secret=([A-Z0-9]+)", html).group(1)
    return post(client, "/mfa/activar", codigo=chiikawa.totp(secreto))
