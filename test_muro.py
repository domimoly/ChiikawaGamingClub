"""Pruebas del muro: selección de equipo por mensaje.

Ejecutar:  pip install pytest && pytest -q
Cada prueba usa una base SQLite temporal; no toca chiikawa.db.
"""
import sqlite3

import app as chiikawa
from conftest import login, post  # client y _reiniciar_bloqueo_de_intentos vienen de conftest.py


def ultimo_mensaje():
    db = sqlite3.connect(chiikawa.DB_PATH)
    fila = db.execute("SELECT autor, contenido, club FROM mensajes ORDER BY id DESC").fetchone()
    db.close()
    return fila


def test_muro_requiere_login(client):
    r = client.get("/muro")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_muro_muestra_selector_con_los_tres_clubes(client):
    login(client)
    html = client.get("/muro").get_data(as_text=True)
    assert '<select id="club" name="club">' in html
    for club in chiikawa.CLUBES:
        assert f'<option value="{club}"' in html


def test_selector_parte_en_el_club_actual_del_jugador(client):
    login(client)  # chiikawa -> Equipo Usagi
    html = client.get("/muro").get_data(as_text=True)
    assert '<option value="Equipo Usagi" selected>' in html


def test_mensaje_se_guarda_con_el_equipo_elegido(client):
    login(client)
    post(client, "/muro", contenido="hola", club="Equipo Momonga")
    assert ultimo_mensaje() == ("chiikawa", "hola", "Equipo Momonga")


def test_mensaje_muestra_chip_y_avatar_del_equipo(client):
    login(client)
    post(client, "/muro", contenido="hola", club="Equipo Kurimanju")
    html = client.get("/muro").get_data(as_text=True)
    assert "<span class='chip'>Equipo Kurimanju</span>" in html
    assert 'href="#a-kuri"' in html


def test_ya_no_salen_todos_los_mensajes_con_el_mismo_equipo(client):
    login(client)
    post(client, "/muro", contenido="uno", club="Equipo Usagi")
    post(client, "/muro", contenido="dos", club="Equipo Momonga")
    html = client.get("/muro").get_data(as_text=True)
    assert "Equipo Usagi</span>" in html and "Equipo Momonga</span>" in html


def test_club_invalido_cae_al_club_actual(client):
    login(client)
    post(client, "/muro", contenido="hola", club="Equipo Inventado")
    assert ultimo_mensaje()[2] == "Equipo Usagi"


def test_sin_campo_club_usa_el_club_actual(client):
    login(client, "hachiware", "estrella99")  # Equipo Momonga
    post(client, "/muro", contenido="hola")
    assert ultimo_mensaje()[2] == "Equipo Momonga"


def test_mensaje_vacio_no_se_guarda(client):
    login(client)
    post(client, "/muro", contenido="   ", club="Equipo Usagi")
    assert ultimo_mensaje() is None


def test_nombre_de_club_no_se_inyecta_como_html(client):
    login(client)
    post(client, "/muro", contenido="x", club="<b>x</b>")
    html = client.get("/muro").get_data(as_text=True)
    assert "<b>x</b></span>" not in html


def test_migracion_agrega_columna_club_a_base_antigua(tmp_path, monkeypatch):
    ruta = tmp_path / "vieja.db"
    db = sqlite3.connect(ruta)
    db.executescript("""
        CREATE TABLE jugadores (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                                password TEXT NOT NULL, club TEXT NOT NULL DEFAULT 'Sin club');
        CREATE TABLE mensajes (id INTEGER PRIMARY KEY AUTOINCREMENT, autor TEXT NOT NULL, contenido TEXT NOT NULL);
        INSERT INTO jugadores (username, password, club) VALUES ('usagi', 'zanahoria1', 'Equipo Usagi');
        INSERT INTO mensajes (autor, contenido) VALUES ('usagi', 'mensaje viejo');
    """)
    db.commit()
    db.close()
    monkeypatch.setattr(chiikawa, "DB_PATH", str(ruta))
    chiikawa.init_db()
    db = sqlite3.connect(ruta)
    assert db.execute("SELECT club FROM mensajes").fetchone() == ("Equipo Usagi",)
    db.close()


def test_paginas_principales_responden(client):
    login(client)
    for ruta in ("/", "/juego", "/perfil", "/muro"):
        assert client.get(ruta).status_code == 200
