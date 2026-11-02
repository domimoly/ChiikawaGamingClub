# Chiikawa Gaming Club 🐾

Mini app Flask con vulnerabilidades intencionales, hecha para practicar la
Evaluación Parcial 2 de Ciberseguridad (EA 2 - OCY1102).

**Úsala solo en tu propio computador, en `localhost`. No la subas a Internet.**

## Cómo correrla

```bash
cd chiikawa_gaming_club
pip install -r requirements.txt --break-system-packages   # o usa un venv
python3 app.py
```

Abre `http://127.0.0.1:5000` en el navegador.

Usuario de prueba: `chiikawa` / contraseña: `sakura123`
(o `hachiware` / `estrella99`, `usagi` / `zanahoria1`)

La base de datos SQLite (`chiikawa.db`) se crea sola la primera vez que
ejecutas `app.py`. Si quieres partir de cero, simplemente bórrala.

## Los 3 puntos de entrada de datos (y su falla)

| # | Punto de entrada | Ruta | Vulnerabilidad | Línea en app.py |
|---|---|---|---|---|
| 1 | Formulario de login (`username`, `password`) | `POST /login` | SQL Injection: la consulta se arma con f-string, sin parametrizar | función `login()` |
| 2 | Mensaje del muro (`contenido`) | `POST /muro` | XSS almacenado: el mensaje se inserta en el HTML sin escapar | función `muro()` |
| 3 | Selector de club (`club`) | `POST /unirse-club` | CSRF: cambia el club del usuario solo con la cookie de sesión, sin token | función `unirse_club()` |

Además, el login **no implementa segundo factor** (falta MFA, IL 2.3).

## Pruebas rápidas para reproducir cada falla

**SQL Injection** — en el login, usuario:
```
x' OR '1'='1
```
contraseña:
```
x' OR '1'='1
```
Entra sin conocer ninguna contraseña real.

**XSS almacenado** — en el muro, escribe:
```
<script>alert('XSS')</script>
```
Se ejecuta cada vez que alguien visita `/muro`.

**CSRF** — con sesión iniciada, este HTML (guardado en un .html aparte y
abierto en el navegador) cambia tu club sin que tú lo pidas desde la app:
```html
<form action="http://127.0.0.1:5000/unirse-club" method="POST">
  <input type="hidden" name="club" value="Equipo Hackeado">
</form>
<script>document.forms[0].submit()</script>
```

## Qué toca hacer en la evaluación (según la rúbrica)

1. Analizar validación/sanitización en los 3 puntos de entrada y describir el proceso.
2. Corregir la inyección SQL (usar `?` con parámetros, no f-strings).
3. Corregir XSS y CSRF (escapar salida; agregar token CSRF con Flask-WTF o similar).
4. Diseñar e implementar MFA en el login.
5. Hacer 3 pruebas de penetración documentadas (puedes reusar las de arriba).
6. Proponer y justificar todas las correcciones en un informe.
