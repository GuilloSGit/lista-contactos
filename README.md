# Lista de Contactos

Directorio de contactos con acceso por correo autorizado. App web en Flask, instalable como PWA
(escritorio y celular), pensada para consultar rápido teléfono, WhatsApp y ubicación en el mapa.

## Funciones

- Ingreso con un correo previamente autorizado (sin contraseña ni consulta DNS: solo cuenta la lista de autorizados).
- Lista de contactos con búsqueda instantánea (ignora mayúsculas y acentos).
- Botón de WhatsApp que arma el link `wa.me` desde el teléfono (maneja formatos argentinos: `+54 9`, `0` inicial, `15`).
- Link a Google Maps por contacto.
- Marca **Desactualizado** a los contactos que llevan más de 125 días sin actualizarse; el admin los confirma con un clic.
- Roles: `admin` (agrega, edita, elimina, restaura, confirma y administra usuarios) y `usuario` (solo consulta).
- El borrado es lógico: los eliminados se listan aparte y se pueden restaurar.
- PWA: botón **Instalar app** en la barra superior (en iOS: Compartir → Agregar a pantalla de inicio).
- En el celular, el formulario de nuevo contacto se abre con el botón **+** junto al título.

## Stack

Flask 2.3 · Flask-SQLAlchemy · Flask-WTF (CSRF) · SQLite en local / PostgreSQL (Neon) en producción ·
Bootstrap 5 · despliegue en Vercel.

## Correr en local

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://localhost:5000
```

Sin `DATABASE_URL` usa SQLite local (`contactos.db`). El primer usuario autorizado (admin) se crea solo
si la tabla está vacía.

## Variables de entorno

| Variable        | Uso                                                                                     |
|-----------------|-----------------------------------------------------------------------------------------|
| `DATABASE_URL`  | URL de Postgres. Se normaliza siempre a `postgresql+psycopg2://` (el driver instalado). |
| `SECRET_KEY`    | Clave de sesión y CSRF. Definida en Vercel (Production, Preview y Development); el valor por defecto es solo de desarrollo. |
| `PORT`          | Puerto local (por defecto 5000).                                                        |

Se pueden poner en un archivo `.env` (ignorado por git).

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Los tests usan una base SQLite temporal y **nunca** cargan `.env`, así que no pueden tocar la base real.
Cubren los modelos (WhatsApp, "desactualizado", mapa, normalización de `DATABASE_URL`) y las rutas
(login, permisos por rol, alta/edición/baja/restauración, usuarios autorizados, `/health`, archivos PWA).

## Deploy

Vercel despliega automáticamente cada push a `main` (`vercel.json`). Python: ver `.python-version`.
Los logs de runtime se ven con `vercel logs <url>`.

> `app.py` consulta la base al importarse: si la base no responde o el driver no está instalado,
> toda la web devuelve 500 (`FUNCTION_INVOCATION_FAILED`).

## Estructura

```
app.py            modelos, rutas y configuración
wsgi.py           entrada alternativa para servidores WSGI
templates/        vistas Jinja (contactos, editar, usuarios, login)
static/           manifest, service worker, íconos
tests/            pytest
```
