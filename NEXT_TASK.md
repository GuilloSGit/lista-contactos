# NEXT_TASK — Prompt para la próxima sesión

Última actualización: 2026-10-05

```
Proyecto: lista-contactos (/Users/guillermoandrada/Projects/lista-contactos). Flask 2.3 + Flask-SQLAlchemy,
SQLite local / Postgres (Neon) en prod, PWA, deploy en Vercel (cada push a main despliega). Todo en español.
Commits en Conventional Commits, SIN líneas de atribución a Claude/Anthropic.

ESTADO: rama main, pusheada. Tests (44, pytest), README, .python-version y requirements-dev.txt agregados.
Rediseño de escritorio/móvil/eliminados, modal "+" para nuevo contacto y botón Instalar app desplegados.
Probado con Puppeteer en local (móvil y escritorio); la instalación PWA real no se probó.

COMPLETADO (2026-10-05):
- Caída de producción por driver: `No module named 'psycopg'`. app.py normaliza DATABASE_URL a
  postgresql+psycopg2:// (función normalizar_db_url).
- UI minimalista y compacta en contactos.html: tabla de escritorio, cards móviles y tabla de eliminados.
  "Desactualizado" = texto rojo en móvil, ícono rojo en escritorio. El buscador usa #tablaContactos y
  #tablaEliminados. En móvil el formulario de alta es un modal abierto con "+" junto al título
  (macro form_nuevo_contacto con sufijo de ids para no duplicar ids).
- PWA: botón "Instalar app" (beforeinstallprompt; iOS muestra instrucciones), id/scope en manifest.json.
- Tests + README + .python-version (3.12) + pytest.ini + requirements-dev.txt.
- Bugs arreglados al testear: /health usaba SQL en string (ahora text()); logout dejaba el rol en la sesión
  (ahora session.clear()).

PRÓXIMAS PRIORIDADES:
1. Probar en dispositivos reales la instalación PWA (Chrome/Android/iOS) y guardar un contacto desde el modal.
2. Higiene del repo: hay volcados con datos personales versionados (contactos.csv, datos_exportados.csv,
   contactos_dump.sql, clean_dump.sql, load_to_neon.load, contactos.db, instance/contactos.db). Evaluar
   sacarlos del repo y agregarlos a .gitignore (decisión del usuario; no se tocaron).
3. Limpiar vercel.json (la config "runtime" dentro de builds se ignora) y runtime.txt (python-3.10.0, no se usa).
4. Login: validate_email hace consulta DNS (check_deliverability); si el DNS falla, nadie entra. Evaluar
   desactivarlo en producción. SECRET_KEY y WTF_CSRF_SECRET_KEY tienen valores por defecto de desarrollo.

CONTEXTO TÉCNICO:
- Lógica en app.py (rutas: /contactos, confirmar_actualizacion, eliminar, restaurar, admin/usuarios).
- app.py hace consultas a la DB al importarse: si la DB falla, toda la web da 500.
- Logs de prod: `vercel logs <url>` (solo en vivo, 5 min); el proyecto no está linkeado (`vercel link`).
- Acciones de admin solo si session['rol'] == 'admin'.
- Tests: `pytest` (conftest usa SQLite temporal, anula load_dotenv y validate_email DNS). Local: reiniciar
  el server tras editar templates (no recarga en producción); matar por PID, el proceso se llama `Python app.py`.
- Preferencia del usuario: pocos colores, pocos botones, filas compactas (ver memoria ui-minimalista-compacto).
```
