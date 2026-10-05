# NEXT_TASK — Prompt para la próxima sesión

Última actualización: 2026-10-05

```
Proyecto: lista-contactos (/Users/guillermoandrada/Projects/lista-contactos). Flask 2.3 + Flask-SQLAlchemy,
SQLite local / Postgres (Neon) en prod, PWA, deploy en Vercel (cada push a main despliega). Todo en español.
Commits en Conventional Commits, SIN líneas de atribución a Claude/Anthropic.

ESTADO: rama main. Rediseño de escritorio y botón de instalación desplegados; el rediseño móvil está
commiteado en local SIN pushear. Nada verificado en navegador real.

COMPLETADO (2026-10-05):
- Caída de producción: FUNCTION_INVOCATION_FAILED por `No module named 'psycopg'` (DATABASE_URL con otro
  driver). Fix en app.py: la URL se normaliza a postgresql+psycopg2:// (commit 6b03ae2, ya en prod, /login 200).
- templates/contactos.html (escritorio): tabla compacta (table-sm, una línea por fila, sin rayado ni cabecera
  negra), Maps como link, WhatsApp como ícono junto al teléfono, acciones Confirmar/Editar/Eliminar en una fila
  con botones outline. El JS del buscador ahora usa #tablaContactos y #tablaEliminados.

- templates/contactos.html (móvil): cards compactas sin fondo rojo ni sombras; nombre + Desactualizado en una
  línea, teléfono+ícono WhatsApp y Maps en otra, acciones Confirmar/Editar/Eliminar en una fila outline.
  Las cards conservan la clase .card (el buscador JS las filtra por ella).
- PWA: el manifest y sw.js ya existían; se agregó botón "Instalar app" en el navbar (base.html, evento
  beforeinstallprompt; en iOS muestra instrucciones) y `id`/`scope` en manifest.json.

PRÓXIMAS PRIORIDADES:
1. Pushear el rediseño móvil si el usuario lo aprueba. Probar en navegador: rediseño de /contactos (escritorio y móvil) y la instalación como app (Chrome/Android/iOS).
2. Aplicar el mismo criterio minimalista a la tabla "Contactos Eliminados".
3. Considerar README mínimo, .python-version (el build usa 3.12 por defecto; vercel.json pide 3.10 y se ignora)
   y tests básicos (no existen).

CONTEXTO TÉCNICO:
- Lógica en app.py (rutas: /contactos, confirmar_actualizacion, eliminar, restaurar, admin/usuarios).
- app.py hace consultas a la DB al importarse: si la DB falla, toda la web da 500.
- Logs de prod: `vercel logs <url>` (solo en vivo, 5 min); el proyecto no está linkeado (`vercel link`).
- Acciones de admin solo si session['rol'] == 'admin'.
- Preferencia del usuario: pocos colores, pocos botones, filas compactas (ver memoria ui-minimalista-compacto).
```
