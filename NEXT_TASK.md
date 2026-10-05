# NEXT_TASK — Prompt para la próxima sesión

Última actualización: 2026-10-05

```
Proyecto: lista-contactos (/Users/guillermoandrada/Projects/lista-contactos). Flask 2.3 + Flask-SQLAlchemy,
SQLite local / Postgres (Neon) en prod, PWA, deploy en Vercel (cada push a main despliega). Todo en español.
Commits en Conventional Commits, SIN líneas de atribución a Claude/Anthropic.

ESTADO: rama main. Pusheado hasta 6b03ae2. El rediseño de la tabla de escritorio está commiteado en local
(chore/feat de contactos.html) pero SIN pushear ni verificar en navegador.

COMPLETADO (2026-10-05):
- Caída de producción: FUNCTION_INVOCATION_FAILED por `No module named 'psycopg'` (DATABASE_URL con otro
  driver). Fix en app.py: la URL se normaliza a postgresql+psycopg2:// (commit 6b03ae2, ya en prod, /login 200).
- templates/contactos.html (escritorio): tabla compacta (table-sm, una línea por fila, sin rayado ni cabecera
  negra), Maps como link, WhatsApp como ícono junto al teléfono, acciones Confirmar/Editar/Eliminar en una fila
  con botones outline. El JS del buscador ahora usa #tablaContactos y #tablaEliminados.

PRÓXIMAS PRIORIDADES:
1. Revisar visualmente el rediseño en navegador (escritorio) y pushear si gusta.
2. Aplicar el mismo criterio minimalista a la vista móvil (cards) y a "Contactos Eliminados".
3. Considerar README mínimo, .python-version (el build usa 3.12 por defecto; vercel.json pide 3.10 y se ignora)
   y tests básicos (no existen).

CONTEXTO TÉCNICO:
- Lógica en app.py (rutas: /contactos, confirmar_actualizacion, eliminar, restaurar, admin/usuarios).
- app.py hace consultas a la DB al importarse: si la DB falla, toda la web da 500.
- Logs de prod: `vercel logs <url>` (solo en vivo, 5 min); el proyecto no está linkeado (`vercel link`).
- Acciones de admin solo si session['rol'] == 'admin'.
- Preferencia del usuario: pocos colores, pocos botones, filas compactas (ver memoria ui-minimalista-compacto).
```
