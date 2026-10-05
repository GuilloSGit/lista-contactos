# NEXT_TASK — Prompt para la próxima sesión

Última actualización: 2026-10-05

```
Proyecto: lista-contactos (/Users/guillermoandrada/Projects/lista-contactos). Flask 2.3 + Flask-SQLAlchemy,
SQLite local / Postgres (Neon) en prod, PWA, deploy en Vercel. Todo en español. Commits en Conventional
Commits, SIN líneas de atribución a Claude/Anthropic.

ESTADO: rama main, limpia y pusheada (último commit 598d0bb).

COMPLETADO (2026-10-05):
- templates/contactos.html: se quitó el fondo rojo de filas desactualizadas; ahora hay badge
  "Desactualizado" bajo el nombre (escritorio) y en la alerta (móvil).
- Botones con texto: "Confirmar datos" (antes solo check) y "Eliminar" (antes solo papelera).
- Columna de acciones ordenada (Confirmar arriba, Editar + Eliminar debajo); teléfono sin cortes.
- Se creó .claude/commands/cierre.md.

PRÓXIMAS PRIORIDADES:
1. Verificar visualmente el cambio en navegador (escritorio y móvil) — no se probó en la sesión.
2. Revisar la tabla de "Contactos Eliminados" por consistencia visual.
3. Considerar README mínimo y tests básicos (no existen).

CONTEXTO TÉCNICO:
- Lógica en app.py (rutas: /contactos, confirmar_actualizacion, eliminar, restaurar, admin/usuarios).
- La búsqueda JS en contactos.html filtra tablas y .card; la columna de contactos es col-md-8.
- Acciones de admin solo si session['rol'] == 'admin'.
```
