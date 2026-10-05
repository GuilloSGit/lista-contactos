# /cierre — Cierre de sesión (lista-contactos)

Proyecto: app Flask 2.3 + Flask-SQLAlchemy (SQLite local `contactos.db`, Postgres/Neon en prod), PWA,
deploy en Vercel (`vercel.json`, `wsgi.py`). Repo único, remoto `origin` = GitHub `GuilloSGit/lista-contactos`, rama `main`.
Hay `README.md` y tests (`pytest`); no hay ROADMAP/PROGRESS. La memoria vive en
`~/.claude/projects/-Users-guillermoandrada-Projects-lista-contactos/memory/`.

## 1. Estado git
`git status`, `git log --oneline -5`, `git diff --stat`.

## 2. Memoria del proyecto
Actualizar la memoria (decisiones, gotchas, cambios de plan). Solo lo no derivable del código.

## 3. Documentación
Actualizar `README.md` solo donde cambió algo (funciones, variables de entorno, deploy, tests).

## 4. Verificación (obligatoria)
- `python3 -m py_compile app.py wsgi.py` y `python3 -m pytest -q` (deben pasar todos)
- Si se tocaron templates: levantar `flask run`/`python app.py` y revisar `/contactos` en escritorio y móvil.
- Si algo falla, no se commitea.
Luego borrar `__pycache__/` y `.pytest_cache/`.

## 5. Commit y push
Conventional Commits, **sin** líneas de atribución a Claude/Anthropic (regla global del usuario).
Push a `origin/main` **siempre**, sin preguntar: invocar `/cierre` ya es la orden de pushear (pedido
explícito del usuario). El push dispara deploy en Vercel; después comprobar con `curl` que `/login` responda 200.

## 6. Prompt para la próxima sesión
Sobrescribir `NEXT_TASK.md` en la raíz (título `# NEXT_TASK — Prompt para la próxima sesión`, fecha
de "Última actualización", prompt completo en bloque de código: estado, COMPLETADO, PRÓXIMAS PRIORIDADES,
CONTEXTO TÉCNICO). Se versiona junto con el commit del cierre. Mostrarlo también en la respuesta final.
