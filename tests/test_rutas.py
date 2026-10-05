from app import app, db, Contacto, UsuarioAutorizado
from datetime import datetime, timedelta


# ---------- acceso y sesión ----------

def test_login_get(client):
    assert client.get("/login").status_code == 200


def test_login_usuario_autorizado(client):
    r = client.post("/login", data={"email": "guillermoandrada@gmail.com"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/contactos")


def test_login_usuario_no_autorizado(client):
    r = client.post("/login", data={"email": "intruso@example.com"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/no_autorizado")
    assert client.get("/contactos").status_code == 302


def test_login_email_invalido(client):
    r = client.post("/login", data={"email": "no-es-un-email"})
    assert r.status_code == 200
    assert "correo electrónico válido" in r.get_data(as_text=True)


def test_login_no_consulta_dns(client, monkeypatch):
    """Si el DNS falla, el login no debe depender de check_deliverability."""
    llamadas = []

    def falso(email, **kw):
        llamadas.append(kw)
        return type("V", (), {"email": email})()

    monkeypatch.setattr("app.validate_email", falso)
    client.post("/login", data={"email": "guillermoandrada@gmail.com"})
    assert llamadas == [{"check_deliverability": False}]


def test_contactos_requiere_login(client):
    r = client.get("/contactos")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_logout_limpia_toda_la_sesion(admin):
    admin.get("/logout")
    with admin.session_transaction() as s:
        assert "email" not in s and "rol" not in s
    assert admin.get("/admin/usuarios").status_code == 302


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.get_json()["status"] == "healthy"


def test_archivos_pwa(client):
    assert client.get("/sw.js").mimetype == "application/javascript"
    assert client.get("/favicon.ico").status_code == 200
    m = client.get("/static/manifest.json").get_json()
    assert m["display"] == "standalone" and m["start_url"] == "/"


# ---------- lista de contactos ----------

def test_lista_muestra_solo_activos_a_usuarios(usuario, crear_contacto):
    crear_contacto(nombre="Activo Uno")
    crear_contacto(nombre="Borrado Dos", activo=False)
    html = usuario.get("/contactos").get_data(as_text=True)
    assert "Activo Uno" in html
    assert "Borrado Dos" not in html
    assert "Contactos Eliminados" not in html


def test_usuario_normal_no_ve_acciones_de_admin(usuario, crear_contacto):
    crear_contacto()
    html = usuario.get("/contactos").get_data(as_text=True)
    assert "Eliminar" not in html and "Editar" not in html
    assert "Agregar Nuevo Contacto" not in html


def test_admin_ve_acciones_formulario_y_eliminados(admin, crear_contacto):
    crear_contacto(nombre="Activo Uno")
    crear_contacto(nombre="Borrado Dos", activo=False)
    html = admin.get("/contactos").get_data(as_text=True)
    assert "Eliminar" in html and "Editar" in html
    assert 'id="tablaEliminados"' in html and "Borrado Dos" in html
    assert html.count("Guardar Contacto") == 2  # escritorio + modal móvil
    assert 'id="nuevoContactoModal"' in html


def test_ids_del_formulario_no_se_repiten(admin):
    html = admin.get("/contactos").get_data(as_text=True)
    assert html.count('id="nombre"') == 1 and html.count('id="nombre-m"') == 1


def test_badge_desactualizado(admin, crear_contacto):
    viejo = crear_contacto(nombre="Viejo")
    with app.app_context():
        c = db.session.get(Contacto, viejo)
        c.fecha_actualizacion = datetime.utcnow() - timedelta(days=200)
        db.session.commit()
    html = admin.get("/contactos").get_data(as_text=True)
    assert "Desactualizado" in html and "Confirmar" in html


# ---------- altas, ediciones y bajas ----------

def test_agregar_contacto(admin):
    r = admin.post("/contactos/agregar", data={
        "nombre": " Ana ", "telefono": "+54 9 264 111", "direccion": "Calle 2", "gps_url": ""})
    assert r.status_code == 302
    with app.app_context():
        c = Contacto.query.filter_by(nombre="Ana").one()
        assert c.activo is True and c.direccion == "Calle 2"


def test_agregar_contacto_sin_nombre_falla(admin):
    r = admin.post("/contactos/agregar", data={"telefono": "1"})
    assert r.status_code == 400


def test_agregar_contacto_requiere_login(client):
    assert client.post("/contactos/agregar", data={"nombre": "X"}).status_code == 302
    with app.app_context():
        assert Contacto.query.count() == 0


def test_editar_contacto(admin, crear_contacto, obtener_contacto):
    cid = crear_contacto()
    r = admin.post(f"/contactos/editar/{cid}", data={
        "nombre": "Nuevo Nombre", "telefono": "123", "direccion": "Otra"})
    assert r.status_code == 302
    c = obtener_contacto(cid)
    assert c.nombre == "Nuevo Nombre" and c.direccion == "Otra"


def test_editar_contacto_inexistente(admin):
    assert admin.get("/contactos/editar/999").status_code == 404


def test_eliminar_y_restaurar(admin, crear_contacto, obtener_contacto):
    cid = crear_contacto()
    admin.post(f"/contactos/eliminar/{cid}")
    assert obtener_contacto(cid).activo is False
    admin.post(f"/contactos/restaurar/{cid}")
    assert obtener_contacto(cid).activo is True


def test_confirmar_actualizacion_renueva_la_fecha(admin, crear_contacto, obtener_contacto):
    cid = crear_contacto()
    with app.app_context():
        c = db.session.get(Contacto, cid)
        c.fecha_actualizacion = datetime.utcnow() - timedelta(days=300)
        db.session.commit()
    assert obtener_contacto(cid).necesita_actualizacion is True
    admin.post(f"/contactos/confirmar_actualizacion/{cid}")
    assert obtener_contacto(cid).necesita_actualizacion is False


def test_usuario_normal_no_puede_editar_eliminar_ni_confirmar(usuario, crear_contacto, obtener_contacto):
    cid = crear_contacto()
    for ruta in (f"/contactos/eliminar/{cid}",
                 f"/contactos/restaurar/{cid}",
                 f"/contactos/confirmar_actualizacion/{cid}",
                 f"/contactos/editar/{cid}"):
        r = usuario.post(ruta, data={"nombre": "Hack", "direccion": "x"})
        assert r.status_code == 302, ruta
    c = obtener_contacto(cid)
    assert c.activo is True and c.nombre == "Juan Pérez"


# ---------- administración de usuarios ----------

def test_admin_usuarios_solo_admin(usuario):
    assert usuario.get("/admin/usuarios").status_code == 302


def test_admin_agrega_usuario(admin):
    admin.post("/admin/usuarios", data={"email": "nuevo@example.com", "main_name": "Nuevo", "rol": "usuario"})
    with app.app_context():
        assert UsuarioAutorizado.query.filter_by(email="nuevo@example.com").count() == 1


def test_admin_no_duplica_usuarios(admin):
    for _ in range(2):
        admin.post("/admin/usuarios", data={"email": "dup@example.com", "main_name": "D", "rol": "usuario"})
    with app.app_context():
        assert UsuarioAutorizado.query.filter_by(email="dup@example.com").count() == 1


def test_rol_invalido_se_degrada_a_usuario(admin):
    admin.post("/admin/usuarios", data={"email": "x@example.com", "main_name": "X", "rol": "superadmin"})
    with app.app_context():
        assert UsuarioAutorizado.query.filter_by(email="x@example.com").one().rol == "usuario"


def test_admin_elimina_usuario_pero_no_a_si_mismo(admin):
    with app.app_context():
        otro = UsuarioAutorizado(email="borrar@example.com", main_name="B", rol="usuario")
        db.session.add(otro)
        db.session.commit()
        otro_id = otro.id
        admin_id = UsuarioAutorizado.query.filter_by(email="guillermoandrada@gmail.com").one().id
    admin.post(f"/admin/usuarios/eliminar/{otro_id}")
    admin.post(f"/admin/usuarios/eliminar/{admin_id}")
    with app.app_context():
        assert UsuarioAutorizado.query.filter_by(email="borrar@example.com").count() == 0
        assert UsuarioAutorizado.query.filter_by(email="guillermoandrada@gmail.com").count() == 1


def test_csrf_usa_secret_key_y_no_una_clave_hardcodeada():
    assert "dev-csrf-key-123" not in open("app.py", encoding="utf-8").read()
    assert not app.config.get("WTF_CSRF_SECRET_KEY")


def test_vercel_publica_subcarpetas_de_static():
    """static/* solo toma el primer nivel y dejaba afuera static/icons/ (404 en el manifest)."""
    import json
    builds = json.load(open("vercel.json"))["builds"]
    assert any(b["src"] == "static/**" for b in builds)
