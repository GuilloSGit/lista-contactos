import os
import sys
import tempfile

import pytest

# Los tests nunca deben tocar la base real: base SQLite temporal y sin cargar .env
# (app.py hace load_dotenv(override=True), que pisaría DATABASE_URL con la de producción).
_tmpdir = tempfile.mkdtemp(prefix="lista-contactos-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmpdir, 'test.db')}"
os.environ["SECRET_KEY"] = "test-secret"

import dotenv  # noqa: E402

dotenv.load_dotenv = lambda *a, **k: False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402
from app import app, db, Contacto, UsuarioAutorizado  # noqa: E402

assert app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///" + _tmpdir)

app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

# validate_email consulta DNS por defecto: los tests no deben depender de la red ni de que
# el dominio de prueba (example.com) tenga registros MX.
_validate_email_real = app_module.validate_email
app_module.validate_email = lambda email, **kw: _validate_email_real(email, check_deliverability=False)

ADMIN_EMAIL = "guillermoandrada@gmail.com"
USER_EMAIL = "usuario@example.com"


@pytest.fixture(autouse=True)
def base_limpia():
    """Cada test arranca con la base vacía, salvo el admin y un usuario normal."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(UsuarioAutorizado(email=ADMIN_EMAIL, main_name="Guillermo", rol="admin"))
        db.session.add(UsuarioAutorizado(email=USER_EMAIL, main_name="Usuario", rol="usuario"))
        db.session.commit()
    yield


@pytest.fixture
def client():
    return app.test_client()


def _login(client, email):
    return client.post("/login", data={"email": email})


@pytest.fixture
def admin(client):
    _login(client, ADMIN_EMAIL)
    return client


@pytest.fixture
def usuario(client):
    _login(client, USER_EMAIL)
    return client


@pytest.fixture
def crear_contacto():
    def _crear(**kw):
        datos = dict(nombre="Juan Pérez", telefono="+54 9 2644 11-3283", direccion="Calle 1", activo=True)
        datos.update(kw)
        with app.app_context():
            c = Contacto(**datos)
            db.session.add(c)
            db.session.commit()
            return c.id
    return _crear


@pytest.fixture
def obtener_contacto():
    def _obtener(contacto_id):
        with app.app_context():
            c = db.session.get(Contacto, contacto_id)
            db.session.expunge(c)
            return c
    return _obtener
