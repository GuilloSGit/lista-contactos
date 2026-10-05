from datetime import datetime, timedelta

import pytest

from app import Contacto, normalizar_db_url


@pytest.mark.parametrize("telefono, esperado", [
    ("+54 9 2644 11-3283", "https://wa.me/5492644113283"),     # ya viene con 549
    ("+54 264 4113283", "https://wa.me/5492644113283"),        # +54 sin el 9
    ("2644 15-113283", "https://wa.me/5492644113283"),         # se saca el 15
    ("02644113283", "https://wa.me/5492644113283"),            # se saca el 0 inicial
    ("5492644113283", "https://wa.me/5492644113283"),          # 549 sin +
    ("+1 415 555 2671", "https://wa.me/14155552671"),          # otro país, tal cual
    ("", ""),
    ("sin teléfono", ""),
])
def test_whatsapp_url(telefono, esperado):
    assert Contacto(telefono=telefono).whatsapp_url == esperado


def test_necesita_actualizacion_pasado_el_limite():
    c = Contacto(fecha_actualizacion=datetime.utcnow() - timedelta(days=200))
    assert c.necesita_actualizacion is True


def test_no_necesita_actualizacion_si_es_reciente():
    c = Contacto(fecha_actualizacion=datetime.utcnow() - timedelta(days=10))
    assert c.necesita_actualizacion is False


def test_necesita_actualizacion_usa_fecha_creacion_si_falta_la_otra():
    c = Contacto(fecha_actualizacion=None, fecha_creacion=datetime.utcnow() - timedelta(days=300))
    assert c.necesita_actualizacion is True


def test_embed_map_url_con_coordenadas():
    c = Contacto(gps_url="https://www.google.com/maps?q=-32.5,-68.5", direccion="x")
    assert "q=-32.5,-68.5" in c.embed_map_url


def test_embed_map_url_cae_en_la_direccion():
    c = Contacto(gps_url="", direccion="Güemes 333")
    assert "G%C3%BCemes%20333" in c.embed_map_url


def test_embed_map_url_vacio_sin_datos():
    assert Contacto(gps_url="", direccion="").embed_map_url == ""


@pytest.mark.parametrize("entrada", [
    "postgres://u:p@h/db",
    "postgresql://u:p@h/db",
    "postgresql+psycopg://u:p@h/db",
    "postgresql+psycopg2://u:p@h/db",
])
def test_normalizar_db_url_fuerza_psycopg2(entrada):
    assert normalizar_db_url(entrada) == "postgresql+psycopg2://u:p@h/db"
