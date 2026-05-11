import os
from datetime import datetime, timedelta
from app import app, db, Contacto

def force_update_all():
    with app.app_context():
        # Hacer que todas las fechas sean de hace 150 días
        fecha_antigua = datetime.utcnow() - timedelta(days=150)
        contactos = Contacto.query.all()
        for contacto in contactos:
            contacto.fecha_actualizacion = fecha_antigua
            contacto.fecha_creacion = fecha_antigua
        db.session.commit()
        print(f"Se actualizaron {len(contactos)} contactos a la fecha {fecha_antigua}")

if __name__ == "__main__":
    force_update_all()
