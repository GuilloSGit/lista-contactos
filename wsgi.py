import os
from app import app, db

try:
    # Crear tablas si no existen
    with app.app_context():
        db.create_all()
except Exception as e:
    print(f"Error al inicializar la base de datos: {str(e)}")

# Esto es necesario para que Vercel pueda servir la aplicación
app = app.server if hasattr(app, 'server') else app

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
