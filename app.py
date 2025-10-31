from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from email_validator import validate_email, EmailNotValidError
import os
import sys

from dotenv import load_dotenv
from pathlib import Path
load_dotenv()

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path, override=True)

app = Flask(__name__)

# Configuración para producción/desarrollo
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

# Configuración de la base de datos
try:
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        raise ValueError("DATABASE_URL no está configurada")
        
    # Asegurarse de que la URL use postgresql://
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
except Exception as e:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contactos.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar extensión de base de datos
db = SQLAlchemy(app)

# Inicializar CSRF con configuración básica
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'dev-csrf-key-123'
csrf = CSRFProtect(app)

# Agregar CSRF token al contexto de la plantilla
@app.context_processor
def inject_csrf():
    # Generar token CSRF para todas las rutas
    csrf_token = generate_csrf()
    return {'csrf_token': csrf_token}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'rol' not in session or session['rol'] != 'admin':
            flash('No tienes permisos para realizar esta acción', 'error')
            return redirect(url_for('lista_contactos'))
        return f(*args, **kwargs)
    return decorated_function

# Modelo para usuarios autorizados
class UsuarioAutorizado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    main_name = db.Column(db.String(100), nullable=True)
    rol = db.Column(db.String(20), nullable=False, default='usuario')  # 'usuario' o 'admin'

# Modelo para contactos
class Contacto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    direccion = db.Column(db.String(200), nullable=False)
    gps_url = db.Column(db.String(500), nullable=True)
    activo = db.Column(db.Boolean, default=True, nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())
    fecha_actualizacion = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# Datos iniciales de ejemplo (comentados)
"""
DATOS_INICIALES_CONTACTOS = [
    {
        "nombre": "Salón del Reino",
        "email": "",
        "telefono": "+54 11 1234-5678",
        "direccion": "Su Casa 554 Barrio Sarmiento",
        "gps_url": ""
    },
    {
        "nombre": "María García",
        "email": "maria@ejemplo.com",
        "telefono": "+54 11 8765-4321",
        "direccion": "Su Casa 555 Barrio Sarmiento",
        "gps_url": ""
    },
    {
        "nombre": "Carlos López",
        "email": "carlos@ejemplo.com",
        "telefono": "+54 11 5555-1234",
        "direccion": "Su Casa 556 Barrio Sarmiento",
        "gps_url": ""
    }
]
"""

# Crear tablas en la base de datos
with app.app_context():
    db.create_all()

    # Agregar algunos correos de ejemplo a la lista de autorizados
    if not UsuarioAutorizado.query.first():
        usuarios_autorizados = [
            {"email": "guillermoandrada@gmail.com", "main_name": "Guillermo", "rol": "admin"}
        ]
        for usuario_data in usuarios_autorizados:
            if not UsuarioAutorizado.query.filter_by(email=usuario_data["email"]).first():
                usuario = UsuarioAutorizado(
                    email=usuario_data["email"],
                    main_name=usuario_data["main_name"],
                    rol=usuario_data["rol"]
                )
                db.session.add(usuario)
        
        # Agregar contactos de ejemplo si no existen y si DATOS_INICIALES_CONTACTOS está definido
        if not Contacto.query.first() and 'DATOS_INICIALES_CONTACTOS' in globals():
            for contacto_data in DATOS_INICIALES_CONTACTOS:
                if not Contacto.query.filter_by(email=contacto_data["email"]).first():
                    contacto = Contacto(
                        nombre=contacto_data["nombre"],
                        email=contacto_data["email"],
                        telefono=contacto_data["telefono"],
                        direccion=contacto_data["direccion"],
                        gps_url=contacto_data["gps_url"]
                    )
                    db.session.add(contacto)
        
        db.session.commit()

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        
        try:
            # Validar el formato del correo electrónico
            valid = validate_email(email)
            email = valid.email
            
            # Buscar el usuario en la base de datos
            usuario = UsuarioAutorizado.query.filter_by(email=email).first()
            
            if usuario:
                session['email'] = email
                session['main_name'] = usuario.main_name
                session['rol'] = usuario.rol  # Guardar el rol en la sesión
                session['user_id'] = usuario.id  # Guardar el ID del usuario en la sesión
                return redirect(url_for('lista_contactos'))
            else:
                # Usuario no autorizado, redirigir a la página de no autorizado
                return redirect(url_for('no_autorizado'))
                
        except EmailNotValidError as e:
            flash('Por favor ingrese un correo electrónico válido.', 'error')
    
    return render_template('login.html')

@app.route('/contactos')
def lista_contactos():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    # Obtener contactos activos e inactivos
    contactos_activos = Contacto.query.filter_by(activo=True).all()
    contactos_inactivos = []
    
    # Solo cargar contactos inactivos si el usuario es administrador
    if 'rol' in session and session['rol'] == 'admin':
        contactos_inactivos = Contacto.query.filter_by(activo=False).all()
    
    return render_template('contactos.html', 
                         contactos=contactos_activos,
                         contactos_inactivos=contactos_inactivos)

@app.route('/contactos/agregar', methods=['POST'])
@login_required
def agregar_contacto():
    try:
        # Obtener datos del formulario
        data = request.form if request.form else request.get_json()
        
        # Validar datos requeridos
        if not data or 'nombre' not in data:
            return jsonify({'success': False, 'error': 'El nombre es requerido'}), 400

        # Crear nuevo contacto
        nuevo_contacto = Contacto(
            nombre=data['nombre'].strip(),
            email=data.get('email', '').strip(),
            telefono=data.get('telefono', '').strip(),
            direccion=data.get('direccion', '').strip(),
            gps_url=data.get('gps_url', '').strip(),
            activo=True
        )

        # Guardar en la base de datos
        db.session.add(nuevo_contacto)
        db.session.commit()

        # Si es una petición AJAX, retornar JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({
                'success': True,
                'message': 'Contacto agregado correctamente',
                'contacto': {
                    'id': nuevo_contacto.id,
                    'nombre': nuevo_contacto.nombre,
                    'email': nuevo_contacto.email,
                    'telefono': nuevo_contacto.telefono,
                    'direccion': nuevo_contacto.direccion,
                    'gps_url': nuevo_contacto.gps_url
                }
            })

        # Si es un envío de formulario normal
        flash('Contacto agregado correctamente', 'success')
        return redirect(url_for('lista_contactos'))

    except Exception as e:
        db.session.rollback()
        error_msg = f'Error al agregar el contacto: {str(e)}'
        print(error_msg)
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'success': False, 'error': error_msg}), 500
            
        flash('Error al agregar el contacto', 'error')
        return redirect(url_for('lista_contactos'))

@app.route('/contactos/editar/<int:contacto_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_contacto(contacto_id):
    contacto = Contacto.query.get_or_404(contacto_id)
    
    if request.method == 'POST':
        try:
            contacto.nombre = request.form['nombre']
            contacto.email = request.form['email']
            contacto.telefono = request.form.get('telefono', '')
            contacto.direccion = request.form['direccion']
            contacto.gps_url = request.form.get('gps_url', '')
            
            db.session.commit()
            flash('Contacto actualizado correctamente', 'success')
            return redirect(url_for('lista_contactos'))
        except Exception as e:
            db.session.rollback()
            flash('Error al actualizar el contacto', 'error')
    
    return render_template('editar_contacto.html', contacto=contacto)

@app.route('/contactos/eliminar/<int:contacto_id>', methods=['POST'])
@login_required
@admin_required
def eliminar_contacto(contacto_id):
    if request.method == 'POST':
        try:
            contacto = Contacto.query.get_or_404(contacto_id)
            # En lugar de eliminar, marcamos como inactivo
            contacto.activo = False
            db.session.commit()
            flash('Contacto eliminado correctamente', 'success')
            return redirect(url_for('lista_contactos'))
        except Exception as e:
            db.session.rollback()
            flash('Error al eliminar el contacto', 'error')
            return redirect(url_for('lista_contactos'))
    return redirect(url_for('lista_contactos'))

@app.route('/contactos/restaurar/<int:contacto_id>', methods=['POST'])
@login_required
@admin_required
def restaurar_contacto(contacto_id):
    if request.method == 'POST':
        try:
            contacto = Contacto.query.get_or_404(contacto_id)
            # Marcamos el contacto como activo nuevamente
            contacto.activo = True
            db.session.commit()
            flash('Contacto restaurado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error al restaurar el contacto', 'error')
    
    return redirect(url_for('lista_contactos'))


@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('main_name', None)
    return redirect(url_for('login'))

@app.route('/admin/usuarios', methods=['GET', 'POST'])
def admin_usuarios():
    # Verificar si el usuario está autenticado y es administrador
    if 'email' not in session or session.get('rol') != 'admin':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        main_name = request.form.get('main_name')
        rol = request.form.get('rol', 'usuario')
        
        try:
            # Validar formato de email
            valid = validate_email(email)
            email = valid.email
            
            # Validar rol
            if rol not in ['usuario', 'admin']:
                rol = 'usuario'
            
            # Verificar si el correo ya existe
            if UsuarioAutorizado.query.filter_by(email=email).first():
                flash('El correo electrónico ya está registrado.', 'error')
            else:
                # Crear nuevo usuario
                nuevo_usuario = UsuarioAutorizado(
                    email=email,
                    main_name=main_name,
                    rol=rol
                )
                db.session.add(nuevo_usuario)
                db.session.commit()
                flash('Usuario agregado correctamente.', 'success')
                
        except EmailNotValidError as e:
            flash('Por favor ingrese un correo electrónico válido.', 'error')
    
    # Obtener lista de usuarios (excepto el administrador)
    usuarios = UsuarioAutorizado.query.filter(UsuarioAutorizado.email != 'guillermoandrada@gmail.com').all()
    
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    # Verificar si el usuario está autenticado y es administrador
    if 'email' not in session or session.get('rol') != 'admin':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('login'))
    
    # Prevenir eliminación del usuario actual o del administrador principal
    if user_id == 1 or user_id == session.get('user_id'):
        flash('No puedes eliminar este usuario', 'error')
        return redirect(url_for('admin_usuarios'))
    
    try:
        # Buscar y eliminar el usuario
        usuario = UsuarioAutorizado.query.get_or_404(user_id)
        db.session.delete(usuario)
        db.session.commit()
        
        flash('Usuario eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error al eliminar el usuario: {str(e)}', 'error')
    
    return redirect(url_for('admin_usuarios'))

@app.route('/no_autorizado')
def no_autorizado():
    return render_template('no_autorizado.html', email=session.get('email', '')), 403

# Ruta de verificación de salud
@app.route('/health')
def health_check():
    try:
        # Intentar una consulta simple a la base de datos
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'database': 'disconnected',
            'error': str(e)
        }), 500

# Crear tablas si no existen
try:
    with app.app_context():
        db.create_all()
except Exception as e:
    print(f"Error al crear tablas: {str(e)}", file=sys.stderr)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') != 'production')