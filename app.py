from flask import Flask, request, render_template, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import os
from werkzeug.utils import secure_filename
from modules.pe_parser import parse_exe
from modules.rules_engine import classify_imports
from modules.ai_module import get_ai_verdict, chat_forensic
from modules.report_generator import generate_pdf_report
import json

app = Flask(__name__)
# Se utiliza variable de entorno para la clave secreta, o se genera una aleatoria (segura por defecto)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#Definicion de la tabla (El cache de analisis)
class ReporteAnalisis(db.Model):
    __tablename__ = 'reportes'

    #El hash es la clave primaria. No puede haber 2 iguales

    hash_sha256 = db.Column(db.String(64), primary_key=True)
    nombre_archivo = db.Column(db.String(255), nullable=False)
    nivel_riesgo = db.Column(db.Integer, nullable=False)
    veredicto_ai = db.Column(db.Text, nullable= False)

    #Guarda la fecha automaticamente 
    fecha_analisis = db.Column(db.Date, default=date.today)

#Crear la tabla en el archivo .db si no existe
with app.app_context():
    db.create_all()


# Configuración para uploads
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'scr', 'sys'  }
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

# Crear carpetas si no existen
for folder in [UPLOAD_FOLDER, REPORTS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No se seleccionó ningún archivo')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # Paso 1: Parsear el PE (Esto es local y rapidísimo)
            datos_crudos = parse_exe(filepath)

            if not datos_crudos:
                flash('Error al analizar el archivo. Asegúrate de que sea un ejecutable PE válido.')
                return redirect(url_for('index'))

            # Paso 2: Clasificar imports (Motor de Reglas)
            nombre_archivo = datos_crudos['metadata']['filename']
            analisis_reglas = classify_imports(datos_crudos['imports'], filename=nombre_archivo)

            # --- INICIO DEL CACHÉ INTELIGENTE ---
            # Sacamos el Hash del archivo que acaba de calcular el parser
            file_hash = datos_crudos['metadata']['sha256']
            
            # Buscamos en la base de datos si ya existe
            reporte_previo = ReporteAnalisis.query.get(file_hash)

            if reporte_previo:
                # ¡HIT EN EL CACHÉ! El archivo ya fue analizado antes.
                # Recuperamos el veredicto de la base de datos y lo convertimos a diccionario
                veredicto_ia = json.loads(reporte_previo.veredicto_ai)
                print(f"[*] AHORRO DE TOKENS: {nombre_archivo} cargado desde la Base de Datos.")
            else:
                # ¡ARCHIVO NUEVO! Consultamos a Gemini (Gasta tokens y tiempo)
                contexto_para_ia = {
                    "metadata": datos_crudos['metadata'],
                    "comportamientos": analisis_reglas['behaviors'],
                    "strings_sospechosos": datos_crudos['strings'],
                    "risk_score_total": analisis_reglas['risk_score']
                }
                veredicto_ia = get_ai_verdict(contexto_para_ia)

                # Guardamos este nuevo análisis en la base de datos para el futuro
                nuevo_reporte = ReporteAnalisis(
                    hash_sha256=file_hash,
                    nombre_archivo=nombre_archivo,
                    nivel_riesgo=analisis_reglas['risk_score'],
                    veredicto_ai=json.dumps(veredicto_ia) # Guardamos el dict como texto JSON
                )
                db.session.add(nuevo_reporte)
                db.session.commit()
                print(f"[*] NUEVO ANÁLISIS: {nombre_archivo} guardado en la Base de Datos.")
            # --- FIN DEL CACHÉ INTELIGENTE ---

            # Preparar datos para el template
            analysis_data = {
                'metadata': datos_crudos['metadata'],
                'behaviors': analisis_reglas['behaviors'],
                'risk_score': analisis_reglas['risk_score'],
                'preliminary_verdict': analisis_reglas['preliminary_verdict'],
                'ai_verdict': veredicto_ia,
                'strings': datos_crudos['strings'],
                'filepath': filepath
            }

            # Generar reporte PDF
            report_filename = f"report_{filename.replace('.exe', '')}_{datos_crudos['metadata']['sha256'][:8]}.pdf"
            report_path = os.path.join(app.config['REPORTS_FOLDER'], report_filename)
            generate_pdf_report(analysis_data, report_path)

            # Guardar en sesión para el chat y descarga
            session['analysis_data'] = json.dumps(analysis_data)
            session['report_path'] = report_path

            # VT Mock ya que la integración aún no está en pipeline
            vt_mock = {
                "encontrado": False,
                "total_motores": 0,
                "malicioso": 0,
                "link_reporte": "#"
            }

            return render_template('result.html', 
                                   pe=datos_crudos, 
                                   reglas=analisis_reglas, 
                                   veredicto=veredicto_ia, 
                                   vt=vt_mock, 
                                   report_filename=report_filename)

        except Exception as e:
            flash(f'Error durante el análisis: {str(e)}')
            return redirect(url_for('index'))
    else:
        # CORRECCIÓN MENOR: Actualicé el mensaje de error para que incluya los nuevos formatos
        flash('Tipo de archivo no permitido. Solo se permiten ejecutables (.exe, .dll, .scr, .sys)')
        return redirect(url_for('index'))

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'GET':
        return render_template('chat.html')

    if request.is_json:
        question = request.json.get('pregunta')
    else:
        question = request.form.get('question')

    analysis_context = session.get('analysis_data')

    if not question or not analysis_context:
        return {'error': 'Datos insuficientes para el chat'}, 400

    try:
        analysis_data = json.loads(analysis_context)
        response = chat_forensic(question, analysis_data)
        return {'respuesta': response}
    except Exception as e:
        return {'error': f'Error en el chat: {str(e)}'}, 500

@app.route('/download_report')
def download_report():
    report_path = session.get('report_path')
    if not report_path or not os.path.exists(report_path):
        flash('Reporte no encontrado')
        return redirect(url_for('index'))

    return send_file(report_path, as_attachment=True, download_name=os.path.basename(report_path))

if __name__ == '__main__':
    # Usar variable de entorno para controlar el modo debug de forma segura (apagado por defecto)
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')


    app.run(host='0.0.0.0', port=5000, debug=debug_mode)    