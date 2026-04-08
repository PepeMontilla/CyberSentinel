from flask import Flask, request, render_template, redirect, url_for, flash, send_file, session
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

# Configuración para uploads
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'exe'}
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
            # Paso 1: Parsear el PE
            datos_crudos = parse_exe(filepath)

            if not datos_crudos:
                flash('Error al analizar el archivo. Asegúrate de que sea un ejecutable PE válido.')
                return redirect(url_for('index'))

            # Paso 2: Clasificar imports
            analisis_reglas = classify_imports(datos_crudos['imports'])

            # Paso 3: Obtener veredicto de IA
            contexto_para_ia = {
                "metadata": datos_crudos['metadata'],
                "comportamientos": analisis_reglas['behaviors'],
                "strings_sospechosos": datos_crudos['strings'],
                "risk_score_total": analisis_reglas['risk_score']
            }

            veredicto_ia = get_ai_verdict(contexto_para_ia)

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
        flash('Tipo de archivo no permitido. Solo se permiten archivos .exe')
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
    app.run(debug=debug_mode)