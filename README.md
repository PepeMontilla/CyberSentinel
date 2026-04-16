# CyberSentinel

CyberSentinel es una plataforma web inteligente para el análisis forense de malware y archivos ejecutables sospechosos (PE: `.exe`, `.dll`, `.sys`, `.scr`). Combina un análisis estático rápido mediante motores de reglas locales con el potencial de la Inteligencia Artificial (Google Gemini) para emitir veredictos precisos y detallados sobre el nivel de riesgo de un archivo.

## Características Principales

- **Análisis Estático de Ejecutables (PE):** Extrae metadatos, funciones importadas y cadenas sospechosas de los binarios.
- **Motor de Reglas Locales:** Clasifica comportamientos y genera una puntuación de riesgo base antes de consultar a la IA.
- **Veredicto por Inteligencia Artificial:** Utiliza Gemini de Google para analizar el contexto del archivo y dar una conclusión definitiva del nivel de amenaza.
- **Caché Inteligente (Base de Datos):** Guarda los resultados en una base de datos local (SQLite) utilizando el hash del archivo (SHA256) para evitar re-análisis innecesarios y ahorrar cuotas de la API.
- **Generación de Reportes PDF:** Permite descargar un reporte ejecutivo del análisis forense.
- **Asistente Chatbot Forense:** Incluye un chat impulsado por IA para realizar preguntas avanzadas sobre el reporte y el comportamiento del archivo recién analizado.

## Requisitos Previos

Para ejecutar CyberSentinel, necesitarás tener instalado en tu sistema:
- **Python 3.8 o superior**
- **Git** (opcional, para clonar el repositorio)

## Instrucciones de Instalación y Ejecución

Sigue estos pasos para preparar tu entorno correctamente y poder iniciar la aplicación.

### 1. Clonar el repositorio (Opcional)
Si tienes el código fuente en un archivo zip, simplemente extráelo en una carpeta. Si usas git:
```bash
git clone <url-del-repositorio>
cd CyberSentinel
```

### 2. Crear un Entorno Virtual (Recomendado)
Para evitar conflictos con otras librerías de Python en tu sistema, crea un entorno virtual (`venv`):

- **En Windows:**
  ```bash
  python -m venv venv
  ```
- **En Linux/Mac:**
  ```bash
  python3 -m venv venv
  ```

### 3. Activar el Entorno Virtual
Una vez creado, debes activarlo:

- **En Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate.bat
  ```
- **En Windows (PowerShell):**
  ```powershell
  venv\Scripts\Activate.ps1
  ```
- **En Linux/Mac:**
  ```bash
  source venv/bin/activate
  ```

*(Sabrás que está activado cuando veas `(venv)` al inicio de la línea de tu terminal).*

### 4. Instalar las Dependencias
Con el entorno virtual activado, instala todas las dependencias necesarias leyendo el archivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 5. Configurar las Variables de Entorno
CyberSentinel necesita de algunas claves para funcionar correctamente, en especial la de la Inteligencia Artificial.

1. Crea un archivo llamado `.env` en la raíz del proyecto (al mismo nivel que `app.py`).
2. Abre el archivo y añade las siguientes variables, reemplazando con tus propios valores:

```ini
# Clave API de Google Gemini (Necesaria para los veredictos y chat)
GEMINI_API_KEY=tu_clave_api_aqui

# (Opcional) Clave API de VirusTotal para futuras integraciones
VIRUSTOTAL_API_KEY=tu_clave_api_aqui

# Llave secreta para la sesión de Flask (puedes inventar una o dejarla en blanco para que se genere automáticamente)
FLASK_SECRET_KEY=tu_clave_secreta_aqui

# Tamaño máximo de subida de archivos en MB
MAX_UPLOAD_SIZE_MB=100
```

### 6. Ejecutar la Aplicación
Una vez instalado todo y configurado el archivo `.env`, ya puedes iniciar el servidor:

```bash
python app.py
```

### 7. Acceder a CyberSentinel
Abre tu navegador de preferencia y dirígete a:
**http://127.0.0.1:5000** o **http://localhost:5000**

¡Listo! Ya puedes subir un archivo binario `.exe` y esperar a que CyberSentinel genere su análisis inicial predictivo y veredicto.

## Estructura de Directorios

- `app.py`: Archivo principal que arranca el servidor web (Flask).
- `modules/`: Contiene la lógica profunda: parseo (PE), motor de reglas, IA (Gemini) y generación de PDF.
- `templates/`: Archivos HTML de la interfaz de usuario.
- `uploads/` y `reports/`: Carpetas generadas automáticamente donde se guardan temporalmente los análisis y archivos procesados.
- `instance/`: Carpeta de Flask donde se crea la base de datos `cybersentinel.db`.
