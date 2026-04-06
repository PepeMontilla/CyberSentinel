# CyberSentinel - Analizador Estático Forense de Malware

Un sistema completo de análisis estático forense para archivos ejecutables PE (Portable Executable), desarrollado en Python con integración de IA.

## Arquitectura del Sistema

### Persona 1 - Parser de Binarios PE
- **Módulo**: `modules/pe_parser.py`
- **Responsabilidades**:
  - Extracción de encabezado PE usando `pefile`
  - Análisis de secciones con cálculo de entropía
  - Extracción completa de tabla de imports
  - Detección de strings sospechosos (comandos de sistema, rutas críticas, IPs/URLs, claves de registro)

### Persona 2 - Motor de Detección + IA
- **Módulos**: `modules/rules_engine.py`, `modules/ai_module.py`
- **Responsabilidades**:
  - Motor de reglas heurísticas con diccionario WinAPI
  - Cálculo de severidad y puntuación de riesgo
  - Integración con Gemini AI para veredictos inteligentes
  - Chat forense interactivo para consultas sobre el análisis

### Persona 3 - Dashboard + Reportes
- **Módulo**: `app.py`, `templates/`, `modules/report_generator.py`
- **Responsabilidades**:
  - Interfaz web Flask con diseño moderno
  - Página de upload con drag & drop
  - Visualización por capas del análisis
  - Tabla de WinAPI calls con íconos de severidad
  - Veredicto de IA destacado visualmente
  - Generación de reportes PDF profesionales con `reportlab`

## Requisitos del Sistema

- Python 3.8+
- Windows (para análisis de PE)
- API Key de Gemini (Google AI)

## Instalación

1. **Clona el repositorio**:
   ```bash
   git clone <url-del-repo>
   cd CyberSentinel
   ```

2. **Instala las dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configura las variables de entorno**:
   Crea un archivo `.env` en la raíz del proyecto:
   ```
   GEMINI_API_KEY=tu_api_key_aqui
   ```

## Uso

### Ejecución Local (Pruebas)
```bash
python prueba_real.py
```

### Interfaz Web
```bash
python app.py
```
Accede a `http://localhost:5000` en tu navegador.

### Funcionalidades

1. **Upload de Archivos**: Arrastra y suelta archivos .exe para análisis
2. **Análisis Automático**:
   - Parsing PE completo
   - Detección de comportamientos maliciosos
   - Veredicto IA con explicaciones
3. **Visualización de Resultados**:
   - Metadatos del archivo
   - Comportamientos detectados con severidad
   - Strings sospechosos
   - Veredicto final con confianza
4. **Chat Forense**: Preguntas interactivas sobre el análisis
5. **Reportes PDF**: Descarga de reportes profesionales

## Estructura del Proyecto

```
CyberSentinel/
├── app.py                    # Aplicación Flask principal
├── prueba_real.py           # Script de pruebas de integración
├── requirements.txt          # Dependencias Python
├── README.md                # Este archivo
├── modules/
│   ├── pe_parser.py         # Parser de archivos PE
│   ├── rules_engine.py      # Motor de reglas heurísticas
│   ├── ai_module.py         # Integración con IA
│   └── report_generator.py  # Generador de reportes PDF
├── templates/
│   ├── index.html           # Página de upload
│   ├── result.html          # Página de resultados
│   └── chat.html            # Template del chat (opcional)
└── uploads/                 # Archivos subidos (creado automáticamente)
    └── reports/             # Reportes PDF generados
```

## Seguridad

- Los archivos se procesan solo en memoria (no se ejecutan)
- Análisis estático únicamente
- No se requiere ejecución del malware
- Compatible con entornos sandbox

## Contribuciones

Este proyecto implementa las tres personas del sistema CyberSentinel:

1. ✅ **Persona 1**: Parser PE completado
2. ✅ **Persona 2**: Motor de reglas + IA integrada
3. ✅ **Persona 3**: Dashboard Flask + Reportes PDF

## Licencia

Proyecto educativo para análisis forense de malware.
