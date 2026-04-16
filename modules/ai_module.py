import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Cargamos las variables de entorno
load_dotenv()

# Inicializamos el cliente con la nueva librería
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def get_ai_verdict(analysis_dict):
    """
    Toma el diccionario con los hallazgos del .exe y le pide a la IA un veredicto.
    """
    
    system_instruction = system_instruction = """
    Eres el motor de inteligencia artificial de CyberSentinel, un analizador estático forense de malware.
    Tu tarea es analizar los datos proporcionados que contienen la estructura PE, strings sospechosos y llamadas WinAPI de un archivo .exe.
    
    REGLAS ESTRICTAS:
    1. Actúa como un analista SOC Senior con 10 años de experiencia.
    2. Si hay llamadas a funciones como 'ExitWindowsEx' o 'NtShutdownSystem', el riesgo es ALTO y el veredicto debe ser Malicioso.
    3. Tu salida debe ser un JSON puro, utilizando EXACTAMENTE las siguientes llaves:
    {
        "veredicto": "Limpio" o "Sospechoso" o "Malicioso",
        "confianza": <número de 0 a 100>,
        "explicacion_tecnica": "<explicación breve en español de lo que intenta hacer el archivo>",
        "recomendaciones": "<qué debería hacer el usuario para mitigar el riesgo>"
    }
    """

    user_content = f"Analiza este ejecutable y devuelve el JSON:\n{json.dumps(analysis_dict, indent=2)}"

    try:
        # Usamos la nueva estructura para llamar al modelo
        response = client.models.generate_content(
            model='gemini-2.5-flash', # Modelo actualizado y ultra rápido
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2,
                response_mime_type="application/json",
            )
        )

      
        # Extraemos el texto y lo convertimos a diccionario Python
        verdict_data = json.loads(response.text)
        
        resultado_final = {
            "veredicto": verdict_data.get("veredicto", "Desconocido"),
            "confianza": verdict_data.get("confianza", 0),
            "explicacion_tecnica": verdict_data.get("explicacion_tecnica", "No se generó explicación."),
            "recomendaciones": verdict_data.get("recomendaciones", "Sin recomendaciones.")
        }

        return resultado_final

    except Exception as e:
        print(f"Error al conectar con Gemini: {e}")
        return {
            "veredicto": "Error",
            "confianza": 0,
            "explicacion_tecnica": f"Falla de API: {str(e)}",
            "recomendaciones": "Verificar la conexión y la API Key."
        }


def chat_forensic(question, analysis_context):
    """
    Recibe una pregunta del usuario y el contexto del análisis previo.
    Responde interactuando como un analista experto en base a esos datos.
    """
    
    system_instruction = """
    Eres el asistente interactivo de CyberSentinel, un analista SOC Senior experto con 10 años de experiencia en respuesta a incidentes.
    El usuario te hará una pregunta sobre un archivo ejecutable que acaba de ser analizado.
    Se te proporcionará el contexto técnico (metadatos, strings, WinAPIs, veredicto) de ese archivo.
    
    REGLAS ESTRICTAS:
    1. Responde ÚNICAMENTE basándote en el contexto técnico proporcionado. No inventes comportamientos que no estén en el JSON.
    2. Si el usuario hace una pregunta técnica sobre una función WinAPI detectada (ej. '¿Para qué sirve ExitWindowsEx?'), explícalo de forma clara y profesional pero entendible.
    3. Si la pregunta no tiene relación con el archivo analizado o la ciberseguridad, responde cortésmente que tu función es estrictamente el análisis forense de este malware.
    4. Responde en texto plano o Markdown (puedes usar negritas o listas para organizar tu respuesta). No devuelvas JSON en esta función.


    IMPORTANTE: Aplicaciones modernas construidas con Electron o Chromium (como navegadores, Spotify, Discord) utilizan funciones de inyección como CreateRemoteThread o WriteProcessMemory
    para comunicación inter-procesos (IPC) y sandboxing, no para fines maliciosos. Si el nombre del archivo o los strings sugieren que es un programa legítimo de este tipo, 
    y no hay otros indicadores críticos, clasifícalo como un Falso Positivo y reduce el nivel de amenaza.

    Debes redactar tu 'Explicación Técnica' estructurándola estrictamente en dos párrafos para que sea entendible por cualquier persona:

    1. Resumen Ejecutivo (Para el usuario normal):
    Explica de forma sencilla y directa qué hace el archivo y por qué es seguro o peligroso. 
    Utiliza un lenguaje cotidiano o una metáfora corta si es necesario. No menciones nombres de librerías (.dll) ni funciones complejas aquí.

    2. Evidencia Técnica (Para el analista):    
    Aquí sí debes ponerte técnico. Justifica el veredicto mencionando las WinAPIs clave encontradas 
    (ej. CreateRemoteThread, VirtualAllocEx), los strings sospechosos o la arquitectura del programa (ej. aplicaciones Electron/Chromium).

    Tus reglas de interacción son:
    1. Tu prioridad es responder cualquier duda técnica que el usuario tenga sobre el reporte y los comportamientos detectados en este archivo específico.
    2. Si el usuario te hace preguntas generales sobre ciberseguridad 
    (ej. "¿Qué es un malware?", "¿Qué es un troyano?", "¿Cómo me protejo?"), TIENES PERMITIDO RESPONDER. Utiliza tus conocimientos para educar al usuario de forma clara y profesional.
    3. Mantén siempre un tono experto, pero accesible.
    """

    # Aseguramos que el contexto sea un string formateado para que Gemini lo lea bien
    if isinstance(analysis_context, dict):
        context_str = json.dumps(analysis_context, indent=2)
    else:
        context_str = str(analysis_context)

    # Armamos el prompt inyectando el contexto y la pregunta
    user_content = f"CONTEXTO DEL ARCHIVO ANALIZADO:\n{context_str}\n\nPREGUNTA DEL USUARIO:\n{question}"

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.3, # Un poco más alto que el veredicto para que fluya más conversacional, pero sin alucinar
            )
        )
        
        return response.text

    except Exception as e:
        print(f"Error en el chat forense: {e}")
        return "Disculpa, ocurrió un error al procesar tu pregunta forense. Verifica la conexión."

 