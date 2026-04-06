import os 
import requests
from dotenv import load_dotenv

# Cargamos las variables de entorno
load_dotenv()

def check_hash_virustotal(file_hash):
    """
    Consulta la API v3 de VirusTotal usando el hash SHA-256 del archivo.
    Devuelve las estadisticas de deteccion
    """

    #Obtenemos la llave desde el .env

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {"error": "API Key de VirusTotal no configurada."}
    
    #Endpoint oficial de la API v3 para buscar hashes
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    #VirusTotal pide la llave en los headers como 'x-apikey'
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try: 
        #Hacemos la peticion GET a los servidores de VirusTotal
        response = requests.get(url, headers=headers)

        #Codigo 200 Significa que el hash SI esta en su base de datos
        if response.status_code == 200:
            data = response.json()
            #Extraemos directamente las estadicticas del analisis 
            stats = data ['data']['attributes']['last_analysis_stats']

            return {
                "encontrado": True,
                "malicioso": stats.get("malicious", 0),
                "sospechoso": stats.get("suspicious", 0),
                "indetectado": stats.get("undetected", 0),

                #Sumamos todos los valores para saber cuantos motores lo analizaron en total
                "total_motores": sum(stats.values()),
                "link_reporte": f"https://www.virustotal.com/gui/file/{file_hash}"
            
            }
        
        #Codigo 404 Significa que el hash NO esta en su base de datos si no que es completamente nuevo

        elif response.status_code == 404:
            return {
                "encontrado": False,
                "mensaje": "Hash no encontrado. El archivo es desconocido para los antivirus mundiales (Posible ataque dirigido o Zero-day)."
            }
        
        #Codigo 401 significa que tu API Key esta mal escrita
        elif response.status_code == 401:
            return {"error": "API Key de VirusTotal inválida o expirada."}
            
        else:
            return {"error": f"Respuesta inesperada de VT: Código {response.status_code}"}

    except Exception as e:
        return {"error": f"Error de conexión HTTP: {str(e)}"}
    

