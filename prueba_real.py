import json
import os
# ¡Aquí está la corrección clave! Importamos 'parse_exe'
from modules.pe_parser import parse_exe 
from modules.rules_engine import classify_imports
from modules.ai_module import get_ai_verdict

# Vamos a usar el block de notas de Windows como archivo de prueba real
# Es un archivo seguro y garantizamos que existe en tu PC.
ruta_exe = r"C:\Windows\System32\notepad.exe"

print("==================================================")
print(f"🚀 INICIANDO INTEGRACIÓN REAL DE CYBERSENTINEL")
print(f"📁 Archivo: {ruta_exe}")
print("==================================================\n")

if not os.path.exists(ruta_exe):
    print(f"❌ ERROR: No se encontró el archivo en {ruta_exe}")
    exit()

try:
    # --- PASO 1 (Persona 1): Extraer datos crudos del .exe ---
    print("\n[1/3] Ejecutando módulo PE Parser (Jose)...")
    datos_crudos = parse_exe(ruta_exe)
    
    if not datos_crudos.get("imports"):
        print("❌ ERROR: El PE Parser no devolvió datos válidos.")
        exit()

    # --- PASO 2 (Persona 2 - Motor): Calcular riesgo matemático ---
    print("\n[2/3] Ejecutando Motor de Reglas Heurísticas (Wilmer)...")
    analisis_reglas = classify_imports(datos_crudos['imports'])
    print(f"      ↳ Riesgo calculado: {analisis_reglas['risk_score']} pts")
    print(f"      ↳ Veredicto preliminar: {analisis_reglas['preliminary_verdict']}")
    
    # --- PASO 3 (Persona 2 - IA): Empaquetar y consultar a Gemini ---
    print("\n[3/3] Consultando a la IA Forense (Gemini)...")
    
    # Preparamos la bandeja de datos exacta que tu IA espera
    contexto_para_ia = {
        "metadata": datos_crudos['metadata'],
        "comportamientos": analisis_reglas['behaviors'],
        "strings_sospechosos": datos_crudos['strings'],
        "risk_score_total": analisis_reglas['risk_score'] # Tu motor espera esta llave
    }
    
    veredicto_final = get_ai_verdict(contexto_para_ia)
    
    # --- RESULTADO FINAL ---
    print("\n🏆 REPORTE FORENSE GENERADO POR IA:")
    print("--------------------------------------------------")
    print(json.dumps(veredicto_final, indent=4, ensure_ascii=False))
    print("--------------------------------------------------")

except Exception as e:
    print(f"\n❌ Error catastrófico en la integración: {e}")