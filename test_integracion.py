import json
from modules.rules_engine import classify_imports
from modules.ai_module import get_ai_verdict

# --- BLOQUE 1: Datos Simulados (Mock Data) ---
# Aquí simulamos lo que el 'pe_parser' (Persona 1) nos entregaría después de leer un .exe malicioso.
mock_pe_data = {
    "metadata": {
        "filename": "actualizacion_urgente.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "size_bytes": 102400
    },
    "imports": {
        "kernel32.dll": ["CreateRemoteThread", "Sleep"], # CreateRemoteThread inyecta código
        "user32.dll": ["ExitWindowsEx", "MessageBoxA"]   # ExitWindowsEx reinicia la PC
    },
    "strings": [
        "cmd.exe /c shutdown -r -t 0",
        "http://servidor-atacante.com/payload.exe"
    ]
}

print("🚀 Iniciando prueba del Módulo de Detección (Persona 2)...\n")

# --- BLOQUE 2: Probando el Motor de Reglas ---
print("⚙️ 1. Ejecutando Motor de Reglas...")
# Le pasamos solo la sección de 'imports' a tu motor matemático
resultado_reglas = classify_imports(mock_pe_data["imports"])

print(f"Puntaje de Riesgo calculado: {resultado_reglas['risk_score']}")
print(f"Veredicto Preliminar: {resultado_reglas['preliminary_verdict']}\n")

# --- BLOQUE 3: Preparando el paquete para la IA ---
# Unimos la metadata, los strings y los comportamientos que detectó tu motor
analisis_completo = {
    "metadata": mock_pe_data["metadata"],
    "comportamientos_detectados": resultado_reglas["behaviors"],
    "strings_sospechosos": mock_pe_data["strings"],
    "risk_score_total": resultado_reglas["risk_score"]
}

# --- BLOQUE 4: Consultando a Gemini ---
print("🧠 2. Consultando a Gemini (Esperando respuesta en formato JSON)...")
veredicto_final = get_ai_verdict(analisis_completo)

print("\n✅ Respuesta Final de Gemini:")
# Imprimimos el diccionario resultante formateado bonito en la terminal
print(json.dumps(veredicto_final, indent=4, ensure_ascii=False))