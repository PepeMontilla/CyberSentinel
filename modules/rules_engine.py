# Diccionario de WinAPI Calls mapeadas a comportamiento y severidad
WINAPI_DICT = {
    "user32.dll": {
        "ExitWindowsEx": {"severity": "HIGH", "category": "system_shutdown", "desc": "Apagado / reinicio del sistema"}
    },
    "advapi32.dll": {
        "InitiateSystemShutdown": {"severity": "HIGH", "category": "system_shutdown", "desc": "Apagado / reinicio del sistema"},
        "RegSetValueEx": {"severity": "MEDIUM", "category": "persistence", "desc": "Modificación del registro (persistencia)"},
        "RegCreateKeyEx": {"severity": "MEDIUM", "category": "persistence", "desc": "Creación de clave de registro"},
        "CryptEncrypt": {"severity": "LOW", "category": "crypto", "desc": "Operaciones criptográficas"}
    },
    "ntdll.dll": {
        "NtShutdownSystem": {"severity": "HIGH", "category": "system_shutdown", "desc": "Reinicio a nivel kernel"},
        "NtAllocateVirtualMemory": {"severity": "HIGH", "category": "memory_allocation", "desc": "Reserva de memoria (nivel bajo)"}
    },
    "kernel32.dll": {
        "CreateRemoteThread": {"severity": "HIGH", "category": "process_injection", "desc": "Inyección de código en otro proceso"},
        "WriteProcessMemory": {"severity": "HIGH", "category": "process_injection", "desc": "Escritura en memoria de otro proceso"},
        "VirtualAllocEx": {"severity": "HIGH", "category": "memory_allocation", "desc": "Reserva de memoria en proceso remoto"},
        "CreateProcess": {"severity": "MEDIUM", "category": "execution", "desc": "Creación de proceso hijo"},
        "WinExec": {"severity": "MEDIUM", "category": "execution", "desc": "Ejecución de comandos (legacy)"},
        "GetSystemDirectory": {"severity": "LOW", "category": "reconnaissance", "desc": "Acceso a directorio del sistema"},
        "GetWindowsDirectory": {"severity": "LOW", "category": "reconnaissance", "desc": "Acceso a directorio de Windows"},
        "FindFirstFile": {"severity": "LOW", "category": "reconnaissance", "desc": "Enumeración de archivos"}
    },
    "shell32.dll": {
        "ShellExecute": {"severity": "MEDIUM", "category": "execution", "desc": "Ejecución de comandos / archivos"}
    },
    "ws2_32.dll": {
        "WSAConnect": {"severity": "MEDIUM", "category": "network", "desc": "Conexión de red saliente"}
    },
    "wininet.dll": {
        "InternetOpen": {"severity": "MEDIUM", "category": "network", "desc": "Inicializa conexión HTTP"},
        "HttpSendRequest": {"severity": "MEDIUM", "category": "network", "desc": "Envía petición HTTP"}
    }
}

# --- LISTA BLANCA (WHITELIST) ---
# Programas legítimos que usan técnicas avanzadas de inyección (IPC, Anticheats, etc.)
PROGRAMAS_SEGUROS = [
    "spotify.exe", 
    "discord.exe", 
    "chrome.exe", 
    "code.exe", 
    "msedge.exe",
    "leagueclient.exe", 
    "vgc.exe" # Vanguard Anticheat
]

# Modificamos la función para que reciba 'filename' por defecto vacío
def classify_imports(parsed_imports, filename=""):
    """
    Recibe un diccionario de imports del pe_parser y el nombre del archivo.
    Devuelve las coincidencias peligrosas filtrando falsos positivos conocidos.
    """
    behaviors = []
    risk_score = 0
    
    # Valores de puntuación por severidad
    score_map = {"HIGH": 50, "MEDIUM": 20, "LOW": 5}

    for dll_name, functions in parsed_imports.items():
        dll_lower = dll_name.lower()
        if dll_lower in WINAPI_DICT:
            for func in functions:
                if func in WINAPI_DICT[dll_lower]:
                    rule = WINAPI_DICT[dll_lower][func]
                    
                    behaviors.append({
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "function": func,
                        "dll": dll_lower,
                        "description": rule["desc"]
                    })
                    
                    risk_score += score_map.get(rule["severity"], 0)

    is_whitelisted = False
    if filename.lower() in PROGRAMAS_SEGUROS:
        risk_score = 0  # Perdonamos el puntaje
        is_whitelisted = True
        
        # Agregamos una nota para que la IA sepa por qué le bajamos el riesgo a 0
        behaviors.append({
            "severity": "INFO",
            "category": "whitelist",
            "function": "N/A",
            "dll": "N/A",
            "description": f"Excepción aplicada: '{filename}' es una aplicación confiable conocida."
        })

    # Determinar el veredicto preliminar
    if is_whitelisted:
        verdict = "CLEAN (Whitelist)"
    elif risk_score >= 50:
        verdict = "MALICIOUS"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "behaviors": behaviors,
        "risk_score": risk_score,
        "preliminary_verdict": verdict
    }

# Bloque de prueba local 
if __name__ == "__main__":
    mock_imports = {
        "kernel32.dll": ["Sleep", "CreateRemoteThread"], # 50 pts
        "user32.dll": ["ExitWindowsEx", "MessageBoxA"]   # 50 pts
    }
    
    print("=== PRUEBA 1: Archivo Desconocido ===")
    print(classify_imports(mock_imports, filename="troyano_oculto.exe"))
    
    print("\n=== PRUEBA 2: Spotify (Lista Blanca) ===")
    print(classify_imports(mock_imports, filename="Spotify.exe"))