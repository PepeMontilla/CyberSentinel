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

def classify_imports(parsed_imports):
    """
    Recibe un diccionario de imports del pe_parser y devuelve las coincidencias peligrosas.
    
    Ejemplo de entrada (parsed_imports):
    {"kernel32.dll": ["CreateProcess", "Sleep"], "user32.dll": ["ExitWindowsEx"]}
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
                    
                    # Añadir al listado de comportamientos detectados
                    behaviors.append({
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "function": func,
                        "dll": dll_lower,
                        "description": rule["desc"]
                    })
                    
                    # Sumar al score total
                    risk_score += score_map.get(rule["severity"], 0)

    # Determinar el veredicto preliminar basado puramente en las reglas
    verdict = "CLEAN"
    if risk_score >= 50:
        verdict = "MALICIOUS"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS"

    return {
        "behaviors": behaviors,
        "risk_score": risk_score,
        "preliminary_verdict": verdict
    }

# Bloque de prueba local 
if __name__ == "__main__":
    # Simulamos lo que te entregaría la Persona 1 (pe_parser)
    mock_imports = {
        "kernel32.dll": ["Sleep", "CreateRemoteThread"], # CreateRemoteThread es HIGH
        "user32.dll": ["ExitWindowsEx", "MessageBoxA"]   # ExitWindowsEx es HIGH
    }
    
    resultado = classify_imports(mock_imports)
    print(resultado)