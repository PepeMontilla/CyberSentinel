import hashlib
import os
import pefile

# Patrones sospechosos para filtrar strings relevantes del binario
PATRONES_SOSPECHOSOS = [
    # Comandos de sistema
    "cmd", "powershell", "shutdown", "reboot", "taskkill", "wscript", "cscript",
    # Rutas críticas de Windows
    "system32", "windows\\", "appdata", "temp\\", "startup",
    "currentversion\\run", "software\\microsoft",
    # Red
    "http://", "https://", "ftp://", "socket", "connect", "download",
    # Registro
    "hkey_", "regedit", "reg add", "reg delete",
    # Archivos ejecutables y scripts
    ".exe", ".bat", ".ps1", ".vbs", ".dll",
    # Comandos maliciosos comunes
    "net user", "net localgroup", "/c shutdown", "-r -t", "base64",
    "invoke-expression", "iex(", "bypass",
]


def _calcular_sha256(ruta_archivo: str) -> str:
    """Calcula el hash SHA-256 del archivo en bloques para no cargar todo en RAM."""
    sha256 = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                sha256.update(bloque)
    except Exception as e:
        print(f"[ERROR] No se pudo calcular el hash: {e}")
        return ""
    return sha256.hexdigest()


def _extraer_imports(pe: pefile.PE) -> dict:
    """
    Extrae la tabla de imports del binario PE.
    Devuelve un dict: {"kernel32.dll": ["CreateProcess", "Sleep"], ...}
    Los nombres de DLL van en minúsculas, los de función conservan capitalización original.
    """
    imports = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entrada in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            nombre_dll = entrada.dll.decode("utf-8", errors="replace").lower()
            funciones = []

            for importacion in entrada.imports:
                if importacion.name:
                    # Conservamos la capitalización exacta para que rules_engine haga match
                    nombre_func = importacion.name.decode("utf-8", errors="replace")
                    funciones.append(nombre_func)
                else:
                    # Import por ordinal (sin nombre), lo registramos igual
                    funciones.append(f"Ordinal_{importacion.ordinal}")

            if funciones:
                imports[nombre_dll] = funciones

        except Exception:
            continue

    return imports


def _extraer_strings(ruta_archivo: str, min_longitud: int = 5) -> list:
    """
    Extrae strings legibles del binario y filtra los que coinciden
    con patrones sospechosos. Devuelve lista sin duplicados.
    """
    strings_encontrados = set()

    try:
        with open(ruta_archivo, "rb") as f:
            contenido = f.read()
    except Exception as e:
        print(f"[ERROR] No se pudo leer el archivo para extraer strings: {e}")
        return []

    # Extraer strings ASCII (caracteres imprimibles consecutivos)
    string_actual = []
    for byte in contenido:
        if 32 <= byte <= 126:  # Rango ASCII imprimible
            string_actual.append(chr(byte))
        else:
            if len(string_actual) >= min_longitud:
                texto = "".join(string_actual).strip()
                if texto:
                    strings_encontrados.add(texto)
            string_actual = []

    # Capturar el último string si quedó pendiente
    if len(string_actual) >= min_longitud:
        texto = "".join(string_actual).strip()
        if texto:
            strings_encontrados.add(texto)

    # Filtrar solo los que contienen patrones sospechosos
    strings_filtrados = []
    for texto in strings_encontrados:
        texto_lower = texto.lower()
        for patron in PATRONES_SOSPECHOSOS:
            if patron in texto_lower:
                strings_filtrados.append(texto)
                break  # No agregar el mismo string más de una vez

    # Ordenar y limitar a 50 para no saturar la IA
    strings_filtrados.sort()
    return strings_filtrados[:50]


def parse_exe(ruta_archivo: str) -> dict:
    """
    Función principal del módulo. Recibe la ruta a un archivo .exe
    y devuelve el diccionario completo que consume el resto del sistema.

    Estructura de retorno:
    {
        "metadata": {"filename": str, "sha256": str, "size_bytes": int},
        "imports":  {"dll_name": ["func1", "func2"]},
        "strings":  ["string_sospechoso_1", ...]
    }
    """

    # Validar que el archivo existe
    if not os.path.isfile(ruta_archivo):
        print(f"[ERROR] Archivo no encontrado: {ruta_archivo}")
        return {}

    nombre_archivo = os.path.basename(ruta_archivo)
    tamanio_bytes = os.path.getsize(ruta_archivo)

    print(f"[*] Analizando: {nombre_archivo} ({tamanio_bytes / 1024:.1f} KB)")

    # SHA-256
    print("[*] Calculando hash SHA-256...")
    sha256 = _calcular_sha256(ruta_archivo)

    # Cargar PE
    print("[*] Leyendo estructura PE...")
    try:
        pe = pefile.PE(ruta_archivo, fast_load=False)
    except pefile.PEFormatError:
        print("[ERROR] El archivo no es un PE válido o está corrupto.")
        return {
            "metadata": {"filename": nombre_archivo, "sha256": sha256, "size_bytes": tamanio_bytes},
            "imports": {},
            "strings": [],
            "error": "Archivo no es un PE válido."
        }
    except Exception as e:
        print(f"[ERROR] Fallo inesperado al leer el PE: {e}")
        return {}

    # Imports
    print("[*] Extrayendo tabla de imports...")
    imports = _extraer_imports(pe)
    total_funciones = sum(len(v) for v in imports.values())
    print(f"    → {len(imports)} DLLs | {total_funciones} funciones importadas")

    # Strings
    print("[*] Extrayendo strings sospechosos...")
    strings = _extraer_strings(ruta_archivo)
    print(f"    → {len(strings)} strings sospechosos encontrados")

    pe.close()

    resultado = {
        "metadata": {
            "filename": nombre_archivo,
            "sha256": sha256,
            "size_bytes": tamanio_bytes
        },
        "imports": imports,
        "strings": strings
    }

    print("[✓] Análisis estático completado.\n")
    return resultado


if __name__ == "__main__":
    import json
    import sys

    # Si se pasa un argumento usa ese archivo, si no usa notepad.exe como prueba
    if len(sys.argv) > 1:
        archivo = sys.argv[1]
    else:
        archivo = r"C:\Windows\System32\notepad.exe"

    resultado = parse_exe(archivo)

    if resultado:
        print(json.dumps(resultado, indent=4, ensure_ascii=False))
    else:
        print("[ERROR] No se pudo analizar el archivo.")