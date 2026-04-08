import hashlib
import math
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

# Umbral de entropy a partir del cual una sección se considera sospechosa
ENTROPY_UMBRAL = 7.0


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


def _calcular_entropy(data: bytes) -> float:
    """
    Calcula la entropía de Shannon de un bloque de bytes.
    Rango: 0.0 (todos iguales) a 8.0 (totalmente aleatorio).
    Valores > 7.0 indican datos comprimidos, cifrados o empaquetados.
    """
    if not data:
        return 0.0

    # Contar frecuencia de cada byte posible (0-255)
    frecuencias = [0] * 256
    for byte in data:
        frecuencias[byte] += 1

    total = len(data)
    entropia = 0.0

    for freq in frecuencias:
        if freq > 0:
            probabilidad = freq / total
            entropia -= probabilidad * math.log2(probabilidad)

    return round(entropia, 4)


def _analizar_secciones(pe: pefile.PE) -> tuple:
    """
    Analiza todas las secciones del PE.
    Devuelve:
      - lista de todas las secciones con su entropy
      - lista de secciones sospechosas (entropy > ENTROPY_UMBRAL)
    """
    todas_secciones = []
    secciones_sospechosas = []

    for seccion in pe.sections:
        try:
            nombre = seccion.Name.decode("utf-8", errors="replace").strip().rstrip("\x00")
            datos = seccion.get_data()
            entropy = _calcular_entropy(datos)

            info_seccion = {
                "nombre": nombre,
                "tamano_virtual": seccion.Misc_VirtualSize,
                "tamano_raw": seccion.SizeOfRawData,
                "entropy": entropy,
                "sospechosa": entropy > ENTROPY_UMBRAL
            }

            todas_secciones.append(info_seccion)

            # Si supera el umbral, la marcamos aparte con explicación
            if entropy > ENTROPY_UMBRAL:
                secciones_sospechosas.append({
                    "nombre": nombre,
                    "entropy": entropy,
                    "motivo": f"Entropy {entropy} supera el umbral de {ENTROPY_UMBRAL} — posible código empaquetado o cifrado"
                })

        except Exception:
            continue

    return todas_secciones, secciones_sospechosas


def _detectar_upx(pe: pefile.PE) -> dict:
    """
    Detecta si el ejecutable fue empaquetado con UPX.
    UPX es el packer más usado para ocultar malware de los antivirus.
    Lo detectamos buscando sus secciones características: UPX0, UPX1, UPX2.
    """
    nombres_secciones = []

    for seccion in pe.sections:
        try:
            nombre = seccion.Name.decode("utf-8", errors="replace").strip().rstrip("\x00")
            nombres_secciones.append(nombre.upper())
        except Exception:
            continue

    secciones_upx = [n for n in nombres_secciones if n.startswith("UPX")]

    if secciones_upx:
        return {
            "detectado": True,
            "secciones_encontradas": secciones_upx,
            "riesgo": "ALTO",
            "motivo": "El ejecutable está empaquetado con UPX. Esta técnica se usa para ocultar el código real del binario y evadir antivirus."
        }

    return {
        "detectado": False,
        "secciones_encontradas": [],
        "riesgo": "NINGUNO",
        "motivo": "No se detectó empaquetado UPX."
    }


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
                    nombre_func = importacion.name.decode("utf-8", errors="replace")
                    funciones.append(nombre_func)
                else:
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

    string_actual = []
    for byte in contenido:
        if 32 <= byte <= 126:
            string_actual.append(chr(byte))
        else:
            if len(string_actual) >= min_longitud:
                texto = "".join(string_actual).strip()
                if texto:
                    strings_encontrados.add(texto)
            string_actual = []

    if len(string_actual) >= min_longitud:
        texto = "".join(string_actual).strip()
        if texto:
            strings_encontrados.add(texto)

    strings_filtrados = []
    for texto in strings_encontrados:
        texto_lower = texto.lower()
        for patron in PATRONES_SOSPECHOSOS:
            if patron in texto_lower:
                strings_filtrados.append(texto)
                break

    strings_filtrados.sort()
    return strings_filtrados[:50]


def parse_exe(ruta_archivo: str) -> dict:
    """
    Función principal del módulo. Recibe la ruta a un archivo .exe
    y devuelve el diccionario completo que consume el resto del sistema.

    Estructura de retorno:
    {
        "metadata":              {...},
        "imports":               {...},
        "strings":               [...],
        "secciones":             [...],   <- NUEVO: todas las secciones con entropy
        "secciones_sospechosas": [...],   <- NUEVO: solo las que superan 7.0
        "upx":                   {...}    <- NUEVO: resultado de detección UPX
    }
    """

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
            "secciones": [],
            "secciones_sospechosas": [],
            "upx": {"detectado": False},
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

    # Secciones + Entropy  ← NUEVO
    print("[*] Analizando secciones y calculando entropy...")
    secciones, secciones_sospechosas = _analizar_secciones(pe)
    print(f"    → {len(secciones)} secciones totales | {len(secciones_sospechosas)} sospechosas")
    for s in secciones_sospechosas:
        print(f"       ⚠  {s['nombre']} — entropy {s['entropy']}")

    # Detección UPX  ← NUEVO
    print("[*] Verificando empaquetado UPX...")
    upx = _detectar_upx(pe)
    if upx["detectado"]:
        print(f"    → ⚠  UPX DETECTADO: {upx['secciones_encontradas']}")
    else:
        print("    → Sin empaquetado UPX")

    pe.close()

    resultado = {
        "metadata": {
            "filename": nombre_archivo,
            "sha256": sha256,
            "size_bytes": tamanio_bytes
        },
        "imports": imports,
        "strings": strings,
        "secciones": secciones,
        "secciones_sospechosas": secciones_sospechosas,
        "upx": upx
    }

    print("[✓] Análisis estático completado.\n")
    return resultado


# ── Prueba local ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1:
        archivo = sys.argv[1]
    else:
        archivo = r"C:\Windows\System32\notepad.exe"

    resultado = parse_exe(archivo)

    if resultado:
        print(json.dumps(resultado, indent=4, ensure_ascii=False))
    else:
        print("[ERROR] No se pudo analizar el archivo.")