import os
import base64
from getpass import getpass
from typing import Tuple, Optional

from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# ===== Encabezado para .p4ym3 con clave envuelta =====
HEADER_MAGIC = "P4Y1"
PKALG_RSA_OAEP_SHA256 = "RSA_OAEP_SHA256"


def _make_header_line1(modo: str, key_bits: int, pk_alg: str) -> bytes:
    """
    Línea 1 (ASCII, termina en \n): P4Y1|<MODO>|<KEYBITS>|PKALG=<ALG>\n
    """
    return f"{HEADER_MAGIC}|{modo.upper()}|{key_bits}|PKALG={pk_alg}\n".encode("ascii")


def _make_header_line2_wrapped_key_b64(wrapped_key: bytes) -> bytes:
    """
    Línea 2 (ASCII, termina en \n): <WRAPPED_KEY_BASE64>\n
    """
    return (base64.b64encode(wrapped_key) + b"\n")


def _parse_header_2lines(blob: bytes):
    """
    Lee las dos primeras líneas ASCII del blob.
    Devuelve (modo, key_bits, pk_alg, wrapped_key_bytes, resto_bytes).
    """
    nl1 = blob.find(b"\n")
    if nl1 == -1:
        raise ValueError("Archivo sin encabezado: falta línea 1.")
    line1 = blob[:nl1].decode("ascii", errors="strict")
    parts = line1.split("|")
    if len(parts) < 3 or parts[0] != HEADER_MAGIC:
        raise ValueError("Encabezado (línea 1) no válido.")
    modo = parts[1].upper()
    key_bits = int(parts[2])
    pk_alg = PKALG_RSA_OAEP_SHA256  # por defecto
    if len(parts) >= 4 and parts[3].startswith("PKALG="):
        pk_alg = parts[3].split("=", 1)[1]

    # Línea 2: wrapped key en base64
    rem = blob[nl1 + 1:]
    nl2 = rem.find(b"\n")
    if nl2 == -1:
        raise ValueError("Archivo sin encabezado: falta línea 2 con clave envuelta.")
    line2 = rem[:nl2]
    try:
        wrapped_key = base64.b64decode(line2, validate=True)
    except Exception as e:
        raise ValueError("Línea 2 no es base64 válido para clave envuelta.") from e

    resto = rem[nl2 + 1:]
    return modo, key_bits, pk_alg, wrapped_key, resto


# ===== Utilidades RSA (Tarea 3) =====
def generar_rsa_keypair(bits: int = 3072) -> Tuple[bytes, bytes]:
    """Genera un par RSA (privada PEM cifrada con contraseña a elección y pública PEM)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    password = getpass("Introduce una contraseña para cifrar la clave privada (o deja vacío para no cifrar): ")
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
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


# ===== Utilidades AES (Tarea 2) =====
def generar_clave(longitud_bits: int) -> bytes:
    if longitud_bits not in (128, 192, 256):
        raise ValueError("La longitud de clave debe ser 128, 192 o 256 bits.")
    return AESGCM.generate_key(bit_length=longitud_bits)


def _cipher_from_mode(clave: bytes, modo_upper: str, iv: bytes) -> Cipher:
    if modo_upper == "CBC":
        return Cipher(algorithms.AES(clave), modes.CBC(iv))
    elif modo_upper == "CFB":
        return Cipher(algorithms.AES(clave), modes.CFB(iv))
    elif modo_upper == "OFB":
        return Cipher(algorithms.AES(clave), modes.OFB(iv))
    elif modo_upper == "CTR":
        return Cipher(algorithms.AES(clave), modes.CTR(iv))
    else:
        raise ValueError("Modo de cifrado no soportado (CBC/CFB/OFB/CTR)")


def _out_path_same_name_with_ext(input_path: str, suffix: str = "") -> str:
    d = os.path.dirname(input_path) or "."
    base = os.path.splitext(os.path.basename(input_path))[0]
    candidate = os.path.join(d, f"{base}{suffix}.p4ym3")
    in_abs = os.path.abspath(input_path)
    cand_abs = os.path.abspath(candidate)
    if cand_abs == in_abs or os.path.exists(candidate):
        i = 1
        while True:
            candidate2 = os.path.join(d, f"{base}{suffix}_{i}.p4ym3")
            cand2_abs = os.path.abspath(candidate2)
            if cand2_abs == in_abs or os.path.exists(candidate2):
                i += 1
                continue
            candidate = candidate2
            break
    return candidate


# ===== Cifrar / Descifrar (híbrido) =====
def cifrar_archivo(ruta_entrada: str, modo: str, key_bits: int, public_key_pem_path: str) -> str:
    """
    Cifra un archivo (AES modo seleccionado) y envuelve la clave simétrica con la
    clave pública RSA (OAEP-SHA256). Escribe:
    L1: P4Y1|<MODO>|<KEYBITS>|PKALG=RSA_OAEP_SHA256\n
    L2: <WRAPPED_KEY_BASE64>\n
    BIN: IV (16 bytes) + CIPHERTEXT
    """
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError("No existe el archivo de entrada.")
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    iv = os.urandom(16)
    modo_upper = modo.upper()
    if modo_upper == "CBC":
        padder = sym_padding.PKCS7(128).padder()
        datos = padder.update(datos) + padder.finalize()

    # 1) Generar clave simétrica
    clave = generar_clave(key_bits)

    # 2) Cargar clave pública y envolver
    pubkey = cargar_public_key_pem(public_key_pem_path)
    wrapped = wrap_key_rsa_oaep(pubkey, clave)

    # 3) Cifrar datos con AES
    cipher = _cipher_from_mode(clave, modo_upper, iv)
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos) + encryptor.finalize()

    # 4) Construir salida
    header1 = _make_header_line1(modo_upper, len(clave) * 8, PKALG_RSA_OAEP_SHA256)
    header2 = _make_header_line2_wrapped_key_b64(wrapped)
    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="")
    with open(ruta_salida, "wb") as f:
        f.write(header1 + header2 + iv + datos_cifrados)

    print(f"Archivo cifrado: {ruta_salida}")
    print(f"IV utilizado: {iv.hex()}\nClave simétrica (no se muestra por seguridad). Clave envuelta: {len(wrapped)} bytes.")
    return ruta_salida


def descifrar_archivo(ruta_entrada: str, private_key_pem_path: str, private_key_password: Optional[str] = None) -> str:
    """
    Descifra leyendo modo, tamaño de clave y algoritmo PK del encabezado. Desenvuelve la
    clave simétrica con la clave privada RSA (OAEP-SHA256) y luego descifra el resto.
    Salida: <mismo_nombre>_dec.p4ym3
    """
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError("No existe el archivo de entrada.")
    with open(ruta_entrada, "rb") as f:
        blob = f.read()

    modo_upper, key_bits, pk_alg, wrapped_key, resto = _parse_header_2lines(blob)
    if pk_alg != PKALG_RSA_OAEP_SHA256:
        raise ValueError(f"Algoritmo de clave pública no soportado en este fichero: {pk_alg}")

    # 1) Desenvolver la clave simétrica
    privkey = cargar_private_key_pem(private_key_pem_path, private_key_password)
    clave = unwrap_key_rsa_oaep(privkey, wrapped_key)
    if len(clave) * 8 != key_bits:
        raise ValueError(f"La clave simétrica envuelta es de {len(clave)*8} bits y no coincide con {key_bits} bits esperados.")

    # 2) Separar IV y ciphertext
    if len(resto) < 16:
        raise ValueError("Archivo corrupto: faltan bytes para el IV.")
    iv, datos_cifrados = resto[:16], resto[16:]

    # 3) Descifrar
    cipher = _cipher_from_mode(clave, modo_upper, iv)
    decryptor = cipher.decryptor()
    datos = decryptor.update(datos_cifrados) + decryptor.finalize()

    if modo_upper == "CBC":
        unpadder = sym_padding.PKCS7(128).unpadder()
        datos = unpadder.update(datos) + unpadder.finalize()

    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="_dec")
    with open(ruta_salida, "wb") as f:
        f.write(datos)

    print(f"Archivo descifrado: {ruta_salida}")
    return ruta_salida


# ===== Interfaz mínima por consola =====
def main():
    print("=== Aplicación AES + RSA (cifrado híbrido con encabezado) ===")
    print("[C] Cifrar  [D] Descifrar  [G] Generar par RSA (opcional) ")
    accion = input("Selecciona opción: ").strip().upper()

    if accion == "G":
        bits = input("Tamaño de clave RSA (2048/3072, por defecto 3072): ").strip()
        try:
            bits = int(bits)
        except ValueError:
            bits = 3072
        priv_pem, pub_pem = generar_rsa_keypair(bits)
        out_priv = os.path.abspath("rsa_private.pem")
        out_pub = os.path.abspath("rsa_public.pem")
        with open(out_priv, "wb") as f:
            f.write(priv_pem)
        with open(out_pub, "wb") as f:
            f.write(pub_pem)
        print(f"Claves generadas:\n  Privada: {out_priv}\n  Pública: {out_pub}")
        return

    ruta_entrada = input("Ruta del archivo de entrada: ").strip().strip('"')
    if not os.path.isfile(ruta_entrada):
        print("No existe el archivo de entrada.")
        return

    if accion == "C":
        print("Opciones de longitud de clave simétrica (AES): 128, 192, 256")
        try:
            key_bits = int(input("Introduce la longitud de clave en bits: ").strip())
        except ValueError:
            key_bits = 256
        if key_bits not in (128, 192, 256):
            print("Longitud no válida. Usando 256 bits por defecto.")
            key_bits = 256

        print("Modos AES soportados: CBC, CFB, OFB, CTR")
        modo = input("Introduce el modo de cifrado: ").strip().upper()
        if modo not in ("CBC", "CFB", "OFB", "CTR"):
            print("Modo no válido. Usando CTR por defecto.")
            modo = "CTR"

        pub_path = input("Ruta a la clave PÚBLICA RSA (PEM) del destinatario: ").strip().strip('"')
        if not os.path.isfile(pub_path):
            print("No se ha encontrado la clave pública.")
            return

        cifrar_archivo(ruta_entrada, modo, key_bits, pub_path)

    elif accion == "D":
        priv_path = input("Ruta a la clave PRIVADA RSA (PEM): ").strip().strip('"')
        if not os.path.isfile(priv_path):
            print("No se ha encontrado la clave privada.")
            return
        need_pw = input("¿La clave privada tiene contraseña? (S/N): ").strip().upper()
        pw = None
        if need_pw == "S":
            pw = getpass("Introduce la contraseña de la clave privada: ")

        descifrar_archivo(ruta_entrada, priv_path, pw)
    else:
        print("Opción no válida.")


if __name__ == "__main__":
    main()
