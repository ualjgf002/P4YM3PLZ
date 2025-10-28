import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ===== Encabezado sencillo para autodescribir los .enc =====
HEADER_MAGIC = "P4Y1"  # Marca del formato

def _make_header(modo: str, key_bits: int) -> bytes:
    """
    Encabezado ASCII de una línea:
    P4Y1|<MODO>|<KEYBITS>\n
    """
    return f"{HEADER_MAGIC}|{modo.upper()}|{key_bits}\n".encode("ascii")

def _parse_header(blob: bytes):
    """
    Lee el encabezado y devuelve (modo, key_bits, resto_bytes).
    """
    nl = blob.find(b"\n")
    if nl == -1:
        raise ValueError("Archivo sin encabezado (no se encontró salto de línea).")
    header = blob[:nl].decode("ascii", errors="strict")
    parts = header.split("|")
    if len(parts) != 3 or parts[0] != HEADER_MAGIC:
        raise ValueError("Encabezado no válido.")
    modo = parts[1].upper()
    key_bits = int(parts[2])
    resto = blob[nl + 1:]
    return modo, key_bits, resto

# ===== Utilidades AES =====
def generar_clave(longitud_bits):
    """Genera una clave AES aleatoria según la longitud en bits (128, 192 o 256)."""
    return os.urandom(longitud_bits // 8)

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
        raise ValueError("Modo de cifrado no soportado")

# ===== Naming automático (.p4ym3) =====
def _out_path_same_name_with_ext(input_path: str, suffix: str = "") -> str:
    """
    Genera ruta de salida en el mismo directorio, con el mismo nombre base
    y extensión .p4ym3. Si coincide con el archivo de entrada o ya existe,
    añade sufijo incremental _1, _2, ...
    """
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

# ===== Cifrar / Descifrar =====
def cifrar_archivo(ruta_entrada, clave, modo):
    """Cifra un archivo y escribe HEADER + IV + CIPHERTEXT en <mismo_nombre>.p4ym3"""
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    iv = os.urandom(16)
    modo_upper = modo.upper()

    # Padding solo en CBC
    if modo_upper == "CBC":
        padder = padding.PKCS7(128).padder()
        datos = padder.update(datos) + padder.finalize()

    cipher = _cipher_from_mode(clave, modo_upper, iv)
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos) + encryptor.finalize()

    # HEADER + IV + CIPHERTEXT
    header = _make_header(modo_upper, len(clave) * 8)

    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="")
    with open(ruta_salida, "wb") as f:
        f.write(header + iv + datos_cifrados)

    print(f"Archivo cifrado: {ruta_salida}")
    print(f"IV utilizado: {iv.hex()}")
    return ruta_salida

def descifrar_archivo(ruta_entrada, clave):
    """Descifra leyendo modo y tamaño de clave desde el encabezado y guarda como <mismo_nombre>_dec.p4ym3"""
    with open(ruta_entrada, "rb") as f:
        blob = f.read()

    modo_upper, key_bits, resto = _parse_header(blob)

    # Comprobar tamaño de clave esperado por el fichero
    if key_bits != len(clave) * 8:
        raise ValueError(
            f"Tamaño de clave incorrecto: el fichero espera {key_bits} bits "
            f"y has introducido {len(clave) * 8} bits."
        )

    if len(resto) < 16:
        raise ValueError("Archivo corrupto: faltan bytes para el IV.")
    iv, datos_cifrados = resto[:16], resto[16:]

    cipher = _cipher_from_mode(clave, modo_upper, iv)
    decryptor = cipher.decryptor()
    datos = decryptor.update(datos_cifrados) + decryptor.finalize()

    # Unpadding solo si se cifró en CBC
    if modo_upper == "CBC":
        unpadder = padding.PKCS7(128).unpadder()
        datos = unpadder.update(datos) + unpadder.finalize()

    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="_dec")
    with open(ruta_salida, "wb") as f:
        f.write(datos)

    print(f"Archivo descifrado: {ruta_salida}")
    return ruta_salida

# ===== Interfaz mínima por consola =====
def main():
    print("=== Aplicación AES (con encabezado) ===")
    accion = input("¿Deseas cifrar (C) o descifrar (D)? ").strip().upper()

    ruta_entrada = input("Ruta del archivo de entrada: ").strip().strip('"')
    if not os.path.isfile(ruta_entrada):
        print("No existe el archivo de entrada.")
        return

    if accion == "C":
        print("Opciones de longitud de clave: 128, 192, 256")
        try:
            longitud = int(input("Introduce la longitud de clave en bits: ").strip())
        except ValueError:
            longitud = 256
        if longitud not in [128, 192, 256]:
            print("Longitud no válida. Usando 256 bits por defecto.")
            longitud = 256

        print("Opciones de modos: CBC, CFB, OFB, CTR")
        modo = input("Introduce el modo de cifrado: ").strip().upper()
        if modo not in ["CBC", "CFB", "OFB", "CTR"]:
            print("Modo no válido. Usando CBC por defecto.")
            modo = "CBC"

        clave = generar_clave(longitud)
        print(f"*** Guarda esta clave para descifrar después ***: {clave.hex()}")

        cifrar_archivo(ruta_entrada, clave, modo)

    elif accion == "D":
        # Descifrado: NO pedimos modo ni longitud; se leen del encabezado
        clave_hex = input("Introduce la clave en hex usada en el cifrado: ").strip()
        try:
            clave = bytes.fromhex(clave_hex)
        except ValueError:
            print("Clave en hex no válida.")
            return
        if len(clave) not in (16, 24, 32):
            print("Longitud de clave inválida para AES.")
            return

        descifrar_archivo(ruta_entrada, clave)
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
