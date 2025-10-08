import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generar_clave(longitud_bits):
    """Genera una clave AES aleatoria según la longitud en bits (128, 192 o 256)."""
    return os.urandom(longitud_bits // 8)

def cifrar_archivo(ruta_entrada, ruta_salida, clave, modo):
    """Cifra un archivo binario usando AES."""
    # Leer contenido del archivo
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    # Padding PKCS7
    padder = padding.PKCS7(128).padder()
    datos_padded = padder.update(datos) + padder.finalize()

    # Generar IV
    iv = os.urandom(16)

    # Crear objeto Cipher según modo
    modo_upper = modo.upper()
    if modo_upper == "CBC":
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    elif modo_upper == "CFB":
        cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    elif modo_upper == "OFB":
        cipher = Cipher(algorithms.AES(clave), modes.OFB(iv), backend=default_backend())
    elif modo_upper == "CTR":
        cipher = Cipher(algorithms.AES(clave), modes.CTR(iv), backend=default_backend())
    else:
        raise ValueError("Modo de cifrado no soportado")

    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos_padded) + encryptor.finalize()

    # Guardar IV + datos cifrados en el archivo de salida
    with open(ruta_salida, "wb") as f:
        f.write(iv + datos_cifrados)

    print(f"Archivo cifrado correctamente: {ruta_salida}")
    print(f"IV utilizado: {iv.hex()}")

def descifrar_archivo(ruta_entrada, ruta_salida, clave, modo):
    """Descifra un archivo previamente cifrado con AES."""
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    iv = datos[:16]
    datos_cifrados = datos[16:]

    modo_upper = modo.upper()
    if modo_upper == "CBC":
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    elif modo_upper == "CFB":
        cipher = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    elif modo_upper == "OFB":
        cipher = Cipher(algorithms.AES(clave), modes.OFB(iv), backend=default_backend())
    elif modo_upper == "CTR":
        cipher = Cipher(algorithms.AES(clave), modes.CTR(iv), backend=default_backend())
    else:
        raise ValueError("Modo de cifrado no soportado")

    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(datos_cifrados) + decryptor.finalize()

    # Quitar padding PKCS7
    unpadder = padding.PKCS7(128).unpadder()
    datos = unpadder.update(datos_padded) + unpadder.finalize()

    with open(ruta_salida, "wb") as f:
        f.write(datos)

    print(f"Archivo descifrado correctamente: {ruta_salida}")

def main():
    print("=== Aplicación de cifrado AES para archivos ===")
    accion = input("¿Deseas cifrar (C) o descifrar (D)? ").upper()

    print("Opciones de longitud de clave: 128, 192, 256")
    longitud = int(input("Introduce la longitud de clave en bits: "))
    if longitud not in [128, 192, 256]:
        print("Longitud no válida. Usando 256 bits por defecto.")
        longitud = 256

    print("Opciones de modos: CBC, CFB, OFB, CTR")
    modo = input("Introduce el modo de cifrado: ").upper()
    if modo not in ["CBC", "CFB", "OFB", "CTR"]:
        print("Modo no válido. Usando CBC por defecto.")
        modo = "CBC"

    clave = generar_clave(longitud)
    print(f"Clave generada ({longitud} bits): {clave.hex()}")

    ruta_entrada = input("Ruta del archivo de entrada: ")

    if accion == "C":
        ruta_salida = input("Ruta del archivo cifrado (por ejemplo, archivo.enc): ")
        cifrar_archivo(ruta_entrada, ruta_salida, clave, modo)
    elif accion == "D":
        ruta_salida = input("Ruta del archivo descifrado (por ejemplo, archivo_out.txt): ")
        descifrar_archivo(ruta_entrada, ruta_salida, clave, modo)
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
