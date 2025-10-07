from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt(plaintext, key_size=128, mode_name='CBC'):
    # Generar clave aleatoria
    key = os.urandom(key_size // 8)
    
    # Inicialización del vector (IV) para modos que lo requieran
    iv = os.urandom(16)
    
    # Selección del modo
    mode = None
    if mode_name.upper() == 'ECB':
        mode = modes.ECB()
    elif mode_name.upper() == 'CBC':
        mode = modes.CBC(iv)
    elif mode_name.upper() == 'CFB':
        mode = modes.CFB(iv)
    elif mode_name.upper() == 'OFB':
        mode = modes.OFB(iv)
    elif mode_name.upper() == 'CTR':
        mode = modes.CTR(iv)
    else:
        raise ValueError("Modo no soportado")
    
    # Crear cifrador AES
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding para que el texto sea múltiplo de 16 bytes
    pad_len = 16 - (len(plaintext) % 16)
    padded_text = plaintext + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return key, iv, ciphertext

def aes_decrypt(ciphertext, key, iv=None, mode_name='CBC'):
    mode = None
    if mode_name.upper() == 'ECB':
        mode = modes.ECB()
    elif mode_name.upper() == 'CBC':
        mode = modes.CBC(iv)
    elif mode_name.upper() == 'CFB':
        mode = modes.CFB(iv)
    elif mode_name.upper() == 'OFB':
        mode = modes.OFB(iv)
    elif mode_name.upper() == 'CTR':
        mode = modes.CTR(iv)
    else:
        raise ValueError("Modo no soportado")
    
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Quitar padding
    pad_len = padded_text[-1]
    plaintext = padded_text[:-pad_len]
    return plaintext

# =============================
# Programa interactivo
# =============================
if __name__ == "__main__":
    mensaje = input("Introduce el texto a cifrar: ").encode()  # Convertir a bytes
    key_size = int(input("Elige tamaño de clave (128, 192, 256): "))
    mode = input("Elige modo de cifrado (ECB, CBC, CFB, OFB, CTR): ")

    key, iv, cifrado = aes_encrypt(mensaje, key_size=key_size, mode_name=mode)
    print("\n--- Resultado ---")
    print("Texto cifrado (hex):", cifrado.hex())
    
    descifrado = aes_decrypt(cifrado, key, iv, mode_name=mode)
    print("Texto descifrado:", descifrado.decode())
