import socket, json
from ca_rsa import verify, CA_NAME


def recibir_linea(sock):
    """Lee del socket hasta encontrar un salto de línea."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()


def comprobar_cert(cert: dict, host_esperado: str) -> bool:
    """Verifica identidad, CA y firma del certificado."""
    if cert.get("identity") != host_esperado:
        print("[!] Identidad del certificado NO coincide con el host esperado.")
        return False

    if cert.get("ca_name") != CA_NAME:
        print("[!] CA del certificado NO está en el almacén de confianza.")
        return False

    public_key_pem = cert["public_key_pem"].encode()
    firma = bytes.fromhex(cert["signature"])
    to_verify = cert["identity"].encode() + public_key_pem + cert["ca_name"].encode()

    if not verify(to_verify, firma):
        print("[!] Firma RSA inválida: el certificado puede ser falso o manipulado.")
        return False

    print("[+] Certificado válido: identidad y firma correctas.")
    return True


def flujo_bueno(sock):
    sock.sendall(b"GET_APP")
    app = sock.recv(4096)
    with open("app_legitima.bin", "wb") as f:
        f.write(app)
    print("[+] Aplicación legítima descargada como app_legitima.bin")
    print("[*] (Simulación) Aquí podrías 'instalar' o ejecutar la app segura.")


def flujo_falso(sock):
    print("[*] Visitando sitio 'banco falso'...")
    input("[*] Pulsa ENTER para hacer clic en el enlace sospechoso de descarga...")
    sock.sendall(b"GET_MALWARE")
    m = sock.recv(4096)
    fname = "malware_demo.bin"
    with open(fname, "wb") as f:
        f.write(m)
    print(f"[!] Archivo corrupto descargado como {fname}")
    print("[!] (Simulación) Ejecutando archivo descargado... (solo demo, no hace nada peligroso)")


def conectar(host, port, esperado, modo):
    s = socket.socket()
    s.connect((host, port))

    # 1) Recibir y parsear certificado
    cert_text = recibir_linea(s)
    cert = json.loads(cert_text)

    # 2) Verificar certificado
    if not comprobar_cert(cert, esperado):
        print("[!] ADVERTENCIA: certificado NO confiable / conexión peligrosa.")
        seguir = input("¿Ignorar advertencia y continuar? (s/n): ").lower()
        if seguir != "s":
            print("[*] Conexión abortada por el usuario.")
            s.close()
            return
        else:
            print("[*] El usuario ha decidido continuar A PESAR de la advertencia...")

    # 3) Flujo según modo
    if modo == "bueno":
        flujo_bueno(s)
    else:
        flujo_falso(s)

    s.close()


if __name__ == "__main__":
    print("=== DEMO DE CERTIFICADOS Y FALSO BANCO ===")
    print("1) Conectar a servidor bueno")
    print("2) Conectar a banco falso")
    op = input("Opción (1/2): ").strip()

    if op == "1":
        conectar("127.0.0.1", 4443, "www.bueno.com", "bueno")
    else:
        conectar("127.0.0.1", 4444, "www.banco-falso.com", "falso")
