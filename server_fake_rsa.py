import socket, json
from ca_rsa import CA_NAME  # solo para saber el nombre de la CA real

import os, sys

IDENTITY_FAKE = "www.banco-falso.com"
# Permitimos sobrescribir el puerto por variable de entorno PORT o por primer arg CLI
_port_env = os.getenv("PORT")
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
elif _port_env:
    PORT = int(_port_env)
else:
    PORT = 4444

# Certificado falso: CA distinta y firma basura
FAKE_CERT = {
    "identity": IDENTITY_FAKE,
    "public_key_pem": "PUBLIC_KEY_FALSA_EN_PEM",
    "ca_name": "OtraCA_Que_No_Es_" + CA_NAME,
    "signature": "00" * 256,  # no valida con la CA real
}


def main():
    cert_text = json.dumps(FAKE_CERT)

    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(5)
    print(f"[+] Servidor falso (RSA) escuchando en puerto {PORT}")

    while True:
        conn, addr = s.accept()
        print("[*] Conexión desde", addr)
        # 1) Enviar certificado falso
        conn.sendall((cert_text + "\n").encode())

        # 2) Esperar petición de "malware"
        req = conn.recv(1024).decode().strip()
        if req == "GET_MALWARE":
            conn.sendall(b"BINARIO_CORRUPTO_DEMO")
        conn.close()


if __name__ == "__main__":
    main()
