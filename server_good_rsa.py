import socket, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from ca_rsa import sign, CA_NAME

import os, sys

IDENTITY = "www.bueno.com"
# Permitimos sobrescribir el puerto por variable de entorno PORT o por primer arg CLI
_port_env = os.getenv("PORT")
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
elif _port_env:
    PORT = int(_port_env)
else:
    PORT = 4443


def create_server_keypair():
    """Genera par de claves del servidor (en memoria)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def create_cert(identity: str, public_key_pem: bytes) -> dict:
    """Construye un 'certificado' simple firmado por la CA."""
    # to_sign = identity + public_key + CA_NAME
    to_sign = identity.encode() + public_key_pem + CA_NAME.encode()
    signature = sign(to_sign)
    return {
        "identity": identity,
        "public_key_pem": public_key_pem.decode(),
        "ca_name": CA_NAME,
        "signature": signature.hex(),
    }


def main():
    server_priv, server_pub_pem = create_server_keypair()
    cert = create_cert(IDENTITY, server_pub_pem)
    cert_text = json.dumps(cert)

    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(5)
    print(f"[+] Servidor bueno (RSA) escuchando en puerto {PORT}")

    while True:
        conn, addr = s.accept()
        print("[*] Conexión desde", addr)
        # 1) Enviar certificado (una línea terminada en \n)
        conn.sendall((cert_text + "\n").encode())

        # 2) Esperar petición de app
        req = conn.recv(1024).decode().strip()
        if req == "GET_APP":
            conn.sendall(b"APP_LEGITIMA_BINARIA_SIMULADA")
        conn.close()


if __name__ == "__main__":
    main()
