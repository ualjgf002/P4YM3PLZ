import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# Nombre lógico de la CA
CA_NAME = "MiCA_RSA"

# Archivos donde persistimos la CA (clave privada y pública)
CA_PRIV_PATH = "ca_private_key.pem"
CA_PUB_PATH = "ca_public_key.pem"


def _generate_and_persist_ca():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    # Serializar y escribir a disco
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(CA_PRIV_PATH, "wb") as f:
        f.write(priv_pem)
    with open(CA_PUB_PATH, "wb") as f:
        f.write(pub_pem)

    return priv, pub


def _load_ca_from_files():
    with open(CA_PRIV_PATH, "rb") as f:
        priv = load_pem_private_key(f.read(), password=None)
    with open(CA_PUB_PATH, "rb") as f:
        pub = load_pem_public_key(f.read())
    return priv, pub


# Inicialización: si no existe, generamos; si existe, cargamos.
if not (os.path.exists(CA_PRIV_PATH) and os.path.exists(CA_PUB_PATH)):
    ca_private_key, ca_public_key = _generate_and_persist_ca()
else:
    ca_private_key, ca_public_key = _load_ca_from_files()


def sign(data: bytes) -> bytes:
    """Firma con RSA-PSS + SHA256 usando la clave privada de la CA.

    La clave privada se persiste en `ca_private_key.pem` para que el servidor
    pueda reutilizar la misma CA entre procesos.
    """
    return ca_private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH,),
        hashes.SHA256(),
    )


def verify(data: bytes, signature: bytes) -> bool:
    """Verifica firma usando la clave pública de la CA (desde `ca_public_key.pem`)."""
    try:
        ca_public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH,),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
