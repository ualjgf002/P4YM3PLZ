import os
from Programa import ejecutable

cwd = os.getcwd()
print('CWD:', cwd)
# Ensure keys exist
ejecutable.generar_y_guardar_claves_repo(cwd)
pub_main, pub_two, pub_sign_pub, priv_sign = ejecutable.obtener_claves_de_repo(cwd)
priv_main = os.path.join(cwd, 'rsa_main_private.pem')

# Create test file
infile = os.path.join(cwd, 'test_integration.txt')
with open(infile, 'wb') as f:
    f.write(b'Test integration content')

# Encrypt
out = ejecutable.cifrar_archivo_automatico(infile, pub_main, modo='CTR', key_bits=256, sign_private_key_pem_path=priv_sign, keyid='main', eliminar_original=False)
print('Encrypted ->', out)

# Decrypt
dec = ejecutable.descifrar_archivo_automatico(out, priv_main, verify_public_key_path=pub_sign_pub)
print('Decrypted ->', dec)

# Verify content
with open(dec, 'rb') as f:
    data = f.read()
print('Match:', data == b'Test integration content')
