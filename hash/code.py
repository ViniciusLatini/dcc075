import os
import json
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Gera par de chaves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Salva chave privada
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Salva chave pública
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Chaves RSA geradas!")

# Le arquivo original
arquivo_entrada = "texto.txt"

with open(arquivo_entrada, "rb") as f:
    conteudo = f.read()

# Assina
assinatura = private_key.sign(
    conteudo,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Arquivo assinado!")

pacote = {
    "nome_arquivo": os.path.basename(arquivo_entrada),
    "conteudo": base64.b64encode(conteudo).decode(),
    "assinatura": base64.b64encode(assinatura).decode()
}

with open("arquivo_assinado.json", "w") as f:
    json.dump(pacote, f)

print("Arquivo assinado salvo!")