import json
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Carrega cahves
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Le arquivo
with open("arquivo_assinado.json", "r") as f:
    pacote = json.load(f)

nome_arquivo = pacote["nome_arquivo"]

conteudo = base64.b64decode(
    pacote["conteudo"]
)

assinatura = base64.b64decode(
    pacote["assinatura"]
)

# Verificando assinatura
try:
    public_key.verify(
        assinatura,
        conteudo,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Assinatura válida!")
    print("Arquivo íntegro e autêntico!")

except InvalidSignature:
    print("Assinatura INVÁLIDA!")
    exit()

arquivo_saida = "RECUPERADO_" + nome_arquivo

with open(arquivo_saida, "wb") as f:
    f.write(conteudo)

print(f"Arquivo restaurado: {arquivo_saida}")