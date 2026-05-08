from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 1. Geração de Chaves (Simulando Origem A)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Salva a publica para o receptor
with open("publica.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2. Criar a Assinatura Digital: E(PRa, H(M))
mensagem = b"Enviando a mesagem para o ponto B"
assinatura = private_key.sign(
    mensagem,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# 3. Enviar Mensagem + Assinatura
with open("envio.dat", "wb") as f:
    f.write(mensagem + assinatura)

print("--- ORIGEM A (Caso A) ---")
print("Mensagem enviada com assinatura digital.")