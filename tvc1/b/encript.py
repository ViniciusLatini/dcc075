import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. Gerar chaves para assinatura
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Salvar PU
with open("publica.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2. Assinatura digital: E(PRa, H(M)) => hash (SHA256) + chave privada
mensagem = b"testando uma mensagem para o ponto B"
assinatura = private_key.sign(
    mensagem,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# 3. Criptografia Simétrica: E(K, [M || Assinatura]) => chave K (AES-256) + (assinatura + mensagem) cifrados
chave_k = os.urandom(32) 
iv = os.urandom(16)
dados_combinados = mensagem + assinatura

cipher = Cipher(algorithms.AES(chave_k), modes.CFB(iv))
encryptor = cipher.encryptor()
pacote_final = encryptor.update(dados_combinados) + encryptor.finalize()

with open("pacote.dat", "wb") as f:
    f.write(pacote_final)
with open("transmissao.key", "wb") as f:
    f.write(chave_k + iv)

print("--- ORIGEM A ---")
print("Mensagem assinada e pacote criptografado com sucesso")