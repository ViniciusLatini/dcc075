from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Carregar Chave Pública e Dados Recebidos
with open("publica.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open("envio.dat", "rb") as f:
    dados_recebidos = f.read()

# 2. Separar Mensagem e Assinatura
msg_recebida = dados_recebidos[:-256]
assinatura_recebida = dados_recebidos[-256:]

# 3. Verificação da Assinatura
print("--- DESTINO B (Caso A) ---")
try:
    public_key.verify(
        assinatura_recebida,
        msg_recebida,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Sucesso: Assinatura digital validada!")
    print(f"Mensagem Validada: {msg_recebida.decode('utf-8')}")
except Exception:
    print("Erro: Falha na verificacao da assinatura. A mensagem nao e confiavel.")