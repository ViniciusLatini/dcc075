from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. Carregar chaves e dados
with open("publica.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
with open("pacote.dat", "rb") as f:
    pacote = f.read()
with open("transmissao.key", "rb") as f:
    key_data = f.read()
    chave_k, iv = key_data[:32], key_data[32:]

# 2. Descriptografia: D(K, pacote)
cipher = Cipher(algorithms.AES(chave_k), modes.CFB(iv))
decryptor = cipher.decryptor()
dados_decifrados = decryptor.update(pacote) + decryptor.finalize()

# 3. Separar Mensagem e Assinatura (RSA 2048 = 256 bytes)
msg_recebida = dados_decifrados[:-256]
assinatura_recebida = dados_decifrados[-256:]

# 4. Verificação e Exibição Final
print("--- DESTINO B ---")
try:
    public_key.verify(
        assinatura_recebida,
        msg_recebida,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Sucesso: A assinatura digital e valida.")
    print(f"Mensagem Validada: {msg_recebida.decode('utf-8')}")
except Exception as e:
    print("Erro: A assinatura e invalida. A mensagem pode ter sido alterada.")