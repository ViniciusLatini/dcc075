import hashlib
import random
import time
import matplotlib.pyplot as plt

# CONFIGURAÇÃO

arquivo = "arquivo_assinado.json"

dificuldades = [1, 2, 3, 4]

repeticoes = 5

with open(arquivo, "rb") as f:
    dados_arquivo = f.read()

def minerar(dificuldade):

    prefixo = "0" * dificuldade

    tentativas = 0

    inicio = time.time()

    while True:

        nonce = random.randint(0, 2**32)

        bloco = dados_arquivo + str(nonce).encode()

        hash_resultado = hashlib.sha256(bloco).hexdigest()

        tentativas += 1

        if hash_resultado.startswith(prefixo):

            fim = time.time()

            return {
                "nonce": nonce,
                "hash": hash_resultado,
                "tentativas": tentativas,
                "tempo": fim - inicio
            }


resultados = {}

for dificuldade in dificuldades:

    tempos = []

    print("\n===================================")
    print(f"Dificuldade: {dificuldade} zeros")
    print("===================================")

    for i in range(repeticoes):

        resultado = minerar(dificuldade)

        tempos.append(resultado["tempo"])

        print(f"\nTeste {i+1}")
        print(f"Nonce encontrado: {resultado['nonce']}")
        print(f"Hash: {resultado['hash']}")
        print(f"Tentativas: {resultado['tentativas']}")
        print(f"Tempo: {resultado['tempo']:.4f} segundos")

    media = sum(tempos) / len(tempos)

    resultados[dificuldade] = media

    x = list(resultados.keys())
    y = list(resultados.values())

    plt.figure(figsize=(8,5))

    plt.plot(x, y, marker='o')

    plt.xlabel("Número de zeros iniciais")
    plt.ylabel("Tempo médio (segundos)")
    plt.title("Proof of Work - Dificuldade vs Tempo")

    plt.grid(True)

    plt.savefig("grafico_pow.png")

    print("Gráfico salvo em grafico_pow.png")