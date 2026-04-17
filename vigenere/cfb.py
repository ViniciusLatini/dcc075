import random

key = 'teste'
block_size = len(key)
init_vector = "fehag"

plainText = open('./plain-text.txt', 'r', encoding='utf-8').read().lower()
text_size = len(plainText)

def splitBlocks(plainText):
    blocks = []
    for i in range(0, len(plainText), block_size):
        blocks.append(plainText[i:i + block_size])
    return blocks

def addPadding(blocks):
    for i in range(len(blocks)):
        if len(blocks[i]) < block_size:
            randon_char = random.choice('abcdefghijklmnopqrstuvwxyz')
            blocks[i] += randon_char * (block_size - len(blocks[i]))
    return blocks

def encondingBlock(block, key):
    encoded_block = ""
    for i in range(len(block)):
        if block[i].isalpha():
            enconded_char = (ord(block[i]) - ord('a') + ord(key[i % block_size]) - ord('a')) % 26 + ord('a')
            encoded_block += chr(enconded_char)
        else:
            encoded_block += block[i]
    return encoded_block

def decodingBlock(block, key):
    decoded_block = ""
    for i in range(len(block)):
        if block[i].isalpha():
            decoded_char = (ord(block[i]) - ord('a') - (ord(key[i % block_size]) - ord('a')) + 26) % 26 + ord('a')
            decoded_block += chr(decoded_char)
        else:
            decoded_block += block[i]
    
    return decoded_block

def xorBlock(block1, block2):
    xorResult = ''
    for i in range(min(len(block1), len(block2))):
        xorResult += chr(ord(block1[i]) ^ ord(block2[i]))
    return xorResult

if __name__ == "__main__":
    blocks = splitBlocks(plainText)
    blocks = addPadding(blocks)
    
    cypher_blocks = []
    current_iv = init_vector
    
    print("=== ENCRIPTAÇÃO CFB ===")
    for i, block in enumerate(blocks):
        keystream = encondingBlock(current_iv, key)
        c_block = xorBlock(keystream, block)
        print(f"Bloco {i + 1}: '{block}'")
        print(f"Vetor de Inicialização: '{current_iv}'")
        print(f"Chave: '{key}'")
        print(f"Bloco Codificado: '{c_block.encode()}'")
        print()
        cypher_blocks.append(c_block)
        current_iv = c_block

    cypherText = "".join(cypher_blocks)
    print("Texto Cifrado (representação):", cypherText.encode())

    decoded_parts = []
    current_iv = init_vector
    
    print("=== DECRIPTAÇÃO CFB ===")
    for i, c_block in enumerate(cypher_blocks):
        keystream = encondingBlock(current_iv, key)
        p_block = xorBlock(keystream, c_block)
        print(f"Bloco {i + 1}: '{c_block.encode()}'")
        print(f"Vetor de Inicialização: '{current_iv}'")
        print(f"Chave: '{key}'")
        print(f"Bloco Decriptado: '{p_block}'")
        print()
        decoded_parts.append(p_block)
        current_iv = c_block

    decoded = "".join(decoded_parts)
    if len(decoded) > text_size:
        decoded = decoded[:text_size]
    print("Texto Decifrado:", decoded)
