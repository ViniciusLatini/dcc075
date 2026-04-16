import re
import random

key = '149ac'
block_size = len(key)

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
            for _ in range(block_size - len(blocks[i])):
                randon_char = random.choice('abcdefghijklmnopqrstuvwxyz')
                blocks[i] += randon_char
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

if __name__ == "__main__":
    print("plainText:", plainText)
    blocks = splitBlocks(plainText)
    print("blocks:", blocks)
    blocks = addPadding(blocks)
    print("blocks with padding:", blocks)
    cipher = ""
    for block in blocks:
        cipher += encondingBlock(block, key)
    print("cipher:", cipher)
    
    blocksEncoded = splitBlocks(cipher)
    print("blocks encoded:", blocksEncoded)
    decoded = ""
    for block in blocksEncoded:
        decoded += decodingBlock(block, key)
    if len(decoded) > text_size:
        decoded = decoded[:text_size]
    print("decoded:", decoded)

    