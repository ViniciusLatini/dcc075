import re

def cifra_de_cesar(message, k):
    resultado = ""

    for i in range(len(message)):
        char = message[i]

        if char.isupper():
            resultado += chr((ord(char) + k - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) + k - 97) % 26 + 97)
        else:
            resultado += char

    return resultado
    

with open('./texto.txt', 'r', encoding='utf-8') as importedText:
    text = importedText.read()
message = re.sub(r'[^a-zA-Z0-9\s]', '', text).lower().replace(' ','').replace('\n','')
key = 3
encrypted_message = cifra_de_cesar(message, key)

with open('./texto_cifrado.txt', 'w', encoding='utf-8') as exportedText:
    exportedText.write(encrypted_message)