import re
# import matplotlib.pyplot as plt

freq_pt = {
    "a": 14.63,
    "b": 1.04,
    "c": 3.88,
    "d": 4.99,
    "e": 12.57,
    "f": 1.02,
    "g": 1.3,
    "h": 1.28,
    "i": 6.18,
    "j": 0.4,
    "k": 0.02,
    "l": 2.78,
    "m": 4.74,
    "n": 5.05,
    "o": 10.73,
    "p": 2.52,
    "q": 1.2,
    "r": 6.53,
    "s": 7.81,
    "t": 4.34,
    "u": 4.63,
    "v": 1.67,
    "w": 0.01,
    "x": 0.21,
    "y": 0.01,
    "z": 0.47
}

with open('./texto_cifrado.txt', 'r', encoding='utf-8') as importedText:
    text = importedText.read()

cleanText = re.sub(r'[^a-zA-Z0-9\s]', '', text).lower()

frequences = {}
for char in cleanText:
    if char in frequences:
        frequences[char] += 1
    else:
        frequences[char] = 1

print(frequences)

percentages = {}
totalChars = len(cleanText)
for char, count in frequences.items():
    percentages[char] = (count / totalChars) * 100
    

def build_mapping(percentages, freq_pt):
    # Ordena ambos por frequência (decrescente)
    sorted_txt = sorted(percentages.items(), key=lambda x: x[1], reverse=True)
    sorted_pt  = sorted(freq_pt.items(), key=lambda x: x[1], reverse=True)

    mapping = {}

    # Associa pela posição
    for (c_txt, _), (c_pt, _) in zip(sorted_txt, sorted_pt):
        mapping[c_txt] = c_pt

    return mapping

def apply_mapping(text, mapping):
    result = ""

    for c in text:
        if c.lower() in mapping:
            new_c = mapping[c.lower()]
            result += new_c.upper() if c.isupper() else new_c
        else:
            result += c

    return result


with open('./texto_decifrado.txt', 'w', encoding='utf-8') as exportedText:
    exportedText.write(apply_mapping(text,build_mapping(percentages, freq_pt)))


print(percentages)



# plt.bar(percentages.keys(), percentages.values())
# plt.xlabel('Characters')
# plt.ylabel('Percentage')
# plt.title('Character Frequency in Text')
# plt.show()