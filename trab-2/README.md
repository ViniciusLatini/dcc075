# Chat E2EE com Algoritmo Double Ratchet em Python

Este projeto implementa um chat básico em Python utilizando Sockets TCP para demonstrar o funcionamento do **Algoritmo Double Ratchet** (usado no Signal e WhatsApp) para criptografia de ponta a ponta (E2EE).

## 🚀 Como Rodar o Projeto

### Pré-requisitos

O único requisito externo é a biblioteca `cryptography` do Python para suportar as operações de curvas elípticas (X25519) e AES-GCM.

Para instalá-la, execute:
```bash
pip install cryptography
```

---

### Opção 1: Simulação Automatizada (Recomendado)

O script `demo.py` inicia automaticamente o servidor e os clientes (Alice e Bob) em segundo plano, executando uma conversa simulada passo a passo. Ele também demonstra o comportamento diante de mensagens que chegam fora de ordem (Skipped Keys).

Para rodar:
```bash
python3 demo.py
```

*Pressione `Ctrl+C` a qualquer momento para encerrar a simulação e o servidor.*

---

### Opção 2: Chat Interativo em Múltiplos Terminais

Para testar a rede real de sockets interativamente, abra **três terminais separados** e execute os seguintes comandos:

#### 1. Iniciar o Servidor
No **Terminal 1**:
```bash
python3 server.py
```

#### 2. Iniciar o Cliente do Bob
No **Terminal 2**:
```bash
python3 client.py Bob
```

#### 3. Iniciar o Cliente da Alice
No **Terminal 3**:
```bash
python3 client.py Alice
```

#### 4. Conversar de Forma Segura
No console da Alice (Terminal 3):
1.  Digite `/list` para listar os usuários online.
2.  Digite `/chat Bob` para iniciar a conversa segura com o Bob.
3.  Digite mensagens normais (ex: `Olá Bob!`). Elas aparecerão cifradas no servidor (Terminal 1) e decifradas no Bob (Terminal 2), com todas as rotações de chaves explicadas em tempo real!
4.  No console do Bob (Terminal 2), digite `/chat Alice` para poder responder.

Para sair de uma conversa ou do console a qualquer momento, digite `/exit`.

---

## 📂 Estrutura de Arquivos

*   `double_ratchet.py`: Implementação da máquina de estados do Double Ratchet (KDF de chaves raiz, KDF de chaves de cadeia, criptografia AES-GCM e tratamento de mensagens puladas).
*   `server.py`: Servidor central de sockets que apenas roteia os dados criptografados sem acesso às chaves secretas.
*   `client.py`: Cliente interativo CLI com visualização colorida e detalhada das chaves criptográficas.
*   `demo.py`: Script de automação e demonstração das capacidades do protocolo.
*   `apresentacao.md`: Documentação conceitual passo a passo e roteiro didático de apresentação do trabalho.
