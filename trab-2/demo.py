import threading
import time
import sys
from server import ChatServer, log_server
from client import ChatClient
from double_ratchet import DoubleRatchet, format_key_hex
from cryptography.hazmat.primitives.asymmetric import x25519

# Configuration
PORT = 8001
HOST = "127.0.0.1"
SHARED_KEY = b"DoubleRatchetPreSharedKey32Bytes"

def print_separator(title):
    print("\n" + "\033[93m" + "*"*80)
    print(f" {title} ".center(80, "*"))
    print("*"*80 + "\033[0m\n")

def run_automated_demo():
    print_separator("INICIANDO SERVIDOR E CLIENTES")
    
    # 1. Start Server on port 8001
    server = ChatServer(host=HOST, port=PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5) # Wait for server to bind
    
    # 2. Start Bob's Client
    bob = ChatClient(host=HOST, port=PORT)
    if not bob.connect():
        print("Erro: Não foi possível conectar o Bob.")
        sys.exit(1)
    bob.register("Bob")
    time.sleep(0.5)
    
    # 3. Start Alice's Client
    alice = ChatClient(host=HOST, port=PORT)
    if not alice.connect():
        print("Erro: Não foi possível conectar a Alice.")
        sys.exit(1)
    alice.register("Alice")
    time.sleep(0.8)
    
    # 4. Alice starts chat session with Bob
    print_separator("ESTABELECENDO SESSÃO INICIAL E2EE (ALICE -> BOB)")
    alice.start_chat("Bob")
    time.sleep(0.8)
    
    # 5. Alice sends Message 1
    print_separator("ALICE ENVIA MENSAGEM 1 (Primeira chave gerada)")
    alice.send_chat_message("Olá Bob! Tudo bem?")
    time.sleep(1.2) # Allow threads to log message relay and receipt
    
    # 6. Alice sends Message 2 (Same DH chain, next Symmetric step)
    print_separator("ALICE ENVIA MENSAGEM 2 (Symmetric Ratchet Avança, DH Estático)")
    alice.send_chat_message("Você viu a nova especificação do Signal?")
    time.sleep(1.2)
    
    # 7. Alice sends Message 3 (Symmetric Ratchet Avança novamente, DH Estático)
    print_separator("ALICE ENVIA MENSAGEM 3 (Symmetric Ratchet Avança novamente)")
    alice.send_chat_message("A criptografia ponta-a-ponta é sensacional!")
    time.sleep(1.2)
    
    # 8. Bob replies to Alice (Triggers DH Ratchet on Bob, deriving new keys)
    print_separator("BOB RESPONDE A ALICE (Gatilho do DH Ratchet no Bob - Chave do DH muda)")
    bob.active_chat = "Alice"
    # Set Bob's session for Alice (it was automatically created during message receipt)
    bob.send_chat_message("Oi Alice! Sim, acabei de ver! O Double Ratchet é fantástico.")
    time.sleep(1.2)
    
    # 9. Bob sends another message (Symmetric Ratchet on Bob's new chain)
    print_separator("BOB ENVIA MENSAGEM 2 (Symmetric Ratchet no Bob, DH Estático)")
    bob.send_chat_message("Ele rotaciona as chaves de criptografia a cada mensagem!")
    time.sleep(1.2)
    
    # 10. Alice replies back to Bob (Triggers DH Ratchet on Alice)
    print_separator("ALICE RESPONDE A BOB (Gatilho do DH Ratchet na Alice - Nova rotação)")
    alice.send_chat_message("Exatamente! Isso garante Perfect Forward Secrecy.")
    time.sleep(1.2)

    # 11. Offline/Out-of-order Simulation
    print_separator("SIMULAÇÃO DE MENSAGENS APATRIADAS / FORA DE ORDEM (SKIPPED KEYS)")
    
    print("Para esta demonstração de pulo de chaves, usaremos instâncias locais isoladas")
    print("para simular perdas de pacotes na rede sem interferência de concorrência de sockets.\n")
    
    # Initializing fresh states
    alice_dh = x25519.X25519PrivateKey.generate()
    bob_dh = x25519.X25519PrivateKey.generate()
    
    alice_state = DoubleRatchet(SHARED_KEY, bob_dh_pub=bob_dh.public_key())
    bob_state = DoubleRatchet(SHARED_KEY, bob_dh_keypair=bob_dh)
    
    print("\033[94mAlice encripta 3 mensagens consecutivas para o Bob:\033[0m")
    h1, n1, c1, mk1 = alice_state.encrypt(b"Mensagem perdida #1 (N=0)")
    h2, n2, c2, mk2 = alice_state.encrypt(b"Mensagem perdida #2 (N=1)")
    h3, n3, c3, mk3 = alice_state.encrypt(b"Mensagem entregue primeiro #3 (N=2)")
    
    print(f"  [+] Msg 1 (N=0) - Msg Key MK: {mk1.hex()[:8]}...")
    print(f"  [+] Msg 2 (N=1) - Msg Key MK: {mk2.hex()[:8]}...")
    print(f"  [+] Msg 3 (N=2) - Msg Key MK: {mk3.hex()[:8]}...")
    
    print("\n\033[93m[Rede] Simulando entrega fora de ordem: Bob recebe Msg 3 (N=2) antes de Msg 1 e 2.\033[0m")
    print("Bob processa a Msg 3 (N=2):")
    
    # Decrypt Msg 3 (this triggers skipping key N=0 and N=1)
    p3, dec_mk3 = bob_state.decrypt(h3, n3, c3)
    
    print(f"  [✓] Bob decriptou Msg 3 com sucesso: '{p3.decode('utf-8')}'")
    print(f"  [!] Chaves puladas em Bob (MKSKIPPED): {len(bob_state.MKSKIPPED)}")
    print(f"      Chaves armazenadas: {list(bob_state.MKSKIPPED.keys())}")
    
    print("\n\033[93m[Rede] Agora as mensagens atrasadas Msg 1 (N=0) e Msg 2 (N=1) chegam ao Bob.\033[0m")
    
    # Bob receives delayed Msg 1
    p1, dec_mk1 = bob_state.decrypt(h1, n1, c1)
    print(f"  [✓] Bob decriptou Msg 1 (atrasada) com sucesso: '{p1.decode('utf-8')}'")
    print(f"  [✓] Chave correspondente removida da memória: MK={dec_mk1.hex()[:8]}...")
    print(f"  [!] Chaves puladas restantes em Bob (MKSKIPPED): {len(bob_state.MKSKIPPED)}")
    
    # Bob receives delayed Msg 2
    p2, dec_mk2 = bob_state.decrypt(h2, n2, c2)
    print(f"  [✓] Bob decriptou Msg 2 (atrasada) com sucesso: '{p2.decode('utf-8')}'")
    print(f"  [✓] Chave correspondente removida da memória: MK={dec_mk2.hex()[:8]}...")
    print(f"  [!] Chaves puladas restantes em Bob (MKSKIPPED): {len(bob_state.MKSKIPPED)}")
    
    print_separator("FIM DA DEMONSTRAÇÃO")
    print("A demonstração foi concluída com sucesso!")
    print("Isso prova o funcionamento de:")
    print("  1. Criptografia ponta-a-ponta (E2EE) transparente via Sockets.")
    print("  2. Perfect Forward Secrecy: Chaves de mensagem alteradas a cada envio.")
    print("  3. Detecção e salvamento de chaves atrasadas (Skipped Keys) para suportar rede instável.")
    print("  4. Impossibilidade de o servidor ler as mensagens, logando apenas cifra.")
    print("\nPressione Ctrl+C para encerrar o servidor.")
    
    # Keep main thread alive to see results
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nFinalizando...")
        alice.running = False
        bob.running = False
        if alice.sock:
            alice.sock.close()
        if bob.sock:
            bob.sock.close()

if __name__ == "__main__":
    run_automated_demo()
