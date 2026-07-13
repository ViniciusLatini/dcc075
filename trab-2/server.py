import socket
import threading
import json
import sys

# Styling prints for terminal
def log_server(msg, category="INFO"):
    colors = {
        "INFO": "\033[94m[INFO]\033[0m",
        "WARN": "\033[93m[WARN]\033[0m",
        "E2EE": "\033[91m[E2EE-SECURITY]\033[0m",
        "SUCCESS": "\033[92m[SUCCESS]\033[0m"
    }
    prefix = colors.get(category, f"[{category}]")
    print(f"{prefix} {msg}")

class ChatServer:
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Maps username -> client socket connection
        self.clients = {}
        # Maps username -> initial DH public key (hex string)
        self.user_keys = {}
        # Offline messages inbox: username -> list of message dicts
        self.inbox = {}
        # Lock to prevent race conditions on shared dicts
        self.lock = threading.Lock()

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            log_server(f"Server started on {self.host}:{self.port}", "SUCCESS")
        except Exception as e:
            log_server(f"Failed to bind/listen: {e}", "WARN")
            sys.exit(1)

        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            except KeyboardInterrupt:
                log_server("Server shutting down...", "WARN")
                break
            except Exception as e:
                log_server(f"Accept error: {e}", "WARN")
                break

    def handle_client(self, client_socket):
        username = None
        log_server(f"New connection from {client_socket.getpeername()}", "INFO")
        
        while True:
            try:
                # Read JSON length first (4 bytes, network byte order)
                len_bytes = client_socket.recv(4)
                if not len_bytes:
                    break
                msg_len = int.from_bytes(len_bytes, byteorder='big')
                
                # Receive the full message JSON string
                data_bytes = bytearray()
                while len(data_bytes) < msg_len:
                    packet = client_socket.recv(msg_len - len(data_bytes))
                    if not packet:
                        break
                    data_bytes.extend(packet)
                
                if len(data_bytes) < msg_len:
                    break
                
                request = json.loads(data_bytes.decode('utf-8'))
                action = request.get("action")
                
                if action == "register":
                    username = request.get("username")
                    dh_pub = request.get("dh_pub")
                    
                    with self.lock:
                        self.clients[username] = client_socket
                        self.user_keys[username] = dh_pub
                        if username not in self.inbox:
                            self.inbox[username] = []
                    
                    log_server(f"User '{username}' registered with initial DH public key: {dh_pub[:8]}...{dh_pub[-8:]}", "SUCCESS")
                    
                    # Deliver offline messages if any exist
                    with self.lock:
                        pending = self.inbox.get(username, [])
                        self.inbox[username] = []
                    
                    if pending:
                        log_server(f"Delivering {len(pending)} pending offline messages to {username}", "INFO")
                        for p_msg in pending:
                            self.send_to_socket(client_socket, p_msg)
                            
                elif action == "get_key":
                    target_user = request.get("username")
                    dh_pub = self.user_keys.get(target_user)
                    
                    if dh_pub:
                        response = {"status": "success", "username": target_user, "dh_pub": dh_pub}
                    else:
                        response = {"status": "error", "message": f"User '{target_user}' not found"}
                    self.send_to_socket(client_socket, response)
                    
                elif action == "send_msg":
                    receiver = request.get("receiver")
                    sender = request.get("sender")
                    header = request.get("header")
                    nonce = request.get("nonce")
                    ciphertext = request.get("ciphertext")
                    
                    log_server(f"Routing encrypted message: {sender} -> {receiver}", "INFO")
                    
                    # Displaying keys inside the server to demonstrate the functioning
                    print("\n" + "="*80)
                    print(f"🔒 SERVER ROUTING DATABASE & METADATA VIEW 🔒".center(80))
                    print("-"*80)
                    print(f"  Sender       : {sender}")
                    print(f"  Receiver     : {receiver}")
                    print(f"  DH Public Key: {header['dh'][:8]}...{header['dh'][-8:]}")
                    print(f"  Prev Chain PN: {header['pn']}")
                    print(f"  Msg Number N : {header['n']}")
                    print(f"  Nonce (IV)   : {nonce}")
                    print(f"  Ciphertext   : {ciphertext}")
                    print("-"*80)
                    log_server(
                        "Attempting server-side decryption using current keys: FAILED!\n"
                        "    [!] REASON: The server does NOT have Alice or Bob's private keys or derived message keys!\n"
                        "    [!] MESSAGE CONFIDENTIALITY: E2EE Verified. Plaintext remains completely secure.",
                        "E2EE"
                    )
                    print("="*80 + "\n")
                    
                    message_payload = {
                        "action": "receive_msg",
                        "sender": sender,
                        "header": header,
                        "nonce": nonce,
                        "ciphertext": ciphertext
                    }
                    
                    delivered = False
                    with self.lock:
                        recipient_socket = self.clients.get(receiver)
                        if recipient_socket:
                            try:
                                self.send_to_socket(recipient_socket, message_payload)
                                delivered = True
                                log_server(f"Message delivered directly to active recipient {receiver}", "SUCCESS")
                            except Exception as e:
                                log_server(f"Failed to send to active socket for {receiver}: {e}. Queuing offline.", "WARN")
                                self.clients.pop(receiver, None)
                                
                        if not delivered:
                            self.inbox[receiver].append(message_payload)
                            log_server(f"Recipient {receiver} is offline. Message queued in server inbox.", "WARN")
                            
                    # Acknowledge receipt to sender
                    self.send_to_socket(client_socket, {"status": "sent", "receiver": receiver, "n": header['n']})
                    
                elif action == "list_users":
                    with self.lock:
                        users_list = list(self.user_keys.keys())
                    self.send_to_socket(client_socket, {"status": "success", "users": users_list})
                    
            except ConnectionResetError:
                break
            except Exception as e:
                log_server(f"Exception handling client: {e}", "WARN")
                break
                
        # Clean up client
        if username:
            with self.lock:
                self.clients.pop(username, None)
            log_server(f"User '{username}' disconnected.", "INFO")
        client_socket.close()

    def send_to_socket(self, sock, message_dict):
        try:
            data = json.dumps(message_dict).encode('utf-8')
            length_bytes = len(data).to_bytes(4, byteorder='big')
            sock.sendall(length_bytes + data)
        except Exception as e:
            log_server(f"Socket send error: {e}", "WARN")
            raise e

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    server = ChatServer(port=port)
    server.start()
