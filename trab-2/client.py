import socket
import threading
import json
import sys
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from double_ratchet import DoubleRatchet, format_key_hex

# Pre-shared 32-byte key for bootstrapping Double Ratchet
SHARED_KEY = b"DoubleRatchetPreSharedKey32Bytes"

def print_state_changes(title, state_dict, msg_key_hex=None, plaintext=None, header=None):
    print("\n" + "\033[95m" + "="*75 + "\033[0m")
    print(f"\033[96m\033[1m{title.upper()}\033[0m")
    print("\033[95m" + "-"*75 + "\033[0m")
    print(f" 👤  Local Public DH  : \033[97m{state_dict['DHs']}\033[0m")
    print(f" 👥  Remote Public DH : \033[97m{state_dict['DHr']}\033[0m")
    print(f" 🔑  Root Key (RK)    : \033[92m{state_dict['RK']}\033[0m")
    print(f" 📤  Sending Chain CKs : \033[94m{state_dict['CKs']}\033[0m")
    print(f" 📥  Receiving Chain CKr: \033[36m{state_dict['CKr']}\033[0m")
    print(f" 🔢  Counters         : Sent (Ns) = {state_dict['Ns']} | Recv (Nr) = {state_dict['Nr']} | Prev (PN) = {state_dict['PN']}")
    print(f" 📦  Skipped Keys     : {state_dict['SkippedKeysCount']}")
    if header:
        print(f" 📨  Header Metadata  : DH={header.get('dh')[:8]}...{header.get('dh')[-8:]} | PN={header.get('pn')} | N={header.get('n')}")
    if msg_key_hex:
        print(f" 🔐  Derived Msg Key  : \033[93m{msg_key_hex[:8]}...{msg_key_hex[-8:]}\033[0m")
    if plaintext is not None:
        print(f" 💬  Plaintext Message: \033[92m\033[1m{plaintext}\033[0m")
    print("\033[95m" + "="*75 + "\033[0m\n")

class ChatClient:
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.username = None
        self.sock = None
        self.sessions = {} # username -> DoubleRatchet instance
        
        # Client generates its initial DH key pair on instantiation
        self.dh_keypair = x25519.X25519PrivateKey.generate()
        
        # Async response fields
        self.response_events = {}
        self.responses = {}
        
        self.active_chat = None
        self.running = True

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            # Start background message listener
            threading.Thread(target=self.receive_loop, daemon=True).start()
            return True
        except Exception as e:
            print(f"\033[91mFailed to connect to server at {self.host}:{self.port} - {e}\033[0m")
            return False

    def send_payload(self, message_dict):
        try:
            data = json.dumps(message_dict).encode('utf-8')
            length_bytes = len(data).to_bytes(4, byteorder='big')
            self.sock.sendall(length_bytes + data)
        except Exception as e:
            print(f"\033[91mSend error: {e}\033[0m")

    def register(self, username):
        self.username = username
        pub_bytes = self.dh_keypair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        payload = {
            "action": "register",
            "username": self.username,
            "dh_pub": pub_bytes.hex()
        }
        self.send_payload(payload)
        print(f"\033[92mRegistered on server as '{self.username}'\033[0m")

    def get_public_key_from_server(self, username):
        event = threading.Event()
        self.response_events[username] = event
        
        payload = {"action": "get_key", "username": username}
        self.send_payload(payload)
        
        # Wait up to 3 seconds for response
        success = event.wait(3.0)
        self.response_events.pop(username, None)
        
        if not success:
            return None
        
        resp = self.responses.pop(username, None)
        if resp and resp.get("status") == "success":
            return resp.get("dh_pub")
        return None

    def request_user_list(self):
        self.send_payload({"action": "list_users"})

    def handle_server_message(self, msg):
        status = msg.get("status")
        action = msg.get("action")
        
        if status == "success" and "dh_pub" in msg:
            target = msg.get("username")
            self.responses[target] = msg
            if target in self.response_events:
                self.response_events[target].set()
                
        elif status == "success" and "users" in msg:
            print(f"\n\033[96mOnline Users:\033[0m {', '.join(msg['users'])}")
            
        elif action == "receive_msg":
            sender = msg.get("sender")
            header = msg.get("header")
            nonce = bytes.fromhex(msg.get("nonce"))
            ciphertext = bytes.fromhex(msg.get("ciphertext"))
            
            # Setup session if not already existing (we are Bob in this session)
            if sender not in self.sessions:
                self.sessions[sender] = DoubleRatchet(
                    SHARED_KEY,
                    bob_dh_keypair=self.dh_keypair
                )
                
            session = self.sessions[sender]
            try:
                plaintext_bytes, mk = session.decrypt(header, nonce, ciphertext)
                plaintext = plaintext_bytes.decode('utf-8')
                
                print_state_changes(
                    title=f"📥 Message Received (From: {sender})",
                    state_dict=session.get_state_summary(),
                    msg_key_hex=mk.hex(),
                    plaintext=plaintext,
                    header=header
                )
            except Exception as e:
                print(f"\n\033[91m[Decryption error for message from {sender}: {e}]\033[0m")

    def receive_loop(self):
        while self.running:
            try:
                len_bytes = self.sock.recv(4)
                if not len_bytes:
                    break
                msg_len = int.from_bytes(len_bytes, byteorder='big')
                
                data_bytes = bytearray()
                while len(data_bytes) < msg_len:
                    packet = self.sock.recv(msg_len - len(data_bytes))
                    if not packet:
                        break
                    data_bytes.extend(packet)
                
                if len(data_bytes) < msg_len:
                    break
                
                msg = json.loads(data_bytes.decode('utf-8'))
                self.handle_server_message(msg)
            except ConnectionResetError:
                break
            except Exception as e:
                if self.running:
                    print(f"\n[Receive error: {e}]")
                break
        self.running = False
        print("\n\033[91mDisconnected from server.\033[0m")

    def start_chat(self, target_user):
        if target_user == self.username:
            print("\033[93mYou cannot chat with yourself.\033[0m")
            return
            
        if target_user in self.sessions:
            self.active_chat = target_user
            print(f"\033[92mActive E2EE Session with '{target_user}' resumed! You can continue sending messages.\033[0m")
            return
            
        print(f"Fetching key for {target_user}...")
        remote_dh_pub_hex = self.get_public_key_from_server(target_user)
        
        if not remote_dh_pub_hex:
            print(f"\033[91mCould not retrieve public key for '{target_user}'. Check if they are registered.\033[0m")
            return
            
        # Parse public key
        remote_pub_bytes = bytes.fromhex(remote_dh_pub_hex)
        remote_dh_pub = x25519.X25519PublicKey.from_public_bytes(remote_pub_bytes)
        
        # Initialize Double Ratchet as Alice (sender)
        self.sessions[target_user] = DoubleRatchet(
            SHARED_KEY,
            bob_dh_pub=remote_dh_pub
        )
        self.active_chat = target_user
        print(f"\033[92mE2EE Session established with {target_user}! You can now send messages.\033[0m")

    def send_chat_message(self, text):
        if not self.active_chat or self.active_chat not in self.sessions:
            print("\033[91mNo active chat session.\033[0m")
            return
            
        session = self.sessions[self.active_chat]
        plaintext_bytes = text.encode('utf-8')
        
        try:
            header, nonce, ciphertext, mk = session.encrypt(plaintext_bytes)
            
            # Log state before sending
            print_state_changes(
                title=f"📤 Message Sent (To: {self.active_chat})",
                state_dict=session.get_state_summary(),
                msg_key_hex=mk.hex(),
                plaintext=text,
                header=header
            )
            
            # Send payload
            payload = {
                "action": "send_msg",
                "sender": self.username,
                "receiver": self.active_chat,
                "header": header,
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex()
            }
            self.send_payload(payload)
        except Exception as e:
            print(f"\033[91mEncryption failed: {e}\033[0m")

    def run_cli(self):
        print("\033[94m" + "="*50)
        print("  SIGNAL SIMPLIFIED (Double Ratchet E2EE Chat)".center(50))
        print("="*50 + "\033[0m")
        
        username = input("Enter your username: ").strip()
        while not username:
            username = input("Username cannot be empty. Enter username: ").strip()
            
        if not self.connect():
            return
            
        self.register(username)
        
        print("\nCommands:")
        print("  /list           - List online users")
        print("  /chat <user>    - Start an E2EE session with <user>")
        print("  /exit           - Exit current chat / Quit application")
        print("  Type any message to send when inside a chat session\n")
        
        while self.running:
            try:
                prefix = f"({self.username} -> {self.active_chat}) " if self.active_chat else f"({self.username}) "
                cmd = input(prefix).strip()
                if not cmd:
                    continue
                    
                if cmd.startswith("/"):
                    parts = cmd.split(" ", 1)
                    action = parts[0].lower()
                    
                    if action == "/exit":
                        if self.active_chat:
                            print(f"Closed chat with {self.active_chat}.")
                            self.active_chat = None
                        else:
                            self.running = False
                            break
                    elif action == "/list":
                        self.request_user_list()
                    elif action == "/chat":
                        if len(parts) < 2:
                            print("Usage: /chat <username>")
                        else:
                            self.start_chat(parts[1].strip())
                    else:
                        print("Unknown command.")
                else:
                    if self.active_chat:
                        self.send_chat_message(cmd)
                    else:
                        print("No active chat. Use /chat <username> to start one.")
            except KeyboardInterrupt:
                print("\nExiting...")
                self.running = False
                break
        
        if self.sock:
            self.sock.close()

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8000
    if len(sys.argv) > 1:
        # Check if argument contains host and/or port
        arg = sys.argv[1]
        if ":" in arg:
            parts = arg.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        else:
            try:
                port = int(arg)
            except ValueError:
                host = arg
                
    client = ChatClient(host=host, port=port)
    client.run_cli()
