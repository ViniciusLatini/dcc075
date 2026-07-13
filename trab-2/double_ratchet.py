import os
import hmac
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Helper function to truncate keys for visual output
def format_key_hex(key_bytes):
    if not key_bytes:
        return "None"
    h = key_bytes.hex()
    return f"{h[:8]}...{h[-8:]}"

class DoubleRatchet:
    def __init__(self, shared_key, bob_dh_pub=None, bob_dh_keypair=None):
        """
        Initializes the Double Ratchet state.
        
        :param shared_key: The 32-byte pre-shared key (e.g. from an out-of-band agreement or X3DH)
        :param bob_dh_pub: Bob's initial DH public key. If provided, self is Alice (the sender/initiator).
        :param bob_dh_keypair: Bob's initial DH private key. If provided (or if bob_dh_pub is None), self is Bob.
        """
        if len(shared_key) != 32:
            raise ValueError("Shared key must be exactly 32 bytes.")
            
        self.RK = shared_key
        self.MKSKIPPED = {}
        
        # State variables
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        
        if bob_dh_pub is not None:
            # Alice (Initiator)
            # 1. Generate Alice's initial DH keypair
            self.DHs = x25519.X25519PrivateKey.generate()
            self.DHr = bob_dh_pub
            
            # 2. Perform initial DH exchange and RK/CK ratchet
            dh_out = self.DHs.exchange(self.DHr)
            self.RK, self.CKs = self.kdf_rk(self.RK, dh_out)
            self.CKr = None
        else:
            # Bob (Receiver)
            self.DHs = bob_dh_keypair or x25519.X25519PrivateKey.generate()
            self.DHr = None
            self.CKs = None
            self.CKr = None

    def kdf_rk(self, rk, dh_out):
        """
        Root Key KDF: derives a new root key and chain key from root key and DH shared secret.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b'DoubleRatchetRootKDF',
            backend=None
        )
        okm = hkdf.derive(dh_out)
        return okm[:32], okm[32:]

    def kdf_ck(self, ck):
        """
        Chain Key KDF: derives a new chain key and message key.
        """
        # Message key (MK) = HMAC-SHA256(CK, b'\x01')
        mk = hmac.new(ck, b'\x01', hashlib.sha256).digest()
        # Next chain key = HMAC-SHA256(CK, b'\x02')
        next_ck = hmac.new(ck, b'\x02', hashlib.sha256).digest()
        return next_ck, mk

    def encrypt(self, plaintext_bytes, ad_bytes=b""):
        """
        Encrypts a message using the current sending chain key.
        """
        if self.CKs is None:
            raise ValueError("Sending chain key is not initialized.")
        
        # 1. Rotate symmetric ratchet
        self.CKs, mk = self.kdf_ck(self.CKs)
        
        # 2. Build header
        dh_pub_bytes = self.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        header = {
            "dh": dh_pub_bytes.hex(),
            "pn": self.PN,
            "n": self.Ns
        }
        self.Ns += 1
        
        # 3. Construct AEAD associated data (AD + header JSON bytes)
        header_bytes = json.dumps(header, sort_keys=True).encode('utf-8')
        combined_ad = ad_bytes + header_bytes
        
        # 4. Authenticated Encryption with AES-GCM
        aesgcm = AESGCM(mk)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, combined_ad)
        
        return header, nonce, ciphertext, mk

    def decrypt(self, header, nonce, ciphertext, ad_bytes=b""):
        """
        Decrypts a message, updating the receiving and sending chain keys if necessary.
        """
        # Deserialize public key in header
        remote_dh_pub_bytes = bytes.fromhex(header["dh"])
        remote_dh_pub = x25519.X25519PublicKey.from_public_bytes(remote_dh_pub_bytes)
        
        # 1. Try decrypting using previously skipped message keys
        plaintext, mk = self.try_skipped_msg_keys(header, nonce, ciphertext, ad_bytes)
        if plaintext is not None:
            return plaintext, mk
        
        # 2. Check if a new DH key was received from the sender
        current_dhr_bytes = (self.DHr.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ) if self.DHr else None)
        
        if remote_dh_pub_bytes != current_dhr_bytes:
            # Skip keys from the previous sending chain (using PN from header)
            self.skip_msg_keys(header["pn"])
            
            self.PN = self.Ns
            self.Ns = 0
            self.DHr = remote_dh_pub
            
            # DH Ratchet step 1 (Receive): Derive new root key and receiving chain key
            dh_out = self.DHs.exchange(self.DHr)
            self.RK, self.CKr = self.kdf_rk(self.RK, dh_out)
            
            # DH Ratchet step 2 (Send): Generate new DH keypair and derive sending chain key
            self.DHs = x25519.X25519PrivateKey.generate()
            dh_out_new = self.DHs.exchange(self.DHr)
            self.RK, self.CKs = self.kdf_rk(self.RK, dh_out_new)
            
        # 3. Skip message keys in current receiving chain up to current message number N
        self.skip_msg_keys(header["n"])
        
        # 4. Symmetric ratchet step on receiving chain
        self.CKr, mk = self.kdf_ck(self.CKr)
        self.Nr += 1
        
        # 5. Decrypt using AES-GCM
        header_bytes = json.dumps(header, sort_keys=True).encode('utf-8')
        combined_ad = ad_bytes + header_bytes
        
        aesgcm = AESGCM(mk)
        plaintext = aesgcm.decrypt(nonce, ciphertext, combined_ad)
        
        return plaintext, mk

    def skip_msg_keys(self, until):
        """
        Skips keys in the current receiving chain, storing skipped message keys for future use.
        """
        if self.CKr is not None:
            # Security safeguard to prevent out-of-memory attack / infinite loops
            if self.Nr + 2000 < until:
                raise ValueError("Too many skipped messages.")
            while self.Nr < until:
                self.CKr, mk = self.kdf_ck(self.CKr)
                dh_r_bytes = self.DHr.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ).hex()
                self.MKSKIPPED[(dh_r_bytes, self.Nr)] = mk
                self.Nr += 1

    def try_skipped_msg_keys(self, header, nonce, ciphertext, ad_bytes):
        """
        Attempts to decrypt a message using keys that were previously skipped.
        """
        dh_hex = header["dh"]
        n = header["n"]
        key = (dh_hex, n)
        if key in self.MKSKIPPED:
            mk = self.MKSKIPPED.pop(key)
            header_bytes = json.dumps(header, sort_keys=True).encode('utf-8')
            combined_ad = ad_bytes + header_bytes
            aesgcm = AESGCM(mk)
            plaintext = aesgcm.decrypt(nonce, ciphertext, combined_ad)
            return plaintext, mk
        return None, None

    # Helper getters for logging/visualization
    def get_dh_pub_self_bytes(self):
        return self.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_dh_pub_remote_bytes(self):
        if not self.DHr:
            return None
        return self.DHr.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_state_summary(self):
        """
        Returns a dictionary containing a snapshot of the current keys in hex.
        """
        return {
            "RK": format_key_hex(self.RK),
            "CKs": format_key_hex(self.CKs),
            "CKr": format_key_hex(self.CKr),
            "DHs": format_key_hex(self.get_dh_pub_self_bytes()),
            "DHr": format_key_hex(self.get_dh_pub_remote_bytes()),
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "SkippedKeysCount": len(self.MKSKIPPED)
        }
