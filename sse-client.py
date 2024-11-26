import socket
import os
import json
import secrets
import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

AES_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_KEY_SIZE = 32
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit for testing
DEFAULT_EXPIRATION = 60  # 60 minutes

class KeyStore:
    def __init__(self, username, password):
        # Derive key from username and password for encrypting the keystore
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=username.encode(),
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(self.master_key)
        self.keys = {}  # file_id -> (file_key, auth_key)
        self.store_path = f"{username}_keystore.enc"
        self.load_keys()

    def add_keys(self, file_id, file_key, auth_key):
        # Store keys as base64-encoded strings
        self.keys[file_id] = {
            'file_key': base64.b64encode(file_key).decode('utf-8'),
            'auth_key': base64.b64encode(auth_key).decode('utf-8')
        }
        self.save_keys()

    def get_keys(self, file_id):
        key_data = self.keys.get(file_id)
        if not key_data:
            return None
        # Decode base64 strings back to bytes
        return (
            base64.b64decode(key_data['file_key']),
            base64.b64decode(key_data['auth_key'])
        )

    def save_keys(self):
        # Convert to JSON-serializable format and encrypt
        encrypted = self.fernet.encrypt(json.dumps(self.keys).encode())
        with open(self.store_path, 'wb') as f:
            f.write(encrypted)

    def load_keys(self):
        try:
            with open(self.store_path, 'rb') as f:
                encrypted = f.read()
                decrypted = self.fernet.decrypt(encrypted)
                self.keys = json.loads(decrypted.decode())
        except FileNotFoundError:
            self.keys = {}

class Client:
    def __init__(self, host: str = 'localhost', port: int = 5002):
        self.host = host
        self.port = port
        self.socket = None  # Don't create socket in __init__
        self.aes_key = None
        self.hmac_key = None
        self.is_logged_in = False  # Todo: implement sessions
        self.keystore = None

    def connect(self):
        try:
            # Create new socket for each connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Reset keys for new connection
            self.aes_key = None
            self.hmac_key = None
            self.is_logged_in = False
            
            # Receive server's RSA public key
            rsa_public_key_bytes = self.socket.recv(2480)
            try:
                rsa_public_key = serialization.load_pem_public_key(rsa_public_key_bytes)
                print("RSA public key loaded successfully")
            except Exception as e:
                print(f"Failed to load RSA public key: {e}") #debugging incase of failed key exchange 
                return False

            # Generate AES and HMAC keys
            self.aes_key = secrets.token_bytes(AES_KEY_SIZE)
            self.hmac_key = secrets.token_bytes(HMAC_KEY_SIZE)
            combined_key = self.aes_key + self.hmac_key
            
            # Encrypt combined AES+HMAC key with server's public RSA key
            encrypted_key = rsa_public_key.encrypt(
                combined_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), #using OAEP padding with SHA256 hashing
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.socket.send(encrypted_key) #send encrypted combined key to server
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def send_secure_request(self, request: dict) -> dict:
        try:
            # Convert request to JSON and encrypt with AES-CTR
            plaintext = json.dumps(request).encode('utf-8')

            # Generate random nonce for AES-CTR mode
            nonce = secrets.token_bytes(NONCE_SIZE)

            
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Generate HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            
            hmac_value = h.finalize()

            # Send message with length prefix
            encrypted_request = nonce + ciphertext + hmac_value
            message_length = len(encrypted_request).to_bytes(4, 'big')
            self.socket.sendall(message_length + encrypted_request)

            # Receive and decrypt response
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.recv_full(response_length)
            nonce = encrypted_response[:NONCE_SIZE]
            ciphertext = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify and decrypt response
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            h.verify(received_hmac)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            print(f"Error sending secure request: {e}")
            return {"status": "failed", "message": str(e)}

    def register(self, username, password):
        return self.send_secure_request({"command": "register", "username": username, "password": password})

    def login(self, username, password):
        # Reconnect for new user session
        self.close()
        if not self.connect():
            return {"status": "failed", "message": "Connection failed"}
            
        response = self.send_secure_request({"command": "login", "username": username, "password": password})
        if response.get("status") == "success":
            self.is_logged_in = True
            self.keystore = KeyStore(username, password)
        return response

    def upload_file(self, file_path, max_downloads=float('inf'), expiration_minutes=None):
        if not self.is_logged_in:
            print("Please log in first.")
            return None
            
        if not os.path.exists(file_path):
            print("File not found")
            return None

        try:
            # Read file and generate file-specific keys
            with open(file_path, 'rb') as f:
                file_data = f.read()
                if len(file_data) > MAX_FILE_SIZE:
                    print("Error: File too large to upload.")
                    return

            # Generate file-specific encryption and authentication keys
            file_key = secrets.token_bytes(AES_KEY_SIZE)
            auth_key = secrets.token_bytes(HMAC_KEY_SIZE)
            file_nonce = secrets.token_bytes(NONCE_SIZE)

            # Client-side encryption
            cipher = Cipher(algorithms.AES(file_key), modes.CTR(file_nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

            # Structure: file_nonce + encrypted_data + file_hmac + transport_hmac
            # Generate file-level HMAC first
            file_hmac = hmac.HMAC(auth_key, hashes.SHA256(), backend=default_backend())
            file_hmac.update(file_nonce + encrypted_file_data)
            file_auth_tag = file_hmac.finalize()

            # Combine file components
            file_blob = file_nonce + encrypted_file_data + file_auth_tag

            # Generate transport-level HMAC
            transport_hmac = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            transport_hmac.update(file_blob)
            transport_auth_tag = transport_hmac.finalize()

            # Send upload command and get response
            command = {
                "command": "upload",
                "max_downloads": max_downloads,
                "expiration": expiration_minutes if expiration_minutes is not None else DEFAULT_EXPIRATION
            }
            upload_response = self.send_secure_request(command)
            if upload_response.get("status") != "ready":
                print(f"Error: Server not ready. {upload_response.get('message', '')}")
                return None
                
            ack_response = self.receive_response()
            if ack_response.get("status") != "ready":
                print(f"Error: Server not ready. {ack_response.get('message', '')}")
                return None

            # Send complete blob with both HMACs
            complete_blob = file_blob + transport_auth_tag
            file_data_length = len(complete_blob).to_bytes(4, 'big')
            self.socket.sendall(file_data_length + complete_blob)
                
            # Get final upload response
            final_response = self.receive_response()
            if final_response.get("status") == "success":
                file_id = final_response.get('file_id')
                self.keystore.add_keys(file_id, file_key, auth_key)
                print(f"File uploaded successfully. ID: {final_response.get('file_id')}")
                print(f"File will expire in {final_response.get('expiration_minutes')} minutes")
                return final_response.get('file_id')
            else:
                print(f"Upload failed: {final_response.get('message')}")
                return None

        except Exception as e:
            print(f"Error during file upload: {e}")
            return None

    def download_file(self, file_id, save_path):
        if not self.is_logged_in:
            print("Please log in first.")
            return False

        # Get file keys from keystore
        keys = self.keystore.get_keys(file_id)
        if not keys:
            print("No encryption keys found for this file.")
            return False

        file_key, auth_key = keys

        try:
            print(f"[CLIENT] Attempting to download file: {file_id}")
            
            # Send download request
            command = {"command": "download", "file_id": file_id}
            response = self.send_secure_request(command)
            
            if response.get("status") != "ready":
                print(f"[CLIENT] Server error: {response.get('message')}")
                return

            # Receive file data
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.recv_full(response_length)
            
            # Verify transport-level HMAC first
            transport_hmac = encrypted_response[-32:]
            encrypted_blob = encrypted_response[:-32]
            
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_blob)
            try:
                h.verify(transport_hmac)
                print("[CLIENT] Transport integrity verified")
            except InvalidSignature:
                print("[CLIENT] Transport integrity check failed")
                return False

            # Now handle the file-level data
            if len(encrypted_blob) < NONCE_SIZE + 32:
                print("[CLIENT] File data too small")
                return False

            file_nonce = encrypted_blob[:NONCE_SIZE]
            encrypted_content = encrypted_blob[NONCE_SIZE:-32]
            file_hmac = encrypted_blob[-32:]

            print(f"[CLIENT] Data sizes - Nonce: {len(file_nonce)}, Content: {len(encrypted_content)}, HMAC: {len(file_hmac)}")

            # Verify file-level HMAC
            h = hmac.HMAC(auth_key, hashes.SHA256(), backend=default_backend())
            h.update(file_nonce + encrypted_content)
            try:
                h.verify(file_hmac)
                print("[CLIENT] File integrity verified")
            except InvalidSignature:
                print("[CLIENT] File integrity check failed")
                return False

            # If we get here, both transport and file integrity verified
            try:
                cipher = Cipher(algorithms.AES(file_key), modes.CTR(file_nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

                with open(save_path, 'wb') as f:
                    f.write(decrypted_content)

                print(f"[CLIENT] File saved to {save_path}")
                return True

            except Exception as e:
                print(f"[CLIENT] Decryption error: {str(e)}")
                return False

        except Exception as e:
            print(f"[CLIENT] Error downloading file: {e}")
            return False

    def receive_response(self):
        try:
            # Receive response length and encrypted response from server
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.socket.recv(response_length)
            nonce = encrypted_response[:NONCE_SIZE]
            ciphertext = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            h.verify(received_hmac)

            # Decrypt response
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode('utf-8'))

        except Exception as e:
            print(f"[CLIENT] Error receiving response: {e}")
            return {"status": "failed", "message": str(e)}



    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        self.aes_key = None
        self.hmac_key = None
        self.is_logged_in = False

    def recv_full(self, expected_length):
        data = b""
        while len(data) < expected_length:
            part = self.socket.recv(expected_length - len(data))
            if not part:
                raise ConnectionError("Incomplete message received.")
            data += part
        return data

# Client class setup remains the same

if __name__ == "__main__":
    client = Client()
    if client.connect():
        while True:
            action = input("Do you want to (register), (login), or (exit)? ").strip().lower()
            if action == "register":
                username = input("Enter username: ")
                password = input("Enter password: ")
                response = client.register(username, password)
                message = response.get("message")
                if message:  # Only print if message exists
                    print(message)
                if response.get("status") == "success":
                    print("Registration successful. You can now login.")
            elif action == "login":
                username = input("Enter username: ")
                password = input("Enter password: ")
                response = client.login(username, password)
                print(response.get("message"))

                if response.get("status") == "success":
                    while True:
                        file_action = input("Do you want to (upload) a file, (download) a file, or (logout)? ").strip().lower()
                        if file_action == "upload":
                            file_path = input("Enter the path of the file to upload: ")
                            max_downloads = input("Enter maximum number of downloads (press Enter for unlimited): ").strip()
                            max_downloads = float('inf') if max_downloads == "" else int(max_downloads)
                            expiration = input("Enter expiration time in minutes (press Enter for default): ").strip()
                            expiration = None if expiration == "" else int(expiration)
                            client.upload_file(file_path, max_downloads, expiration)
                        elif file_action == "download":
                            file_id = input("Enter the file ID to download: ")
                            save_path = input("Enter the path to save the file: ")
                            client.download_file(file_id, save_path)
                        elif file_action == "logout":
                            print("Logging out...")
                            client.is_logged_in = False
                            break
                        else:
                            print("Invalid option. Choose upload, download, or logout.")
                else:
                    print("Invalid login details.")
            elif action == "exit":
                print("Exiting client.")
                break
            else:
                print("Invalid choice. Please choose either 'register', 'login', or 'exit'.")
        
        client.close()