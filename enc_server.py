import os
import socket
import json
import threading
import secrets
import binascii
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

AES_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_KEY_SIZE = 32
MAX_FILE_SIZE = 1024 * 1024  # 1 MB for testing
FILE_DIRECTORY = "server_files"
DEFAULT_EXPIRATION = 60  # 60 minutes
MAX_EXPIRATION = 4320   # 3 days in minutes

USER_DB = {}
FILE_DB = {}  # Tracks file metadata including download counts

class Server:
    def __init__(self, host='localhost', port=5002):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.hmac_key = None

        # Generate RSA key pair for server
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        self.cleanup_thread = threading.Thread(target=self.cleanup_expired_files, daemon=True)
        self.cleanup_thread.start()

    def handle_client(self, client_socket):
        try:
            # Send RSA public key to client
            rsa_public_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print("Sending RSA public key to client...")
            client_socket.send(rsa_public_key_bytes)
            print("RSA public key sent successfully")

            # Receive and decrypt AES + HMAC keys from client
            encrypted_key = client_socket.recv(256)
            combined_key = self.rsa_private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.aes_key, self.hmac_key = combined_key[:AES_KEY_SIZE], combined_key[AES_KEY_SIZE:]
            print("Received and decrypted AES Key: " + self.aes_key.hex())
            print("Received and decrypted HMAC Key: " + self.hmac_key.hex())

            # Keep connection alive and wait for multiple commands
            while True:
                length_prefix = client_socket.recv(4)
                if not length_prefix:
                    print("Client disconnected")
                    break
                message_length = int.from_bytes(length_prefix, 'big')
                encrypted_data = self.recv_full(client_socket, message_length)
                
                request = self.decrypt_and_verify(encrypted_data)
                print(f"Decrypted Request: {request}")
                command = request.get("command")
                print(f"Received Command: {command}")

                if command == "register":
                    response = self.register_user(request["username"], request["password"])
                elif command == "login":
                    response = self.authenticate_user(request["username"], request["password"])
                elif command == "upload":
                    ack_response = {"status": "ready"}
                    self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))
                    response = self.handle_upload(client_socket, request)
                elif command == "download":
                    response = self.handle_download(client_socket, request)
                else:
                    response = {"status": "failed", "message": "Unknown command"}
                
                response_data = json.dumps(response).encode('utf-8')
                self.send_encrypted_response(client_socket, response_data)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print(f"Closing client {client_socket}")
            client_socket.close()

    def register_user(self, username, password):
        print(f"Attempting to register user: {username}")
        if username in USER_DB:
            print(f"Username '{username}' already exists in the database")
            return {"status": "failed", "message": "Username already exists"}
        
        # Generate a salt and hash the password
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,# The number of times hashed. Slows down brute force attacks.
            backend=default_backend()
        )
        password_hash = kdf.derive(password.encode())
        USER_DB[username] = {"salt": salt, "password_hash": password_hash}
        
        print(f"User '{username}' registered successfully")
        return {"status": "success", "message": "User registered successfully"}

    def handle_upload(self, client_socket, request):
        try:
            # Send "ready" acknowledgment to the client
            ack_response = {"status": "ready"}
            self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))

            # Receive the file data length and content
            file_data_length = int.from_bytes(client_socket.recv(4), 'big')
            file_data = self.recv_full(client_socket, file_data_length)

            # Separate nonce, encrypted data, and auth tag
            file_nonce = file_data[:NONCE_SIZE]
            encrypted_file_data = file_data[NONCE_SIZE:-32]
            auth_tag = file_data[-32:]

            # Verify HMAC
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_file_data)
            try:
                h.verify(auth_tag)
                print("[SERVER] HMAC verification successful.")
            except InvalidSignature:
                print("[SERVER] HMAC verification failed. Rejecting file.")
                return {"status": "failed", "message": "Integrity check failed"}

            # Save the file
            file_id = secrets.token_hex(24)
            file_path = os.path.join(FILE_DIRECTORY, file_id)
            os.makedirs(FILE_DIRECTORY, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file_nonce + encrypted_file_data)

            # Get max_downloads from request, default to infinity
            max_downloads = request.get("max_downloads", float('inf'))
            
            # Get expiration time from request or use default
            expiration_minutes = request.get("expiration")
            if expiration_minutes is None:
                expiration_minutes = DEFAULT_EXPIRATION
            elif expiration_minutes > MAX_EXPIRATION:
                expiration_minutes = MAX_EXPIRATION
            
            expiration_time = time.time() + (expiration_minutes * 60)
            
            # Store file metadata with expiration
            FILE_DB[file_id] = {
                "downloads": 0,
                "max_downloads": max_downloads,
                "expiration_time": expiration_time,
                "upload_time": time.time()
            }

            print(f"[SERVER] File saved with ID: {file_id}, expires in {expiration_minutes} minutes")
            return {"status": "success", "file_id": file_id, "expiration_minutes": expiration_minutes}

        except Exception as e:
            print(f"Error handling upload: {e}")
            return {"status": "failed", "message": "File upload failed"}



    def handle_download(self, client_socket, request):
        try:
            file_id = request.get("file_id")
            print(f"[SERVER] Attempting to download file: {file_id}")
            
            # First check - file exists in database
            if file_id not in FILE_DB:
                print(f"[SERVER] File {file_id} not found in database")
                return {"status": "failed", "message": "File not found"}

            file_meta = FILE_DB[file_id]
            current_time = time.time()
            print(f"[SERVER] File metadata: {file_meta}")
            
            # Second check - file hasn't expired
            if current_time > file_meta["expiration_time"]:
                print(f"[SERVER] File {file_id} has expired")
                # Clean up expired file
                file_path = os.path.join(FILE_DIRECTORY, file_id)
                if os.path.exists(file_path):
                    os.remove(file_path)
                del FILE_DB[file_id]
                return {"status": "failed", "message": "File has expired"}

            # Third check - download limit not reached
            if file_meta["downloads"] >= file_meta["max_downloads"]:
                print(f"[SERVER] File {file_id} reached download limit")
                # Delete the file and its metadata
                file_path = os.path.join(FILE_DIRECTORY, file_id)
                if os.path.exists(file_path):
                    os.remove(file_path)
                del FILE_DB[file_id]
                return {"status": "failed", "message": "Download limit reached"}

            file_path = os.path.join(FILE_DIRECTORY, file_id)
            if not os.path.exists(file_path):
                print(f"[SERVER] File {file_id} not found on disk")
                return {"status": "failed", "message": "File not found"}

            # Send single ready response
            self.send_encrypted_response(client_socket, json.dumps({"status": "ready"}).encode("utf-8"))

            # Read the stored file data (nonce + encrypted content)
            with open(file_path, 'rb') as f:
                stored_data = f.read()
                print("[SERVER] File content read for download:", stored_data)

            # Generate response nonce and HMAC
            response_nonce = secrets.token_bytes(NONCE_SIZE)
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(response_nonce + stored_data)
            hmac_value = h.finalize()

            # Send: response_nonce + stored_data + hmac
            response_data = response_nonce + stored_data
            data_length = len(response_data + hmac_value).to_bytes(4, 'big')
            client_socket.sendall(data_length + response_data + hmac_value)
            print(f"[SERVER] File with ID {file_id} successfully sent to client")

            # Update download count after successful download
            file_meta["downloads"] += 1
            print(f"[SERVER] File {file_id} downloaded. {file_meta['max_downloads'] - file_meta['downloads']} downloads remaining")

            # If max downloads reached, delete the file
            if file_meta["downloads"] >= file_meta["max_downloads"]:
                os.remove(file_path)
                del FILE_DB[file_id]

            return {"status": "success"}

        except Exception as e:
            print(f"Error handling file download: {e}")
            return {"status": "failed", "message": str(e)}


    def authenticate_user(self, username, password):
        user_record = USER_DB.get(username)
        if not user_record:
            return {"status": "failed", "message": "User does not exist"}
        
        # Hash the provided password with the stored salt
        salt = user_record["salt"]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            kdf.verify(password.encode(), user_record["password_hash"])
            return {"status": "success", "message": "Login successful"}
        except Exception:
            return {"status": "failed", "message": "Incorrect password"}

    def send_encrypted_response(self, client_socket, data):
        # Encrypt the response data and send it with HMAC
        response_nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(response_nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Generate HMAC for integrity
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(response_nonce + ciphertext)
        hmac_value = h.finalize()

        # Send length-prefixed encrypted response with HMAC
        print(f"Response Nonce: {response_nonce.hex()}")
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"HMAC Value: {hmac_value.hex()}")
        encrypted_response = response_nonce + ciphertext + hmac_value
        response_length = len(encrypted_response).to_bytes(4, 'big')
        client_socket.sendall(response_length + encrypted_response)

    def recv_full(self, client_socket, expected_length):
        data = b""
        while len(data) < expected_length:
            part = client_socket.recv(expected_length - len(data))
            if not part:
                raise ConnectionError("Incomplete message received from client.")
            data += part
        return data

    def decrypt_and_verify(self, encrypted_data):
        # Separate the nonce, ciphertext, and HMAC
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:-32]
        received_hmac = encrypted_data[-32:]

        # Verify HMAC
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(nonce + ciphertext)
        h.verify(received_hmac)  # Raises exception if HMAC does not match

        # Decrypt data
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return json.loads(plaintext.decode('utf-8'))

    def cleanup_expired_files(self):
        while True:
            current_time = time.time()
            expired_files = []
            
            # Check for expired files
            for file_id, metadata in FILE_DB.items():
                if current_time > metadata["expiration_time"]:
                    expired_files.append(file_id)
            
            # Remove expired files
            for file_id in expired_files:
                try:
                    file_path = os.path.join(FILE_DIRECTORY, file_id)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    del FILE_DB[file_id]
                    print(f"[SERVER] Removed expired file: {file_id}")
                except Exception as e:
                    print(f"[SERVER] Error removing expired file {file_id}: {e}")
            
            # Check every minute
            time.sleep(60)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, address = self.server_socket.accept()
            print(f"Connection from {address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = Server(port=5002)
    server.start()
