import os
import socket
import json
import threading
import secrets
import binascii
import time
import json
from typing import Dict, List
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
PORT = 5003

USER_DB = {}
FILE_DB = {}  # Tracks file metadata including download counts

class Server:
    def __init__(self, host='localhost', port=5002):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.hmac_key = None
        self.client_keys = {}  # Store keys per client connection
        self.encrypted_index: Dict[str, List[dict]] = {}

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
            client_id = id(client_socket)  # Unique ID for this connection
            self.client_keys[client_id] = {'aes_key': None, 'hmac_key': None}
            
            # Send RSA public key to client
            rsa_public_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print("Sending RSA public key to client...")
            client_socket.send(rsa_public_key_bytes)
            print("RSA public key sent successfully")

            # Receive client's public key
            client_public_key_bytes = client_socket.recv(2480)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=default_backend()
            )

            # Receive encrypted keys and signature
            msg_len = int.from_bytes(client_socket.recv(4), 'big')
            message = client_socket.recv(msg_len)
            
            # Split message into encrypted key and signature
            # RSA-2048 encrypted data is 256 bytes
            encrypted_key = message[:-256]  # Everything except last 256 bytes
            signature = message[-256:]      # Last 256 bytes is signature

            # Decrypt the symmetric keys
            combined_key = self.rsa_private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Verify signature
            try:
                client_public_key.verify(
                    signature,
                    combined_key,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print("Client signature verification failed")
                return

            # Extract AES and HMAC keys
            self.aes_key, self.hmac_key = combined_key[:AES_KEY_SIZE], combined_key[AES_KEY_SIZE:]
            print("Received and decrypted AES Key: " + self.aes_key.hex())
            print("Received and decrypted HMAC Key: " + self.hmac_key.hex())

            # Store keys for this specific client
            self.client_keys[client_id]['aes_key'] = self.aes_key
            self.client_keys[client_id]['hmac_key'] = self.hmac_key

            # Keep connection alive and wait for multiple commands
            while True:
                # Use client-specific keys
                aes_key = self.client_keys[client_id]['aes_key']
                hmac_key = self.client_keys[client_id]['hmac_key']
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
                elif command == "list_files":
                    response = self.list_files()
                elif command == "upload":
                    ack_response = {"status": "ready"}
                    self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))
                    response = self.handle_upload(client_socket, request)
                elif command == "download":
                    response = self.handle_download(client_socket, request)
                elif command == "search":
                    response = self.handle_search(client_socket, request)
                else:
                    response = {"status": "failed", "message": "Unknown command"}
                
                response_data = json.dumps(response).encode('utf-8')
                self.send_encrypted_response(client_socket, response_data)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            if client_id in self.client_keys:
                del self.client_keys[client_id]
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

            # Structure: file_blob + transport_hmac
            # where file_blob = file_nonce + encrypted_data + file_hmac
            file_blob = file_data[:-32]  # Everything except transport HMAC
            transport_hmac = file_data[-32:]

            # Verify transport HMAC
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(file_blob)
            try:
                h.verify(transport_hmac)
                print("[SERVER] Transport HMAC verification successful")
            except InvalidSignature:
                print("[SERVER] Transport HMAC verification failed")
                return {"status": "failed", "message": "Integrity check failed"}

            # Extract file data
            # received_data = json.loads(file_blob.decode('utf-8'))
            # print(received_data)
            # file_data = received_data["encrypted_file"]
            # search_tokens = received_data["search_tokens"]
            # ack_response = {"status": "ready"}
            # self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))

            file_data_length = int.from_bytes(client_socket.recv(4), 'big')
            search_tokens_json = self.recv_full(client_socket, file_data_length)
            search_tokens = json.loads(search_tokens_json.decode('utf-8'))

            # Save the complete file blob (without transport HMAC)
            file_id = secrets.token_hex(24)
            file_path = os.path.join(FILE_DIRECTORY, file_id)
            os.makedirs(FILE_DIRECTORY, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file_blob)

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
                "upload_time": time.time(),
                "search_tokens": search_tokens,
            }
            print(search_tokens)
            for token in search_tokens:
                if token not in self.encrypted_index:
                    self.encrypted_index[token] = []
                
                # Store encrypted document with its ID
                self.encrypted_index[token].append({
                    'file_id': file_id,
                })

            print(f"[SERVER] File saved with ID: {file_id}, expires in {expiration_minutes} minutes")
            return {"status": "success", "file_id": file_id, "expiration_minutes": expiration_minutes}

        except Exception as e:
            print(f"Error handling upload: {e}")
            return {"status": "failed", "message": "File upload failed"}

    def handle_search(self, client_socket, request):
        search_token = request.get('keyword')

        # Assumes file db only has this user's files
        search_result = self.encrypted_index.get(search_token, [])
        
        # self.send_encrypted_response(client_socket, json.dumps().encode("utf-8"))

        return {"status": "success", "search_result": search_result}


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

            # Add transport-level HMAC
            transport_hmac = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            transport_hmac.update(stored_data)
            transport_tag = transport_hmac.finalize()

            # Send complete blob with transport HMAC
            complete_data = stored_data + transport_tag
            data_length = len(complete_data).to_bytes(4, 'big')
            client_socket.sendall(data_length + complete_data)

            print(f"[SERVER] Sent file {file_id} with transport integrity")

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
        client_id = id(client_socket)
        client_keys = self.client_keys.get(client_id)
        if not client_keys:
            raise Exception("No keys found for client")
            
        aes_key = client_keys['aes_key']
        hmac_key = client_keys['hmac_key']
        
        response_nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(response_nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
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
        # Get client-specific keys
        client_sockets = list(self.client_keys.keys())
        if not client_sockets:
            raise Exception("No active clients")
        client_keys = self.client_keys[client_sockets[-1]]
        
        aes_key = client_keys['aes_key']
        hmac_key = client_keys['hmac_key']
        
        # Separate the nonce, ciphertext, and HMAC
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:-32]
        received_hmac = encrypted_data[-32:]

        # Verify HMAC
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(nonce + ciphertext)
        h.verify(received_hmac)  # Raises exception if HMAC does not match

        # Decrypt data
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
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

    def list_files(self):
        current_time = time.time()
        available_files = []
        
        for file_id, metadata in FILE_DB.items():
            if current_time <= metadata["expiration_time"] and metadata["downloads"] < metadata["max_downloads"]:
                file_info = {
                    "file_id": file_id,
                    "downloads_remaining": metadata["max_downloads"] - metadata["downloads"],
                    "expires_in_minutes": int((metadata["expiration_time"] - current_time) / 60)
                }
                available_files.append(file_info)
        
        return {"status": "success", "files": available_files}

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
    server = Server(port=PORT)
    server.start()