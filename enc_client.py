import socket
import os
import json
import secrets
import binascii
from google.cloud import storage
import google.cloud.aiplatform as aiplatform

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

AES_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_KEY_SIZE = 32
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit for testing
DEFAULT_EXPIRATION = 60  # 60 minutes
DEFAULT_GCS_BUCKET = "client-user-storage"

class Client:
    def __init__(self, host: str = 'localhost', port: int = 5002, gcs_credentials_path: str = None):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.hmac_key = None
        self.is_logged_in = False
        
        # Setup Google Cloud credentials if path is provided
        if gcs_credentials_path:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = gcs_credentials_path
            try:
                aiplatform.init(project="focus-ensign-437302-v1", location="us-central1")
            except Exception as e:
                print(f"Error initializing Vertex AI: {e}")
    def connect(self):
        try:
            self.socket.connect((self.host, self.port))
            
            # Receive server's RSA public key
            rsa_public_key_bytes = self.socket.recv(2480)
            try:
                rsa_public_key = serialization.load_pem_public_key(rsa_public_key_bytes)
                print("RSA public key loaded successfully")
            except Exception as e:
                print(f"Failed to load RSA public key: {e}")
                return False

            # Generate AES and HMAC keys
            self.aes_key = secrets.token_bytes(AES_KEY_SIZE)
            self.hmac_key = secrets.token_bytes(HMAC_KEY_SIZE)
            combined_key = self.aes_key + self.hmac_key
            
            # Encrypt combined AES+HMAC key with server's public RSA key
            encrypted_key = rsa_public_key.encrypt(
                combined_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.socket.send(encrypted_key)
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def send_secure_request(self, request: dict) -> dict:
        try:
            # Convert request to JSON and encrypt with AES-CTR
            plaintext = json.dumps(request).encode('utf-8')
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
        response = self.send_secure_request({"command": "login", "username": username, "password": password})
        if response.get("status") == "success":
            self.is_logged_in = True  # Set login status to true
        return response

    def upload_file(self, file_path, max_downloads=float('inf'), expiration_minutes=None, upload_to_gcs=False, gcs_bucket="client-user-storage"):
        if not self.is_logged_in:
            print("Please log in first.")
            return None

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                if len(file_data) > MAX_FILE_SIZE:
                    print("Error: File too large to upload.")
                    return None

                # Encrypt the file data using AES-CTR
                file_nonce = secrets.token_bytes(NONCE_SIZE)
                cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

                # Generate HMAC for integrity
                h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
                h.update(encrypted_file_data)
                auth_tag = h.finalize()

                # Send upload command and get response
                command = {
                    "command": "upload",
                    "max_downloads": max_downloads,
                    "expiration": expiration_minutes if expiration_minutes is not None else DEFAULT_EXPIRATION
                }
                upload_response = self.send_secure_request(command)
                ack_response = self.receive_response()
                
                if ack_response.get("status") != "ready":
                    print(f"Error: Server not ready. {ack_response.get('message', '')}")
                    return None

                # Send file data
                file_data_length = len(file_nonce + encrypted_file_data + auth_tag).to_bytes(4, 'big')
                self.socket.sendall(file_data_length + file_nonce + encrypted_file_data + auth_tag)
                
                # Get final upload response
                final_response = self.receive_response()
                file_id = None
                if final_response.get("status") == "success":
                    file_id = final_response.get('file_id')
                    print(f"File uploaded successfully. ID: {file_id}")
                    print(f"File will expire in {final_response.get('expiration_minutes')} minutes")
                else:
                    print(f"Upload failed: {final_response.get('message')}")
                    return None

                # Optional GCS upload of encrypted file
                if upload_to_gcs:
                    try:
                        # Create a temporary encrypted file
                        encrypted_file_path = f"{file_path}.encrypted"
                        with open(encrypted_file_path, 'wb') as f:
                            f.write(file_nonce + encrypted_file_data)

                        # Upload to GCS
                        storage_client = storage.Client()
                        bucket = storage_client.bucket(gcs_bucket)
                        
                        # Use file ID as blob name to ensure uniqueness
                        blob_name = f"encrypted_files/{file_id}"
                        blob = bucket.blob(blob_name)
                        blob.upload_from_filename(encrypted_file_path)
                        
                        print(f"Encrypted file uploaded to GCS: gs://{gcs_bucket}/{blob_name}")
                        
                        # Optional: Remove temporary encrypted file
                        os.remove(encrypted_file_path)
                    
                    except Exception as e:
                        print(f"Error uploading to Google Cloud Storage: {e}")

                return file_id

        except Exception as e:
            print(f"Error during file upload: {e}")
            return None


    def download_file(self, file_id, save_path):
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
            
            # Extract components
            response_nonce = encrypted_response[:NONCE_SIZE]
            file_data = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify HMAC
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(response_nonce + file_data)
            h.verify(received_hmac)
            print("[CLIENT] HMAC verification successful")

            # Extract file nonce and encrypted content
            file_nonce = file_data[:NONCE_SIZE]
            encrypted_content = file_data[NONCE_SIZE:]

            # Decrypt using original file nonce
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()
            
            print(f"[CLIENT] Decrypted content: {decrypted_content}")

            # Save decrypted file
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)

            print(f"[CLIENT] File saved to {save_path}")
            return True

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
        self.socket.close()

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
    client = Client(gcs_credentials_path="focus-ensign-437302-v1-89352d588e13.json")
    if client.connect():
        while True:
            action = input("Do you want to (register), (login), or (exit)? ").strip().lower()
            if action == "register":
                username = input("Enter username: ")
                password = input("Enter password: ")
                response = client.register(username, password)
                print(response.get("message"))
                
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
                            gcs_upload = input("Upload to Google Cloud Storage? (y/n): ").strip().lower() == 'y'
                            
                            client.upload_file(
                                file_path, 
                                max_downloads, 
                                expiration, 
                                upload_to_gcs=gcs_upload
                            )
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