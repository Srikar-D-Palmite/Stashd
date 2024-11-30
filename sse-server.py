import os
import socket
import json
import threading
import secrets
import binascii
import time
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from google.cloud import storage
from google.cloud import bigquery
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file('focus-ensign-437302-v1-3627a068eafc.json')
storage_client = storage.Client(credentials=credentials)
bigquery_client = bigquery.Client(credentials=credentials)

# Set up GCP bucket
bucket_name = "client-user-storage"
bucket = storage_client.bucket(bucket_name)

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
        
        # First, check if the username already exists in BigQuery
        query = f"""
        SELECT *
        FROM `focus-ensign-437302-v1.your_dataset.users`
        WHERE username = @username
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("username", "STRING", username)
            ]
        )
        query_job = bigquery_client.query(query, job_config=job_config)
        results = query_job.result()

        # Check if user already exists
        if next(results, None):
            print(f"Username '{username}' already exists in the database")
            return {"status": "failed", "message": "Username already exists"}
        
        # Generate a salt and hash the password
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        password_hash = kdf.derive(password.encode())

        # Insert user into BigQuery
        insert_query = f"""
        INSERT INTO `focus-ensign-437302-v1.your_dataset.users`
        (username, password, salt)
        VALUES (@username, @password, @salt)
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("username", "STRING", username),
                bigquery.ScalarQueryParameter("password", "STRING", password_hash.hex()),  # Store as hex string
                bigquery.ScalarQueryParameter("salt", "STRING", binascii.hexlify(salt).decode())  # Store salt as hex string
            ]
        )
        
        try:
            bigquery_client.query(insert_query, job_config=job_config).result()
            print(f"User '{username}' registered successfully in BigQuery")
            return {"status": "success", "message": "User registered successfully"}
        except Exception as e:
            print(f"Error registering user in BigQuery: {e}")
            return {"status": "failed", "message": f"Registration failed: {str(e)}"}

    def handle_upload(self, client_socket, request):
        try:
            username = request.get("username")
            if not username:
                return {"status": "failed", "message": "Username not provided"}
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

            file_data_length = int.from_bytes(client_socket.recv(4), 'big')
            search_tokens_json = self.recv_full(client_socket, file_data_length)
            search_tokens = json.loads(search_tokens_json.decode('utf-8'))

            # Save the complete file blob (without transport HMAC)
            file_id = secrets.token_hex(24)
            # Insert file metadata into BigQuery
            query = f"""
            INSERT INTO `focus-ensign-437302-v1.your_dataset.file-db`
            (username, file_id, upload_path, max_downloads, expiration_time, upload_time)
            VALUES (@username, @file_id, @upload_path, @max_downloads, @expiration_time, @upload_time)
            """

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("username", "STRING", request.get("username")),
                    bigquery.ScalarQueryParameter("file_id", "STRING", file_id),
                    bigquery.ScalarQueryParameter("upload_path", "STRING", f"gs://{bucket_name}/{file_id}"),
                    bigquery.ScalarQueryParameter("max_downloads", "INTEGER", request.get("max_downloads")),
                    bigquery.ScalarQueryParameter("expiration_time", "INTEGER", int(time.time() + request.get("expiration", DEFAULT_EXPIRATION) * 60)),
                    bigquery.ScalarQueryParameter("upload_time", "INTEGER", int(time.time()))
                ]
            )

            bigquery_client.query(query, job_config=job_config).result()

            file_path = os.path.join(FILE_DIRECTORY, file_id)
            os.makedirs(FILE_DIRECTORY, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file_blob)
                
            #save on GCP
            blob = bucket.blob(file_id)
            blob.upload_from_string(file_blob)

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
        
        self.send_encrypted_response(client_socket, json.dumps({"search_result": search_result}).encode("utf-8"))

        return {"status": "success"}

    def handle_download(self, client_socket, request):
        try:
            file_id = request.get("file_id")
            
            # Query BigQuery for file metadata
            query = f"""
            SELECT * FROM `focus-ensign-437302-v1.your_dataset.file-db`
            WHERE file_id = @file_id AND expiration_time > @current_time
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("file_id", "STRING", file_id),
                    bigquery.ScalarQueryParameter("current_time", "INTEGER", int(time.time()))
                ]
            )
            query_job = bigquery_client.query(query, job_config=job_config)
            results = list(query_job.result())

            if not results:
                print(f"File not found in BigQuery: {file_id}")
                return {"status": "failed", "message": "File not found or expired"}

            file_meta = results[0]
            
            self.send_encrypted_response(client_socket, json.dumps({"status": "ready"}).encode("utf-8"))
            # Download file from GCS bucket
            blob = bucket.blob(file_id)
            file_data = blob.download_as_string()
            # Add transport-level HMAC
            transport_hmac = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            transport_hmac.update(file_data)
            transport_tag = transport_hmac.finalize()

            # Send complete blob with transport HMAC
            complete_data = file_data + transport_tag
            data_length = len(complete_data).to_bytes(4, 'big')
            client_socket.sendall(data_length + complete_data)

            print(f"[SERVER] Sent file {file_id} with transport integrity")

            update_query = f"""
            UPDATE `focus-ensign-437302-v1.your_dataset.file-db`
            SET downloads = downloads + 1
            WHERE file_id = @file_id
            """
            update_job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("file_id", "STRING", file_id)
                ]
            )
            bigquery_client.query(update_query, job_config=update_job_config).result()
            return {"status": "success"}
        except Exception as e:
            print(f"Error handling download: {e}")
            return {"status": "failed", "message": str(e)}
    def upload_file(self, file_data, max_downloads, expiration_minutes):
        try:
            file_id = secrets.token_hex(24)
            expiration_time = int(time.time() + (expiration_minutes * 60))

            # Upload file to GCP bucket
            try:
                blob = bucket.blob(file_id)
                blob.upload_from_string(file_data)
                print(f"File uploaded successfully to GCS with file_id: {file_id}")
            except Exception as gcs_error:
                print(f"Error uploading to GCS: {gcs_error}")
                return {"status": "failed", "message": f"GCS upload failed: {str(gcs_error)}"}

            # Set metadata
            blob.metadata = {
                "max_downloads": str(max_downloads),
                "expiration_time": str(expiration_time),
                "download_count": "0"
            }
            blob.patch()

            return {"status": "success", "file_id": file_id, "expiration_minutes": expiration_minutes}
        except Exception as e:
            print(f"Error uploading file: {e}")
            return {"status": "failed", "message": str(e)}

    def authenticate_user(self, username, password):
        query = f"""
        SELECT *
        FROM `focus-ensign-437302-v1.your_dataset.users`
        WHERE username = @username
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("username", "STRING", username)
            ]
        )
        query_job = bigquery_client.query(query, job_config=job_config)
        results = query_job.result()

        user_record = next(results, None)
        if not user_record:
            return {"status": "failed", "message": "User does not exist"}

        # Verify password
        stored_salt = binascii.unhexlify(user_record['salt'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=stored_salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Hash the provided password with the stored salt
        password_hash = kdf.derive(password.encode())
        
        # Compare hashed passwords
        if password_hash.hex() == user_record['password']:
            return {"status": "success", "message": "Login successful"}
        else:
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
