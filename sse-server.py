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
import re
credentials = service_account.Credentials.from_service_account_file('model-marker-440302-n9-e34ab14c4039.json')
storage_client = storage.Client(credentials=credentials)
bigquery_client = bigquery.Client(credentials=credentials, project="model-marker-440302-n9")
# Set up GCP bucket
bucket_name = "client-user-storage-1"
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
                command = request.get("command", "")  # Default to empty string if no command
                print(f"Received Command: {command}")

                # Handle empty requests (used during file upload)
                if not command and not request:
                    continue

                response = {"status": "failed", "message": "Unknown command"}
                if command == "register":
                    response = self.register_user(request["username"], request["password"])
                elif command == "login":
                    response = self.authenticate_user(request["username"], request["password"])
                elif command == "list_files":
                    response = self.list_files(request)
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
        FROM `model-marker-440302-n9.your_dataset.users`
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
        INSERT INTO `model-marker-440302-n9.your_dataset.users`
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
            is_public = request.get('is_public', False)
            
            username = request.get("username")
            is_public = request.get('is_public', False)
            
            if not username or username == "anonymous":
                return {"status": "failed", "message": "Login required for file upload"}

            print(f"[SERVER] Handling upload for user: {username}")
            
            # Send "ready" acknowledgment
            ack_response = {"status": "ready"}
            self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))
            print("[SERVER] Sent ready acknowledgment")

            file_data_length = int.from_bytes(client_socket.recv(4), 'big')
            print(f"[SERVER] Expected file data length: {file_data_length} bytes")
            
            if file_data_length > MAX_FILE_SIZE:
                return {"status": "failed", "message": "File too large"}
                
            file_data = self.recv_full(client_socket, file_data_length)
            print(f"[SERVER] Received file data: {len(file_data)} bytes")

            file_blob = file_data[:-32]
            transport_hmac = file_data[-32:]

            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(file_blob)
            try:
                h.verify(transport_hmac)
                print("[SERVER] Transport HMAC verification successful")
            except InvalidSignature:
                return {"status": "failed", "message": "Integrity check failed"}

            tokens_length = int.from_bytes(client_socket.recv(4), 'big')
            search_tokens_json = self.recv_full(client_socket, tokens_length)
            search_tokens = json.loads(search_tokens_json.decode('utf-8'))

            file_id = secrets.token_hex(24)
            blob = bucket.blob(file_id)
            blob.upload_from_string(file_blob)
            print(f"[SERVER] File uploaded to GCS with file_id: {file_id}")
            MAX_DOWNLOADS = 2147483647
            max_downloads = request.get("max_downloads", MAX_DOWNLOADS)
            expiration_minutes = min(request.get("expiration", DEFAULT_EXPIRATION), MAX_EXPIRATION)
            expiration_time = int(time.time() + (expiration_minutes * 60))

            query = """
            INSERT INTO `model-marker-440302-n9.your_dataset.file-db` 
            (username, file_id, upload_path, max_downloads, expiration_time, upload_time, is_public, search_tokens,downloads)
            VALUES (@username, @file_id, @upload_path, @max_downloads, @expiration_time, @upload_time, @is_public, @search_tokens,0)
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("username", "STRING", username),
                    bigquery.ScalarQueryParameter("file_id", "STRING", file_id),
                    bigquery.ScalarQueryParameter("upload_path", "STRING", f"gs://{bucket_name}/{file_id}"),
                    bigquery.ScalarQueryParameter("max_downloads", "INTEGER", max_downloads),
                    bigquery.ScalarQueryParameter("expiration_time", "INTEGER", expiration_time),
                    bigquery.ScalarQueryParameter("upload_time", "INTEGER", int(time.time())),
                    bigquery.ScalarQueryParameter("is_public", "BOOL", is_public),
                    bigquery.ArrayQueryParameter("search_tokens", "STRING", search_tokens)
                    
                ]
            )
            try:
                bigquery_client.query(query, job_config=job_config).result()
                print(f"[SERVER] File metadata inserted into BigQuery for {file_id}")
            except Exception as bq_error:
                print(f"[SERVER] Error inserting metadata into BigQuery: {bq_error}")
                raise

            for token in search_tokens:
                if token not in self.encrypted_index:
                    self.encrypted_index[token] = []
                self.encrypted_index[token].append({'file_id': file_id})


            return {
                "status": "success",
                "file_id": file_id,
                "expiration_minutes": expiration_minutes,
                "is_public": is_public
            }

        except Exception as e:
            print(f"[SERVER] Error handling upload: {e}")
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

    def handle_search(self, client_socket, request):
        try:
            search_token = request.get('keyword')
            username = request.get('username')

            # Escape reserved characters in the search token
            escaped_search_token = re.sub(r'([=\[\]<>(){}|!\'"\*&?+/:~^\\-])', r'\\\1', search_token)

            # Construct BigQuery search query
            query = """
            SELECT 
                file_id, 
                max_downloads, 
                downloads, 
                expiration_time, 
                is_public,
                username as owner
            FROM `model-marker-440302-n9.your_dataset.file-db`
            WHERE 
                SEARCH(search_tokens, @search_token)
                AND expiration_time > @current_time
                AND (is_public = TRUE OR username = @username)
            """

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("search_token", "STRING", escaped_search_token),
                    bigquery.ScalarQueryParameter("current_time", "INTEGER", int(time.time())),
                    bigquery.ScalarQueryParameter("username", "STRING", username or "")
                ]
            )

            # Execute query
            query_job = bigquery_client.query(query, job_config=job_config)
            results = list(query_job.result())

            # Process search results
            search_results = []
            current_time = time.time()

            for row in results:
                if row['downloads'] < row['max_downloads']:
                    search_results.append({
                        'file_id': row['file_id'],
                        'downloads_remaining': row['max_downloads'] - row['downloads'],
                        'expires_in_minutes': int((row['expiration_time'] - current_time) / 60),
                        'is_public': row['is_public']
                    })

            # Send search results
            response = {"status": "success", "search_result": search_results}
            self.send_encrypted_response(client_socket, json.dumps(response).encode("utf-8"))

            return {"status": "success"}

        except Exception as e:
            print(f"[SERVER] Search error: {e}")
            error_response = {"status": "failed", "message": str(e)}
            self.send_encrypted_response(client_socket, json.dumps(error_response).encode("utf-8"))
            return {"status": "failed", "message": str(e)}

    def handle_download(self, client_socket, request):
        try:
            file_id = request.get("file_id")
            username = request.get("username")

            if not username:
                return {"status": "failed", "message": "User not logged in"}

            print(f"[SERVER] Attempting to download file: {file_id}")

            # Query BigQuery for file metadata
            query = """
            SELECT *, IFNULL(is_public, FALSE) as is_public
            FROM `model-marker-440302-n9.your_dataset.file-db`
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
                return {"status": "failed", "message": "File not found or expired"}

            file_meta = results[0]
            is_public = file_meta.get('is_public', False)
            file_owner = file_meta.get('username')

            # Check if the user has permission to download
            if username != file_owner and not is_public:
                return {"status": "failed", "message": "You don't have permission to download this file"}

            # Check download limit
            downloads = file_meta.get('downloads', 0)
            max_downloads = file_meta.get('max_downloads', float('inf'))
            if downloads >= max_downloads:
                return {"status": "failed", "message": "Download limit reached"}

            # Send initial response with file metadata
            initial_response = {
                "status": "success",
                "is_public": is_public,
                "file_size": file_meta.get('file_size', 0),
                "is_encrypted": not is_public  # Assume private files are encrypted
            }
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

            # Update download count in BigQuery
            update_query = """
            UPDATE `model-marker-440302-n9.your_dataset.file-db`
            SET downloads = COALESCE(downloads, 0) + 1
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
            print(f"Error handling file download: {e}")
            return {"status": "failed", "message": str(e)}
        
    def list_files(self, request):
        try:
            username = request.get('username')
            current_time = time.time()

            # Construct BigQuery query
            if username:
                query = """
                SELECT file_id, max_downloads, downloads, expiration_time, is_public
                FROM `model-marker-440302-n9.your_dataset.file-db`
                WHERE expiration_time > @current_time AND (is_public = TRUE OR username = @username)
                """
            else:
                query = """
                SELECT file_id, max_downloads, downloads, expiration_time, is_public
                FROM `model-marker-440302-n9.your_dataset.file-db`
                WHERE expiration_time > @current_time AND is_public = TRUE
                """

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("current_time", "INTEGER", int(current_time)),
                    bigquery.ScalarQueryParameter("username", "STRING", username or "")
                ]
            )

            query_job = bigquery_client.query(query, job_config=job_config)
            results = list(query_job.result())

            available_files = []
            for row in results:
                downloads = row['downloads']
                max_downloads = row['max_downloads'] or float('inf')
                expiration_time = row['expiration_time'] or 0
                if downloads < max_downloads:
                    file_info = {
                        "file_id": row['file_id'],
                        "downloads_remaining": max_downloads - downloads,
                        "expires_in_minutes": max(0, int((expiration_time - current_time) / 60)),
                        "is_public": row['is_public'] or False
                    }
                    available_files.append(file_info)

            return {"status": "success", "files": available_files}
        except Exception as e:
            print(f"[SERVER] Error in list_files: {e}")
            return {"status": "failed", "message": str(e)}
    
    def authenticate_user(self, username, password):
        query = f"""
        SELECT *
        FROM `model-marker-440302-n9.your_dataset.users`
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
