import socket
import threading
import time

class Server:
    clients = {}  # Shared dictionary to store client information
    lock = threading.Lock()  # Lock for thread-safe operations on clients

    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((HOST, PORT))
        self.socket.listen(5)
        print("Server berjalan...")

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            client_id = str(client_address[1])  # Use port as a unique client ID
            print(f"Client dengan ID {client_id} mencoba terhubung...")

            # Start a thread for the client
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_id))
            client_thread.start()

    def handle_client(self, client_socket, client_id):
        try:
            client_name = client_socket.recv(1024).decode()
            print(f"Client {client_id} ({client_name}) terhubung.")

            with Server.lock:
                # Store client information
                Server.clients[client_id] = {
                    'socket': client_socket,
                    'name': client_name,
                    'public_key': None
                }

            self.broadcast_message(
                f"NOTENC:Telah bergabung ke room chat user {client_name} ({client_id})", exclude_id=client_id
            )

            client_socket.send(
                (
                    f"NOTENC:ID Anda adalah {client_id}. "
                    "Gunakan format pesan 'to:<target_id> <message terenkripsi>' "
                    "atau 'broadcast <message terenkripsi>' untuk mengirim pesan."
                ).encode()
            )

            # Wait for public key from the client
            if not self.receive_public_key(client_socket, client_id):
                raise TimeoutError("Public key not received.")

            while True:
                try:
                    message = client_socket.recv(7632).decode()
                    if not message:
                        break

                    if message.startswith("to:"):
                        parts = message.split(": ", 2)
                        if len(parts) < 3:
                            continue
                        target_id, encrypted_message = parts[1], parts[2]

                        with Server.lock:
                            if target_id in Server.clients:
                                target_socket = Server.clients[target_id]['socket']
                                sender_name = Server.clients[client_id]['name']
                                forward_message = f"Dari {sender_name} ({client_id}): {encrypted_message}"
                                target_socket.send(forward_message.encode())
                                print(f"Pesan terenkripsi dari {client_id} diteruskan ke {target_id}.")
                            else:
                                client_socket.send(f"NOTENC:Client {target_id} tidak ditemukan.".encode())

                    elif message.startswith("getkey:"):
                        target_id = message.split(":")[1]
                        self.handle_public_key_request(client_socket, client_id, target_id)

                except ConnectionResetError:
                    print(f"Koneksi ke client {client_id} terputus.")
                    break
        except Exception as e:
            print(f"Kesalahan pada client {client_id}: {e}")
        finally:
            self.remove_client(client_id)

    def handle_public_key_request(self, client_socket, requester_id, target_id):
        with Server.lock:
            if target_id in Server.clients:
                target_public_key = Server.clients[target_id]['public_key']
                if target_public_key:
                    response = f"PUB_KEY:{target_public_key}"
                    client_socket.send(response.encode())
                    print(f"Public key dari {target_id} dikirim ke {requester_id}.")
                else:
                    error_msg = f"NOTENC:Public key untuk client {target_id} tidak tersedia."
                    client_socket.send(error_msg.encode())
                    print(f"Public key tidak tersedia untuk client {target_id}.")
            else:
                error_msg = f"NOTENC:Client {target_id} tidak ditemukan."
                client_socket.send(error_msg.encode())
                print(f"Client {target_id} tidak ditemukan saat diminta oleh {requester_id}.")


    def broadcast_message(self, message, exclude_id=None):
        with Server.lock:
            for cid, client_info in Server.clients.items():
                if cid != exclude_id:
                    try:
                        client_info['socket'].send(message.encode())
                    except Exception as e:
                        print(f"Kesalahan mengirim pesan ke client {cid}: {e}")

    def remove_client(self, client_id):
        with Server.lock:
            if client_id in Server.clients:
                client_socket = Server.clients[client_id]['socket']
                try:
                    client_socket.close()
                except Exception:
                    pass
                client_name = Server.clients[client_id]['name']
                del Server.clients[client_id]
                print(f"Client {client_id} ({client_name}) telah terputus.")
                self.broadcast_message(
                    f"NOTENC:User {client_name} dengan ID ({client_id}) telah meninggalkan server!", exclude_id=client_id
                )

    def receive_public_key(self, client_socket, client_id):
        try:
            client_socket.settimeout(10)  # Wait up to 10 seconds for the public key
            key_message = client_socket.recv(1024).decode()
            if key_message.startswith("PUB_KEY:"):
                public_key_data = key_message.split(":", 1)[1]
                with Server.lock:
                    Server.clients[client_id]['public_key'] = eval(public_key_data)
                print(f"Public key diterima dari client {client_id}: {public_key_data}")
                client_socket.settimeout(None)  # Reset timeout after receiving public key
                return True
            else:
                print(f"Public key tidak diterima dari client {client_id}.")
        except socket.timeout:
            print(f"Timeout saat menunggu public key dari client {client_id}.")
        except Exception as e:
            print(f"Kesalahan saat menerima public key dari client {client_id}: {e}")
        return False

if __name__ == '__main__':
    server = Server('127.0.0.1', 7632)
    server.listen()
