import socket
import threading
from rsa import *

class Server:
    clients = {}

    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST, PORT))
        self.socket.listen(5)
        print("Server berjalan...")

        # Generate RSA Key Pair
        self.public_key, self.private_key = generate_keys()

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            client_id = str(client_address[1])
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_id))
            client_thread.start()

    def handle_client(self, client_socket, client_id):
        try:
            client_name = client_socket.recv(7632).decode()
            print(f"Client {client_id} ({client_name}) terhubung.")

            # Send server's public key to client
            client_socket.send(str(self.public_key).encode())

            # Receive client's public key
            client_public_key_data = client_socket.recv(1024).decode()
            client_public_key = eval(client_public_key_data)

            # Store client information
            Server.clients[client_id] = {
                'socket': client_socket,
                'name': client_name,
                'public_key': client_public_key
            }

            # Notify other clients about the new connection
            broadcast_message = f"NOTENC:Telah bergabung ke room chat user {client_name} ({client_id})"
            for cid, client_info in Server.clients.items():
                if cid != client_id:
                    client_info['socket'].send(broadcast_message.encode())

            # Notify the connected client
            response_message = (
                f"NOTENC:ID Anda adalah {client_id}. "
                "Gunakan format pesan 'to:<target_id> <message terenkripsi>' "
                "atau 'broadcast <message terenkripsi>' untuk mengirim pesan."
            )
            client_socket.send(response_message.encode())

            while True:
                try:

                    # Receive the encrypted message
                    message = client_socket.recv(1024).decode()

                    if message:
                        if message.startswith("to:"):
                            parts = message.split(" ", 2)
                            if len(parts) < 3:
                                continue
                            target_id = parts[1]
                            encrypted_message = parts[2]
                            print(f"Sending Message from client {client_id} to {target_id} with encrypted message: {encrypted_message}")

                            if target_id in Server.clients:
                                target_socket = Server.clients[target_id]['socket']
                                target_public_key = Server.clients[target_id]['public_key']
                                sender_name = Server.clients[client_id]['name']

                                # Receive encrypted DES key
                                encrypted_key_string = client_socket.recv(1024).decode()
                                encrypted_key = string_to_ciphertext(encrypted_key_string)
                                des_key = RSAdecrypt(encrypted_key, self.private_key)
                                print(f"DES Key decrypted for client {client_id}: {des_key}")

                                # Encrypt DES key with the target client's public key
                                encrypted_des_key = RSAencrypt(des_key, target_public_key)
                                encrypted_key_string = ciphertext_to_string(encrypted_des_key)

                                # Send encrypted DES key and message to the target client
                                forward_message = f"Dari {sender_name} ({client_id}): {encrypted_message}"
                                target_socket.send(forward_message.encode())
                                target_socket.send(f"KEY:{encrypted_key_string}".encode())
                            else:
                                client_socket.send(f"NOTENC:Client {target_id} tidak ditemukan.".encode())

                        elif message.startswith("broadcast"):
                            encrypted_message = message.split(" ", 1)[1]
                            print(f"Broadcast Message from client {client_id}: {encrypted_message}")
                            broadcast_message = f"Broadcast dari {Server.clients[client_id]['name']} ({client_id}): {encrypted_message}"
                            # Receive encrypted DES key
                            encrypted_key_string = client_socket.recv(1024).decode()
                            encrypted_key = string_to_ciphertext(encrypted_key_string)
                            des_key = RSAdecrypt(encrypted_key, self.private_key)
                            print(f"DES Key decrypted from client {client_id}: {des_key}")
                            for cid, client_info in Server.clients.items():
                                if cid != client_id:
                                    # Encrypt DES key with each client's public key
                                    encrypted_des_key = RSAencrypt(des_key, client_info['public_key'])
                                    encrypted_key_string = ciphertext_to_string(encrypted_des_key)

                                    # Send encrypted DES key and message
                                    client_info['socket'].send(broadcast_message.encode())
                                    client_info['socket'].send(f"KEY:{encrypted_key_string}".encode())
                    else:
                        break
                except ConnectionResetError:
                    print(f"Koneksi ke client {client_id} terputus.")
                    break
        except Exception as e:
            print(f"Kesalahan pada client {client_id}: {e}")
        finally:
            client_socket.close()
            if client_id in Server.clients:
                broadcast_message = f"NOTENC:User {Server.clients[client_id]['name']} dengan ID ({client_id}) telah meninggalkan server!"
                del Server.clients[client_id]
                for cid, client_info in Server.clients.items():
                    client_info['socket'].send(broadcast_message.encode())
            print(f"Client {client_id} telah terputus.")


if __name__ == '__main__':
    server = Server('127.0.0.1', 7632)
    server.listen()
