import socket
import threading
import os
import queue
from des import *
from rsa import *

class Client:
    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.response_queue = queue.Queue()  # Queue for handling specific responses

        self.name = input("Masukkan nama Anda: ")
        self.socket.send(self.name.encode())

        # Generate RSA Key Pair
        self.public_key, self.private_key = generate_keys()
        self.send_public_key_to_server()

        # Thread to handle incoming messages
        threading.Thread(target=self.receive_message, daemon=True).start()

        # Start sending messages
        self.send_message()

    def send_public_key_to_server(self):
        """Send the public key to the server."""
        public_key_string = f"PUB_KEY:{str(self.public_key)}"
        self.socket.send(public_key_string.encode())

    def request_public_key(self, target_id):
        """Request the public key of a specific target ID from the server."""
        request_message = f"getkey:{target_id}"
        self.socket.send(request_message.encode())
        print("Meminta Public Key Ke Server...")

        try:
            # Wait for a response in the queue with a timeout
            response = self.response_queue.get(timeout=10)

            if response.startswith("PUB_KEY:"):
                # Isolate the public key portion
                public_key_data = response[len("PUB_KEY:"):]
                
                # Evaluate the tuple to a Python object
                public_key = eval(public_key_data)
                
                # Ensure it is a tuple of two integers
                if isinstance(public_key, tuple) and len(public_key) == 2:
                    return public_key
                else:
                    print("Invalid public key format.")
                    return None
            else:
                print("Unexpected response format.")
                return None
        except queue.Empty:
            print("Timeout waiting for public key response.")
            return None


    def route_message(self, message):
        """Route messages based on their type."""
        if message.startswith("PUB_KEY:"):
            self.response_queue.put(message)
        elif message.startswith("NOTENC:"):
            print(message[7:])
        elif message.startswith("Dari "):
            self.process_received_message(message)
        else:
            print("Pesan tidak dikenali.")

    def process_received_message(self, message):
        """Process incoming encrypted messages."""
        try:
            parts = message.split(": ", 3)
            sender_info = parts[0]  # Includes sender's ID and name
            encrypted_message = parts[1]
            encrypted_des_key = parts[2]

            # Decrypt DES key using own private key
            des_key = RSAdecrypt(string_to_ciphertext(encrypted_des_key), self.private_key)

            # Get sender's public key to decrypt the message
            sender_id = sender_info.split("(")[-1][:-1]
            sender_public_key = self.request_public_key(sender_id)

            if not sender_public_key:
                print("Gagal memperoleh kunci publik pengirim.")
                return

            # Decrypt the DES key using sender's public key
            des_key = RSAdecrypt(string_to_ciphertext(des_key), sender_public_key)
            print("-- Kunci DES berhasil didekripsi.")

            # Decrypt the message using DES
            self.key = str2hex(des_key)
            self.rkb, self.rk = generate_round_key(self.key)
            decrypted_text = decrypt(encrypted_message, self.rkb, self.rk)
            print("-- Pesan berhasil didekripsi.")
            print("")
            print("===============================================")
            print("")
            print(f"{sender_info}: {decrypted_text}")
            print("")
            print("===============================================")
            print("")
        except Exception as e:
            print(f"Kesalahan saat memproses pesan: {e}")

    def receive_message(self):
        while True:
            try:
                message = self.socket.recv(1024).decode()
                if message:
                    threading.Thread(target=self.route_message, args=(message,), daemon=True).start()
                else:
                    print("Koneksi ke server terputus.")
                    self.socket.close()
                    break
            except Exception as e:
                print(f"Kesalahan saat menerima pesan: {e}")


    def send_message(self):
        while True:
            try:
                message = input("")
                if message.lower() == 'exit':
                    self.socket.close()
                    os._exit(0)

                if message.startswith("to:"):
                    target_id, actual_message = message[3:].split(" ", 1)
                    actual_message = pad(actual_message)

                    # Request target's public key from the server
                    target_public_key = self.request_public_key(target_id)
                    if not target_public_key:
                        print(f"Gagal memperoleh kunci publik untuk ID {target_id}.")
                        continue  
                    # Input DES key
                    while True:
                        key = input("Masukan Key (8 Karakter): ")
                        if len(key) == 8:
                            break
                        else:
                            print("Key harus 8 karakter")

                    # Encrypt DES key using own private key and target's public key
                    des_key = key
                    encrypted_des_key = RSAencrypt(des_key, self.private_key)
                    encrypted_des_key = RSAencrypt(ciphertext_to_string(encrypted_des_key), target_public_key)
                    encrypted_key_string = ciphertext_to_string(encrypted_des_key)
                    print("-- Kunci DES berhasil dienkripsi.")

                    # Encrypt the message using DES
                    self.key = str2hex(des_key)
                    self.rkb, self.rk = generate_round_key(self.key)
                    encrypted_text = encrypt(actual_message, self.rkb, self.rk)
                    print("-- Pesan berhasil dienkripsi.")

                    message_to_send = f"to: {target_id}: {encrypted_text}: {encrypted_key_string}"
                else:
                    print("Format pesan tidak valid.")
                    continue

                self.socket.send(message_to_send.encode())
                print("-- Pesan terkirim.")
            except Exception as e:
                print(f"Kesalahan saat mengirim pesan: {e}")

if __name__ == '__main__':
    Client('127.0.0.1', 7632)
