import socket
import threading
import os
from des import *

class Client:
    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))

        while True:
            key = input("Masukan Key (8 Karakter): ")
            if len(key) == 8:
                break
            else:
                print("Key harus 8 karakter")
                
        self.key = str2hex(key)
        self.rkb, self.rk = generate_round_key(self.key)

        self.name = input("Masukkan nama Anda: ")
        self.socket.send(self.name.encode())

        threading.Thread(target=self.receive_message, daemon=True).start()
        self.send_message()

    def receive_message(self):
        while True:
            try:
                message = self.socket.recv(1024).decode()
                if message:
                    if message.startswith("NOTENC:"):
                        decrypted_text = message[7:]
                        print(decrypted_text)
                    elif message.startswith("Dari "):
                        parts = message.split(": ", 1)
                        sender_info = parts[0]
                        encrypted_text = parts[1]
                        decrypted_text = decrypt(encrypted_text, self.rkb, self.rk)
                        print(f"{sender_info}: {decrypted_text}")
                    elif message.startswith("Broadcast dari "):
                        parts = message.split(": ", 1)
                        broadcast_info = parts[0]
                        encrypted_text = parts[1]
                        decrypted_text = decrypt(encrypted_text, self.rkb, self.rk)
                        print(f"{broadcast_info}: {decrypted_text}")
                    else:
                        continue
                else:
                    print("Koneksi ke server terputus.")
                    self.socket.close()
                    break
            except Exception as e:
                print(f"Terjadi kesalahan dalam menerima pesan: {e}")
                continue
        self.socket.close()

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
                    encrypted_text = encrypt(actual_message, self.rkb, self.rk)
                    message_to_send = f"to: {target_id} {encrypted_text}"
                elif message.startswith("broadcast"):
                    actual_message = message[10:]
                    actual_message = pad(actual_message)
                    encrypted_text = encrypt(actual_message, self.rkb, self.rk)
                    message_to_send = f"broadcast {encrypted_text}"
                else:
                    print("Format pesan tidak valid.")
                    continue

                self.socket.send(message_to_send.encode())
            except Exception as e:
                print(f"Terjadi kesalahan dalam mengirim pesan: {e}")
                continue
        self.socket.close()

if __name__ == '__main__':
    Client('127.0.0.1', 7632)
