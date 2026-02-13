import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

FILE_REQUESTED = "data/server_data/example.txt"
FILE_CREATED = "data/client_data/received_file.txt"

def prepare():
    if os.path.exists(FILE_CREATED):
        os.remove(FILE_CREATED)
        print(f"Removed old file: {FILE_CREATED}")

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    public_key_data = client_socket.recv(4096)  # receive public key from the server
    public_key = RSA.import_key(public_key_data)  # import the public key

    client_socket.send(b'HELLO RSA-AES-256-GCM')

    aes_key = get_random_bytes(32) 

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    client_socket.send(encrypted_key)

    file_request = FILE_REQUESTED
    client_socket.send(file_request.encode())  # send file request

    nonce = client_socket.recv(16)
    tag = client_socket.recv(16)
    ciphertext = b''

    while True:
        chunk = client_socket.recv(1024)
        print('Chunk: ', chunk)
        if not chunk:
            break
        ciphertext += chunk

    print('Ciphertext: ', ciphertext)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    print('Plaintext: ', plaintext)

    with open(FILE_CREATED, "wb") as f:
        f.write(plaintext)
        
    print("File received successfully.")
    


if __name__ == '__main__':
    prepare()
    client_program()