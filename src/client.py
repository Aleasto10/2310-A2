import socket
import os
import config
import RSA_l
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

"data/server_data/example.txt"
"data/server_data/Analisis_del_Codigo_Fuente_y_Metricas_Asociadas_S2_20250319.txt"

FILE_REQUESTED = config.FILE_REQUESTED
FILE_RECEIVED = config.FILE_RECEIVED
LOCAL_RSA = config.LOCAL_RSA

def prepare():
    if os.path.exists(FILE_RECEIVED):
        os.remove(FILE_RECEIVED)
        print(f"Removed old file: {FILE_RECEIVED}")

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    

    client_socket.send(b'HELLO RSA-AES-256-GCM')

    hello = client_socket.recv(1024).decode()
    print("Server says: " + hello)

    public_key_data = client_socket.recv(4096)  # receive public key from the server

    if LOCAL_RSA:
        # server sends "e,n" as UTF-8; parse into integers
        e_str, n_str = public_key_data.decode().split(',')
        public_key = (int(e_str), int(n_str))
    else:
        public_key = RSA.import_key(public_key_data)  # import the public key

    aes_key = get_random_bytes(32) 

    if LOCAL_RSA:
        # convert AES key bytes -> int, encrypt with local RSA, send as fixed-length bytes
        aes_key_int = int.from_bytes(aes_key, byteorder='big')
        aes_key_str = str(aes_key_int)
        l = []
        l_int = []
        l_enc = []
        l_k = []
        i = 0
        for i in range(0,len(aes_key_str),3):
            l.append(aes_key_str[i:i+3])
        if len(aes_key_str) % 3 !=0:
            if len(aes_key_str) % 3 == 1:
                l.append(aes_key_str[-1])
            else:
                l.append(aes_key_str[-2:-1])
        
        for s in l:
            l_int.append(int(s))
        
        for i in l_int:
            enc = RSA_l.encrypt(i,public_key[0],public_key[1])
            l_enc.append(enc)
        
        #encrypted_int = RSA_l.encrypt(aes_key_int, public_key[0], public_key[1])
        #modulus_len = (public_key[1].bit_length() + 7) // 8
        for e in l_enc:
            l_k.append(str(enc.to_bytes()))
    
    else:
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)

    client_socket.send(encrypted_key)

    file_request = FILE_REQUESTED
    client_socket.send(file_request.encode())  # send file request
    print(f"Requested file: {file_request}")

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

    with open(FILE_RECEIVED, "wb") as f:
        f.write(plaintext)
        
    print("File received successfully.")
    


if __name__ == '__main__':
    prepare()
    client_program()