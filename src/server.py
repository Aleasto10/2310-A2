import socket
import RSA_l
import config
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

LOCAL_RSA = config.LOCAL_RSA

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000 
    
    if LOCAL_RSA:
        key = RSA_l.generateKeys()
        private_key = [key[1], key[2]]
        public_key = [key[0], key[2]]
    else:
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together
    print("Server is listening on port " + str(port))
    server_socket.listen(1)

    conn, address = server_socket.accept()  # accept new connection
    

    hello = conn.recv(1024).decode()
    print("Connection from: " + str(address))
    print("Client says: " + hello)

    conn.send(b'HELLO RSA-AES-256-GCM')

    if LOCAL_RSA:
        conn.send(bytes(str(public_key[0]) + ',' + str(public_key[1]), 'utf-8'))
    else:
        conn.send(public_key.export_key())  # send the public key to the client

    encrypted_key = conn.recv(4096)  # receive the encrypted AES key from the client

    if LOCAL_RSA:
        # convert received ciphertext bytes -> int, decrypt with local RSA, convert back to 32-byte AES key
        encrypted_int = int.from_bytes(encrypted_key, byteorder='big')
        aes_key_int = RSA_l.decrypt(encrypted_int, private_key[0], private_key[1])
        aes_key = aes_key_int.to_bytes(32, byteorder='big')  # AES-256 key size = 32 bytes
    else:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)  # decrypt the AES key

    filename = conn.recv(1024).decode()
    print(f"Client requested file: {filename}")
    with open(filename, "rb") as f:
        file_data = f.read()

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    print('Ciphertext: ', ciphertext)
    conn.send(cipher.nonce)
    conn.send(tag)
    conn.send(ciphertext)

    conn.close()
    server_socket.close()


if __name__ == '__main__':
    server_program()