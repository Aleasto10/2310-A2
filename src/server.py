import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000 
    
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together
    server_socket.listen(1)

    conn, address = server_socket.accept()  # accept new connection
    

    hello = conn.recv(1024).decode()
    print("Connection from: " + str(address))
    print("Client says: " + hello)

    conn.send(b'HELLO RSA-AES-256-GCM')

    conn.send(public_key.export_key())  # send the public key to the client

    encrypted_key = conn.recv(4096)  # receive the encrypted AES key from the client
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)  # decrypt the AES key

    filename = conn.recv(1024).decode()
    with open(filename, "rb") as f:
        file_data = f.read()

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    conn.send(cipher.nonce)
    conn.send(tag)
    conn.send(ciphertext)

    conn.close()
    server_socket.close()


if __name__ == '__main__':
    server_program()