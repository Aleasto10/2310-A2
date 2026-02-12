import socket
import os
from Crypto.Cipher import AES


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    
    key = b'Sixteen byte key'  # AES key must be either 16, 24, or 32 bytes long
    nonce = b'RandomNonce1234' 

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))
        try:
            with open(data, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            conn.send(b"File not found")
        encrypted = cipher.encrypt(data)
        conn.sendall(encrypted)  # send data to the client
        conn.close()  # close the connection


if __name__ == '__main__':
    server_program()