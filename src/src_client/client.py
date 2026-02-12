import socket
from Crypto.Cipher import AES


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    key = b'Sixteen byte key'  # AES key must be either 16, 24, or 32 bytes long
    nonce = b'RandomNonce1234'  # The nonce must be the same as the one used by the server

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    file_bytes = b''

    file_request = 'data/example.txt'
    client_socket.send(file_request.encode())  # send file request

    with open('received_example.txt', 'wb') as f:
        print("Opened file")
        while True:
            print("Receiving data...")
            data = client_socket.recv(1024)
            print('Data=%s', (data))
            if not data:
                break
            file_bytes += data
        decrypted = cipher.decrypt(file_bytes)
        f.write(decrypted)
    print("File received successfully.")
    


if __name__ == '__main__':
    client_program()