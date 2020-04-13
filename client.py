import socket, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def AES_encrypt(session_key, plain_text, iv):
    encryptor = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(b'idk what this is')
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()
    return (cipher_text, encryptor.tag)

def AES_decrypt(session_key, cipher_text, iv, tag):
    decryptor = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(b'idk what this is')
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    return plain_text

HOST = '192.168.0.14'
PORT = 8000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
try:
    message = b'httpRequest'
    sock.sendall(message)
    server_key = sock.recv(1024)
    server_pub_key = load_pem_public_key(server_key, backend=default_backend())
    if server_key:
        session_key = os.urandom(32)
        iv = os.urandom(12)
        enc_session_key = server_pub_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #print("Encrypted session key: ")
        #print(enc_session_key)
        sock.send(enc_session_key)
        ack = sock.recv(1024)
        if ack:
            sock.send(iv)
            encrypted_data = sock.recv(1024)
            if encrypted_data:
                sock.sendall(b'ack')
                tag = sock.recv(1024)
                if tag:
                    #print(encrypted_data)
                    print(AES_decrypt(session_key, encrypted_data, iv, tag))
                    ackmsg = b'wow i am stupid'
                    ack, acktag = AES_encrypt(session_key, ackmsg, iv)
                    sock.sendall(ack)
                    sock.recv(1024)
                    sock.sendall(acktag)
                    #print(encrypted_data)

                    while True:
                        message = sock.recv(1024)
                        sock.sendall(b'ack')
                        new_tag = sock.recv(1024)
                        print()
                        print("Message from server:")
                        print(message)
                        message = AES_decrypt(session_key, message, iv, new_tag)
                        print(message.decode('utf-8'))
                        print()
                        response = input("Type message to send:\n")
                        response, new_tag = AES_encrypt(session_key, response.encode('utf-8'), iv)
                        sock.sendall(response)
                        sock.recv(1024)
                        sock.sendall(new_tag)
finally:
    print("Closing socket")
    sock.close()

