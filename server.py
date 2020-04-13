import socket, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
pub_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

HOST = '192.168.0.14'
PORT =  8000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
while True:
    conn, client_addr = sock.accept()
    try:
        print("Connection from: " ,client_addr)
        while True:
            data = conn.recv(1024)
            if data:
                conn.sendall(pub_key_bytes)
                enc_session_key = conn.recv(1024)
                conn.sendall(b'ack')
                iv = conn.recv(1024)
                if enc_session_key and iv:
                    session_key = private_key.decrypt(
                        enc_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    #iv = os.urandom(16)
                    plain_text = b'Secure communication channel established...'
                    
                    ct, tag = AES_encrypt(session_key, plain_text, iv)
    
                    conn.sendall(ct)
                    ack = conn.recv(1024)
                    if ack:
                        conn.sendall(tag)

                        while True:
                            message = conn.recv(1024)
                            conn.sendall(b'ack')
                            new_tag = conn.recv(1024)
                            print()
                            print("Message from client:")
                            print(message)
                            message = AES_decrypt(session_key, message, iv, new_tag)
                            print(message.decode('utf-8'))
                            print()
                            response = input("Type message to send:\n")
                            enc_response, new_tag = AES_encrypt(session_key, response.encode('utf-8'), iv)
                            conn.sendall(enc_response)
                            conn.recv(1024)
                            conn.sendall(new_tag)
                            

            else:
                break
    finally:
        conn.close()


