#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client

import datetime
import sys # handle system error
import socket
import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


global host, port
host = socket.gethostname()
port = 8888 # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

def encrypt_data(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext

def initialize_keys(password: str): 
    try: 
        with open("private.pem", "rb") as f: 
            private_key = RSA.import_key(f.read(), passphrase=password.encode()) 
            private_enc = PKCS1_OAEP.new(private_key) 
    except: 
        print(f"Authenticity of private key could not be verified. Ensure that the key is correct.") 
        sys.exit()

''' # Generate a key pair for the client
key = RSA.generate(2048)
passphrase = b"client"
private_key = key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=passphrase)
with open("private.pem", "wb") as f:
    f.write(private_key)
public_key = key.publickey().export_key()

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

# Send the client's public key to the server
client_socket.send(public_key_bytes)

# Receive the server's public key bytes
server_public_key_bytes = client_socket.recv(4096)

# Load the server's public key
server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes,
    backend=default_backend()
)

# Save the server's public key to a file
with open("server_public.pem", 'wb') as f:
    f.write(server_public_key) '''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )
    data = my_socket.recv(4096)
    menu_file = open(menu_file,"wb")
    menu_file.write( data)
    menu_file.close()
    my_socket.close()
    print('Menu today received from server')
    my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
     out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
        file_bytes = out_file.read(1024)
        sent_bytes=b''
    while file_bytes != b'':
        encrypted_data = encrypt_data(file_bytes, key)
        my_socket.send(encrypted_data)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
        out_file.close()
        my_socket.close()
        print('Sale of the day sent to server')
        my_socket.close()


