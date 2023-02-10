from Cryptodome.PublicKey import RSA
import Cryptodome.Cipher.AES as AES
from cryptography import x509 
from cryptography.x509.oid import NameOID
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import datetime, socket, sys, time
from Cryptodome.Cipher import PKCS1_OAEP

with open("server_priv.pem", "rb") as f:
    private_key = RSA.import_key(f.read(), passphrase="server")
    public_key = private_key.publickey().export_key()

def encrypt_message(message):
    client_public = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(client_public)
    return cipher_rsa.encrypt(message)

def decrypt_message(ciphertext):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

try:    
    menu_file = open('test_dec_enc_day_end.txt',"rb").read()
    dec_file_contents = decrypt_message(menu_file)
    menu_file = open('test_dec_enc_day_end.txt',"wb")
    menu_file.write(dec_file_contents)
    menu_file.close()
except:
    menu_file = open('test_dec_enc_day_end.txt',"rb").read()
    enc_file_contents = encrypt_message(menu_file)
    menu_file = open('test_dec_enc_day_end.txt',"wb")
    menu_file.write(enc_file_contents)
    menu_file.close()