from Cryptodome.PublicKey import RSA
from cryptography import x509 
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes 
import datetime, sys
from Cryptodome.Cipher import PKCS1_OAEP
from threading import Thread    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose
import Cryptodome.Cipher.AES as AES
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.x509.oid import NameOID 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

import ssl
import os

def initialize_keys(password: str): 
  try: 
   with open("private.pem", "rb") as f: 
    private_key = RSA.import_key(f.read(), passphrase=password.encode()) 
    private_enc = PKCS1_OAEP.new(private_key) 
  except: 
   print(f"Authenticity of private key could not be verified. Ensure that the key is correct.") 
   sys.exit()

def gen_cert():
    builder = x509.CertificateBuilder() 
    builder = builder.subject_name(x509.Name([ 
        x509.NameAttribute(NameOID.COMMON_NAME, u"Client 2504"), 
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"), 
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Singapore Polytechnic"), 
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"DISM/FT/1B/02"), 
    ])) 
    builder = builder.issuer_name(x509.Name([ 
    x509.NameAttribute(NameOID.COMMON_NAME, u"Server 2504"), 
    ])) 
    builder = builder.public_key(private_key.public_key()) 
    builder = builder.serial_number(x509.random_serial_number()) 
    builder = builder.not_valid_before(datetime.datetime.utcnow()) 
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) 
    builder = builder.add_extension( 
        x509.SubjectAlternativeName([x509.DNSName(u"Client.local")]), 
        critical=False 
    ) 
    certificate = builder.sign( 
        private_key=private_key, algorithm=hashes.SHA256(), 
        backend=default_backend() 
    ) 
    with open(cert_name, "wb") as cert_file: 
        cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
             # The port used by the server

def verify_client_cert(x):
    with open("client_cert.crt", "rb") as f:
        client_cert_data = f.read()
        correct_client_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())
    try:
        client_cert = x509.load_pem_x509_certificate(x, default_backend())
        client_cert.public_key().verify(
            client_cert.signature,
            correct_client_cert.tbs_certificate_bytes,
            PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False
        
        

private_key = "server_priv.pem" 
cert_name = "server_cert.crt" 
with open(private_key, "rb") as key_file: 
    private_key = serialization.load_pem_private_key( 
    key_file.read(), 
    password=b"server", 
    backend=default_backend() 
) 

host = socket.gethostname()
port = 8888
def start_server():
    global host, port
    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket and can accept 10 connection
    soc.listen(10)
    print('Socket now listening')

    # this will make an infinite loop needed for 
    # not reseting server for every client
    # this will make an infinite loop needed for 
    # not reseting server for every client
     # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        validated = False
        while validated == False:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port + "\n")

            try:
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                conn.sendall(public_pem)
                print("You have sent Client your Public Key!")
                time.sleep(0.4)
            except:
                print("An Error has Occured while sending the Public Key.")
                sys.exit()

            try:
                client_public_pem = conn.recv(4096)
                client_public_key = serialization.load_pem_public_key(
                client_public_pem,
                backend=default_backend()
                )
                print("You have received the Client's public key!")
                time.sleep(0.4)
            except:
                print("An Error has Occured while trying to receive the Public Key.")
                sys.exit()


            try:
                with open("server_cert.crt", "rb") as file:
                    server_cert_data = file.read()
                conn.sendall(server_cert_data)
                print("\nServer's Certificate has been sent over to the client successfully!")
            except:
                print("An Error has Occured while sending the Server Certificate.")
                sys.exit()

            try:
                incoming_client_cert_data = conn.recv(4096)
                print("\nClient's Certificate received")
                print("Verifying the incoming Client Certificate...")
                if verify_client_cert(incoming_client_cert_data):
                    print("The Client's Certificate is Valid")
                else:
                    print("The Client's certificate is invalid")
                    sys.exit()
            except:
                print("Error")
                sys.exit()
            
            validated = True
            
            if validated == True:
                while True:
                    conn, addr = soc.accept()
                    # assign ip and port
                    ip, port = str(addr[0]), str(addr[1])
                    print("\nClient Verified!")
                    print('Establishing connection with ' + ip + ':' + port + "\n")
                    input('Enter to close server...')
                    sys.exit()
            else:
                break
            


    
            
    except:
        pass
    soc.close()
    return

start_server()