import Cryptodome.Cipher.AES as AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography import x509 
from cryptography.x509.oid import NameOID 
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import datetime, sys
from Cryptodome.Cipher import PKCS1_OAEP
from threading import Thread    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose

import ssl
import os

with open("server_priv.pem", "rb") as f:
    private_key = RSA.import_key(f.read(), passphrase="server")
    public_key = private_key.publickey().export_key()

def verify_signature(file_content, signature):
    public_key = RSA.import_key(client_public)
    hashed_file_data = SHA256.new(file_content)

    # Verify the signature using the public key and the pkcs1_15 scheme
    try:
        pkcs1_15.new(public_key).verify(hashed_file_data, signature)
        return True
    except Exception:
        print("Error has occured")

def gen_digital_signature(file_contents, passphrase: str):
        # Open the file and read its contents
        with open("server_priv.pem", 'rb') as f:
            private_key = f.read()

        # Create an RSA object from the private key
        server_private_key = RSA.import_key(private_key, passphrase.encode())

        # Create a SHA256 hash of the message
        hashed_file_data = SHA256.new(file_contents)

        # Sign the hash using the private key and the pkcs1_15 signing scheme
        signed_hashed_file = pkcs1_15.new(server_private_key).sign(hashed_file_data)

        return signed_hashed_file



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

def encrypt_message(message):
    global client_public
    client_public = RSA.import_key(client_public)
    cipher_rsa = PKCS1_OAEP.new(client_public)
    return cipher_rsa.encrypt(message)
    

def encrypt_aes(key, file_contents):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(file_contents)
    return ciphertext

def process_connection(conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    menu_file = open(default_menu,"rb")
                except:
                    print("file not found : " + default_menu)
                    sys.exit(0)
                while True:
                    with open(default_menu, 'rb') as f:
                        menu_file_contents = f.read()
                    if menu_file_contents == b'':
                        break
                    #insert encrypted file contents here later
                    gen_digital_signature(menu_file_contents, 'server')
                    #items_to_be_sent = menu_file_contents + b"||" + signed_menu
                    #print(menu_file_contents + b"||" + signed_menu)
                    #conn.sendall(items_to_be_sent)
                    #conn.send(encrypted_hash_menu)
                #menu_file.close()
                #print("Menu and A Hashed + Signed Menu has been sent") 
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)  
                blk_count = blk_count + 1
        

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"
private_key = "server_priv.pem" 
cert_name = "server_cert.crt" 

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
    AES_session_key = os.urandom(32) # generate a 32-byte key for AES-256

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
                conn.sendall(public_key)
                print("You have sent Client your Public Key!")
                time.sleep(0.4)
            except:
                print("An Error has Occured while sending the Public Key.")
                sys.exit()

            try:
                global client_public
                client_public_key = conn.recv(4096)
                client_public = client_public_key.decode()
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
            
            try:
                print(AES_session_key)
                enc_aes_key = encrypt_message(AES_session_key)
                conn.sendall(enc_aes_key)
                print("Successfully sent the new AES Session Key to Client")
            except:
                print("Error in sending AES Key over to Client.")
            
        
            validated = True

            if validated == True:
                while True:
                    print("\nClient Verified!")
                    print('Establishing connection with ' + ip + ':' + port + "\n")
                    blk_count = 0
                    net_bytes = conn.recv(4096)
                    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
                    while net_bytes != b'':
                        if blk_count == 0: #  1st block
                            usr_cmd = net_bytes[0:15].decode("utf8").strip()
                            if cmd_GET_MENU in usr_cmd: # ask for menu
                                try:
                                    menu_file = open(default_menu,"rb")
                                except:
                                    print("file not found : " + default_menu)
                                    sys.exit(0)
                                while True:
                                    with open(default_menu, 'rb') as f:
                                        menu_file_contents = f.read()
                                    if menu_file_contents == b'':
                                        break
                                    #insert encrypted file contents here later
                                    signed_menu = gen_digital_signature(menu_file_contents, 'server')
                                    enc_data = encrypt_aes(AES_session_key ,menu_file_contents)
                                    print(enc_data)
                                    items_to_be_sent = enc_data + b"||" + signed_menu
                                    conn.sendall(items_to_be_sent)
                                    menu_file.close()
                                    break
                            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                                now = datetime.datetime.now()
                                filename = default_save_base +  ip + "-" + now.strftime("%Y-%m-%d_%H%M")                
                                dest_file = open(filename,"wb")

                                # Hints: net_bytes may be an encrypted block of message.
                                # e.g. plain_bytes = my_decrypt(net_bytes)
                                net_bytes = conn.recv(4096)
                                signature = conn.recv(4096)
                                if verify_signature(net_bytes, signature):
                                    print("File contents have not been altered and Data did indeed come from Client")
                                    dest_file.write(net_bytes) # remove the CLOSING header    
                                    blk_count = blk_count + 1
                                else:
                                    print("Invalid Signature. File contents are either altered or sent by a third party. File was not saved.")
                                    sys.exit()
    
                        # Hints: net_bytes may be an encrypted block of message.
                        # e.g. plain_bytes = my_decrypt(net_bytes
                        input('Enter to close server...')
                        sys.exit()

            else:
                sys.exit()
            


    
            
    except:
        pass
    soc.close()
    return

start_server()