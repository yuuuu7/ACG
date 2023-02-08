#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

import ssl
import os
global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server


def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return (cipher.nonce + ciphertext)

def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    src_file = open(default_menu,"rb")
                except:
                    print("file not found : " + default_menu)
                    sys.exit(0)
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break
                    '''openedFile = open(default_menu)
                    readFile = openedFile.read()
                    menu_hashed = hashlib.sha256(readFile.encode())
                    encrypted_hash_menu = encrypt_aes(key2, menu_hashed)'''
                    
                    encrypted_read_bytes = encrypt_aes(key, read_bytes)
                    conn.send(encrypted_read_bytes)
                    #conn.send(encrypted_hash_menu)
                src_file.close()
                print("Processed SENDING menu") 
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                encrypted_net_bytes = encrypt_aes(key, net_bytes[ len(cmd_END_DAY): ])
                dest_file.write( encrypted_net_bytes ) # remove the CLOSING header    
                blk_count = blk_count + 1
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            encrypted_net_bytes = encrypt_aes(key, net_bytes)
            dest_file.write(encrypted_net_bytes)
    # last block / empty block
    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done") 
    return

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + "ended")
    return

def start_server():
    global host, port
    # Generate the RSA keypair
    key = RSA.generate(2048) 

    # Export the private key
    private_key = key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=b"server") 
    with open("private.pem", "wb") as f: 
        f.write(private_key) 

    # Export the public key
    public_key = key.publickey().export_key()

    # Convert the RSA public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
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

    
    # Generate the RSA keypair
    key = RSA.generate(2048) 

    # Export the private key
    private_key = key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=b"server") 
    with open("private.pem", "wb") as f: 
        f.write(private_key) 

    # Export the public key
    public_key = key.publickey().export_key()

    # Load the public key as a RSA object
    public_key_rsa = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    # Convert the RSA public key to bytes
    public_key_bytes = public_key_rsa.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.send(public_key_bytes)

    # this will make an infinite loop needed for 
    # not reseting server for every client
    # this will make an infinite loop needed for 
    # not reseting server for every client
     # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        while True:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except:
                print("Terrible error!")
                traceback.print_exc()
    except:
        pass
    soc.close()
    return

'''private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SP"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"ACG"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACG Demo"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Client 2205513"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Our certificate will be valid for 10 years
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).sign(private_key, hashes.SHA256(), default_backend())

cert_pem = cert.public_bytes(serialization.Encoding.PEM)

with open("private_key.pem", "wb") as f:
    f.write(private_key_pem)    

with open("server_cert.crt", "wb") as cert_file: 
  cert_file.write(cert_pem)

start_server()'''
start_server()