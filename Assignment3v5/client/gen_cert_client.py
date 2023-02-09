from Cryptodome.PublicKey import RSA
import Cryptodome.Cipher.AES as AES
from cryptography import x509 
from cryptography.x509.oid import NameOID
from Cryptodome.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import datetime, socket, sys, time
from Cryptodome.Cipher import PKCS1_OAEP


private_key = "client_priv.pem" 
cert_name = "client_cert.crt" 
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

with open("client_priv.pem", "rb") as f:
    private_key = RSA.import_key(f.read(), passphrase="client")
    public_key = private_key.publickey().export_key()

def cert_gen():
    builder = x509.CertificateBuilder() 
    builder = builder.subject_name(x509.Name([ 
        x509.NameAttribute(NameOID.COMMON_NAME, u"Server 2504"), 
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"), 
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Singapore Polytechnic"), 
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"DISM/FT/1B/02"), 
    ])) 
    builder = builder.issuer_name(x509.Name([ 
    x509.NameAttribute(NameOID.COMMON_NAME, u"Client 2504"), 
    ])) 
    builder = builder.public_key(private_key.public_key()) 
    builder = builder.serial_number(x509.random_serial_number()) 
    builder = builder.not_valid_before(datetime.datetime.utcnow()) 
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) 
    builder = builder.add_extension( 
        x509.SubjectAlternativeName([x509.DNSName(u"Server.local")]), 
        critical=False 
    ) 
    certificate = builder.sign( 
        private_key=private_key, algorithm=hashes.SHA256(), 
        backend=default_backend() 
    ) 
    with open(cert_name, "wb") as cert_file: 
        cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))


def verify_server_cert(x):
    with open("server_cert.crt", "rb") as f:
        server_cert_data = f.read()
        correct_server_cert = x509.load_pem_x509_certificate(server_cert_data, default_backend())
    try:
        server_cert = x509.load_pem_x509_certificate(x, default_backend())
        server_cert.public_key().verify(
            server_cert.signature,
            correct_server_cert.tbs_certificate_bytes,
            PKCS1v15(),
            server_cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False

def verify_signature(file_content, signature):
    public_key = RSA.import_key(server_public)
    hashed_file_data = SHA256.new(file_content)

    # Verify the signature using the public key and the pkcs1_15 scheme
    try:
        pkcs1_15.new(public_key).verify(hashed_file_data, signature)
        return True
    except Exception:
        return False


def decrypt_aes(key, file_contents):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(file_contents)
    return plaintext


def gen_digital_signature(file_contents, passphrase: str):
        # Open the file and read its contents
        with open("client_priv.pem", 'rb') as f:
            private_key = f.read()

        # Create an RSA object from the private key
        client_private_key = RSA.import_key(private_key, passphrase.encode())

        # Create a SHA256 hash of the message
        hashed_file_data = SHA256.new(file_contents)

        # Sign the hash using the private key and the pkcs1_15 signing scheme
        signed_hashed_file = pkcs1_15.new(client_private_key).sign(hashed_file_data)

        return signed_hashed_file

def decrypt_message(ciphertext):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

host = socket.gethostname()
port = 8888

validated = False
while validated == False:
    server_address = (host, 8888)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)

    try:
        server_public_key = sock.recv(4096)
        server_public = server_public_key.decode()
        print("You have received the Server's public key!")
    except:
        print("An Error has Occured while trying to receive the Public Key.")

    try:
        sock.sendall(public_key)
        print("Successfully sent your Public Key to the Server!")
    except:
        print("An Error Occured during the sending of your Public Key to the Server.")
        sys.exit()

    try:
        incoming_server_cert_data = sock.recv(4096)
        print("Server's Certificate received")
        print("Verifying the incoming Server Certificate...")
        if verify_server_cert(incoming_server_cert_data):
            print("The Incoming Server Certificate presented is valid")
        else:
            print("The Incoming Server Certificate presented is not valid")
            sys.exit()
    except:
        print("Error")
        sys.exit()

    try:
        with open("client_cert.crt", "rb") as file:
            cert_data = file.read()
        sock.sendall(cert_data)
        print("Client's Certificate has been sent over to the Server successfully!")

    except:
        print("An Error occured while sending your Certificate to the client.")
        sys.exit()

    try:
        AES_key = sock.recv(4096)
        dec_aes_key = decrypt_message(AES_key)
        aes_session_key = dec_aes_key
        print(aes_session_key)
        print("Successfully received Shared AES Session Key.")
    except:
        print("Error occured while trying to receive the Session Key.")
    
    validated = True

    if validated == True:
        while True:
            print("\n1. Get the menu of the day\n2. Send day_end to server\n3. Quit")
            user_input = input("\n>>")
            if user_input == '1':
                sock.sendall(cmd_GET_MENU)
                incoming_data = sock.recv(4096)
                incoming_data = incoming_data.split(b'||')

                enc_original_data = incoming_data[0]
                original_data = decrypt_aes(aes_session_key, enc_original_data)
                signed_hash_data = incoming_data[1]

                if verify_signature(original_data, signed_hash_data):
                    print("File contents have not been altered and Data did indeed come from Server")
                    menu_file = open('menu.csv',"wb")
                    menu_file.write(original_data)
                    menu_file.close()
                    sock.close()
                    print('Menu today received from server')
                    sock.close()
                else:
                    print("Invalid Signature. File contents are either altered or sent by a third party. File was not saved.")
                    sys.exit()
                
            elif user_input == '2':
                sock.sendall(cmd_END_DAY)
                try:
                    day_end_outgoing = open(return_file,"rb")
                except:
                    print("file not found : " + return_file)
                    sys.exit(0)
                file_bytes = day_end_outgoing.read(1024)
                sent_bytes=b''
                while file_bytes != b'': 
                    sock.send(file_bytes)
                    sent_bytes+=file_bytes
                    file_bytes = day_end_outgoing.read(1024) # read next block from file
                signed_day_end = gen_digital_signature(sent_bytes, 'client')
                sock.send(signed_day_end)
                day_end_outgoing.close()
                sock.close()
                print('Sale of the day sent to server')
            elif user_input == '3':
                sock.close()
                sys.exit()







