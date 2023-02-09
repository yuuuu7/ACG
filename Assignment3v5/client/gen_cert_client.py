from Cryptodome.PublicKey import RSA
from cryptography import x509 
from cryptography.x509.oid import NameOID 
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import datetime, socket, sys, time
from Cryptodome.Cipher import PKCS1_OAEP


private_key = "client_priv.pem" 
cert_name = "client_cert.crt" 

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

with open(private_key, "rb") as key_file: 
    private_key = serialization.load_pem_private_key( 
    key_file.read(), 
    password=b"client", 
    backend=default_backend() 
) 


public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

host = socket.gethostname()

validated = False
while validated == False:
    server_address = (host, 8888)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)

    try:
        server_public_pem = sock.recv(4096)
        server_public_key = serialization.load_pem_public_key(
        server_public_pem,
        backend=default_backend()
        )
        print("You have received the Server's public key!")
    except:
        print("An Error has Occured while trying to receive the Public Key.")

    try:
        sock.sendall(public_pem)
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
    
    validated = True
    break
    
if validated == True:
    print("\nSuccessfully verified identities of Server and Client! Establishing a connection with the server...")
    time.sleep(0.4)
    server_address = (host, 8888)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    input("Enter to break connection...")
    sys.exit()






