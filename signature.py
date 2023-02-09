from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

def signprivate():
    key = RSA.import_key(open("privatekey.pem").read())
    message = open("menu_today.txt", "rb").read()
    h = SHA256.new(message)
    signature = PKCS1_v1_5.new(key).sign(h)
    sig = open("private.sig","wb")
    sig.write(signature)
    print(signature) 
signprivate()

def signpublic():
    key = RSA.import_key(open("publickey.pem").read())
    message = open("menu_today.txt", "rb").read()
    h = SHA256.new(message)
    signature = PKCS1_v1_5.new(key).sign(h)
    sig = open("public.sig","wb")
    sig.write(signature)
    print(signature) 
signpublic()


signpublic()


signprivate()