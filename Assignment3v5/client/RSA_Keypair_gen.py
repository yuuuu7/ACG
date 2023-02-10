from Crypto.PublicKey import RSA

key = RSA.generate(2048) 
passphrase = b"client" 
private_key = key.export_key(pkcs=8, protection="scryptAndAES128-CBC", passphrase=passphrase) 
with open("client_priv.pem", "wb") as f: 
    f.write(private_key) 
public_key = key.publickey().export_key()