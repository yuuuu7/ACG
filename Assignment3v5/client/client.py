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
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

global host, port
host = socket.gethostname()
port = 8888 # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"
key = os.urandom(32)

# function to encrypt the data using AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC, os.urandom(AES.block_size))
    data = Padding.pad(data, AES.block_size)
    ciphertext = cipher.encrypt(data)
    return ciphertext

# Request for today's menu from the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )
    data = my_socket.recv(4096)
    menu_file = open(menu_file,"wb")
    menu_file.write( data)
    menu_file.close()
    my_socket.close()
    print('Menu today received from server')

# Sending end-of-day sales report to the server
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



