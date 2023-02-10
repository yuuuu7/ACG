Step by Step Guide:

1. Open two terminals (or you can open 1 and split them into 2 by clicking on the little "Split" icon on the right column of the terminal (Hover over the terminals on the right column))

2. CD to Assignment3v5 -> client and Assignment3v5 -> server on the seperate terminals

3. Type 'python .\server.py'
 3.1  You should see:

	   a.   Socket Created
      b.   Socket bind complete
      c.   Socket now listening

   	You have successfully started the server and is listening for connections

4. Type 'python .\client.py' 
   4.1  You should see (Client):

	   [CERT] Received Server's Certificate

      [CERT] Verifying the incoming Client Certificate...
      [CERT] Server Certificate presented is valid

      [CERT] Sent Client Certificate over to the Server...

      [PKI] Received the Server's public key
      [PKI] Sent Public Key to the Server

      [AES] Received Shared AES Session Key.

      *A Menu should pop up at the bottom if the connection was successful*

   4.2  You should see (Server):
   
         Accepting connection from 192.168.14.1:39642


         [CERT] Server's Certificate has been sent over to the client successfully!
         [CERT] Verifying the incoming Client Certificate...

         [CERT] The Client's Certificate is Valid

         [PKI] Sent Server Public Key over to client
         [PKI] Received the Client's public key

         [AES] Generated Shared-Session-Key...

         [AES] Successfully sent AES Session Key to Client

         Client Verified!
         Establishing connection with 192.168.14.1:39643

5. Client directory should contain:
      client.py
      client_cert.crt
      server_cert.crt
      client_priv.pem
      day_end.csv
      RSA_Keypair_gen.py
      TEST_enc_dec_menu.py:
            - Used only to TEST the encryption and decryption of the received 'menu.csv' file using the Client's Private and Public keys. 
            - By running 'python .\TEST_enc_dec_menu.py'
            - Used to show that data is encrypted at rest using the receiver's Public key and can only be decrypted by corresponding Private key.

6. Server directory should contain:
      server.py
      client_cert.crt
      server_cert.crt
      server_priv.pem
      day_end.csv
      RSA_Keypair_gen.py
      TEST_enc_dec_day_end.py:
            - Used only to TEST the encryption and decryption of the test file received 'test_dec_enc_day_end.txt' file using the Server's Private and Public keys. 
            - By running 'python .\TEST_enc_dec_menu.py'
            - Used to show that data is encrypted at rest using the receiver's Public key and can only be decrypted by corresponding Private key.

7. Enter '1' and you should see (Client):

   [INTEGRITY] Menu Today Received. File contents have not been altered, Data did indeed come from Server.

8. Enter '2' and you should see:

   Client:
      Sale of the day sent to server

   Server:
      [INTEGRITY] day-end Received. File contents have not been altered, Data did indeed come from Client.

9. Enter '3' and you should exit out of client.py.



