from Crypto.Cipher import AES
from pwnlib.tubes.remote import remote

from Exercises.basics.servers.myconfig import *

BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2*BLOCK_SIZE


server = remote(HOST, PORT)

start_str = "This is what I received: "

msg = b"Hello World!"
print("Sending: "+str(msg))
server.send(msg)

ciphertext = server.recv(1024)
ciphertext = ciphertext.decode().strip()
print(ciphertext)

server.close()