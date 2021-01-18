#!/usr/bin/env python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import random
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256
from tkinter import *
import time

# this is the thread used to get the message from the server
def receive(socket):
    result = login_system(socket)
    while result == 2:
        result = login_system(socket)
    if result == 0:
        return
    while True:
        try:
            get_and_print(socket)
        except OSError:  # Possibly client has left the chat.
            print(OSError)
            return

#this is the thread used to send the message the user tpye to the server
def send(event=None):  # event is passed by binders.
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    if msg:
        send_message(msg,client_socket)
        if msg == "{quit}":
            client_socket.close()
            top.quit()

def on_closing(event=None):
    exit()
#this is used to genrate the AES key and iv 
def generate_key(client):
    primes = [i for i in range(500000,700000) if isPrime(i)]
    
    #generate the g for the key exchange
    g = random.randint(1000,2000)
    client.sendall(bytes(str(g),"utf8"))
    
    #get the p from the server
    p = client.recv(BUFSIZ).decode("utf8")
    p = int(p)
    
    #get the prime number
    prime_b = random.choice(primes)
    
    #get the g^a mod p from the server
    half_key = client.recv(BUFSIZ).decode("utf8")
    half_key = int(half_key)
    
    # calculate g^b mod p
    half_key2 = pow(g,prime_b,p)
    client.sendall(bytes(str(half_key2),"utf8"))
    
    session_key = pow(half_key,prime_b,p)
    
    return session_key

#check is a number a prime number 
def isPrime(num):
    for i in range(2,int(num**0.5)+1):
        if ( num % i  == 0) and ( i != num ):
            return False
    return True   
    
# padding the key if they are not 16 bytes long or more than 16 bytes
def padding(string):
    temp = str(string)
    if len(temp) < 16:
        for i in range(0,16-len(temp)):
            temp+='0';
    elif len(temp) > 16:
        temp = temp[0:16]
    return temp 
    
#AES encryption
def AES_encrypt(k1,string,iv):
    #we assume the k1 is int and str is not bytes
    str1 = bytes(string,"utf8")
    key = bytes(k1,"utf8")
    IV = bytes(iv,"utf8")
    cipher = AES.new(key, AES.MODE_CFB,IV)
    ciphertext = cipher.encrypt(str1)
    return ciphertext
    
# AES decryption 
def AES_decrypt(k1,string,iv):
    key = bytes(k1,"utf8")
    IV = bytes(iv,"utf8")
    decipher = AES.new(key, AES.MODE_CFB,IV)
    plaintext = decipher.decrypt(string).decode("utf8")
    return plaintext

# the function used to sign the message send 
def signer(message):
    hash = SHA256.new()
    hash.update(message.encode())
    signer = PKCS1_v1_5.new(rsa)
    signature = signer.sign(hash)
    return str(signature)
   
# function used to verify the message received 
def verifier(message,signature):
    hash = SHA256.new()
    hash.update(message.encode())
    ver = PKCS1_v1_5.new(rsa1)
    try:
        ver.verify(hash,signature)
    except:
        print("message corrupted!")
        return False
    return True

# this is the routine used to send the message to the server
def send_message(message,client):
    client.sendall(AES_encrypt(AES_key,message,iv))
    time.sleep(0.01)
    signature = signer(message)
    client.sendall(AES_encrypt(AES_key,signature,iv))
    return

# this is the routine used to get the message from the server 
def get_message(client): 
    message = AES_decrypt(AES_key,client.recv(BUFSIZ),iv)
    signture = AES_decrypt(AES_key,client.recv(BUFSIZ),iv)
    if verifier(message,signture) == True:
        print("verify success")
        return message
    else:
        print("verify fail")
        return ""

'''
0 = exit
1 = success 
2 = fail
'''
# this is the login system
def login_system(socket):
    message = get_and_print(socket)
    message = get_and_print(socket)
    if message == "Please input your user name": 
        get_and_print(socket)
        valid = get_and_print(socket)
        if valid == "Authorized":
            print(valid)
            return 1
        else:
            print(valid)
            return 2
    elif message == "Please input the user name":
        message = get_and_print(socket)
        message = get_and_print(socket)
        valid = get_and_print(socket)
        if valid == "The password is not the same":
            return 2
        elif valid == "User name already existed":
            return 2
        elif valid == "Password is not valid":
            return 2
        else:
            return 1
    else:
        return 0
    return

#get the server message and print on the chatroom    
def get_and_print(socket):
    try:
        msg = get_message(socket)
        msg_list.insert(tkinter.END, msg)
    except OSError: 
        exit()
    return msg

#get the user input and then send to the server
def get_from_user():
    msg = ""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    while len(msg)==0:
        msg_list.insert(tkinter.END,"Please inter something!")
        msg = my_msg.get()
        my_msg.set("")
    msg_list.insert(tkinter.END,msg)    
    return msg
            
top = tkinter.Tk()
top.title("Instant messaging chatroom")
messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  
my_msg.set("")
scrollbar = tkinter.Scrollbar(messages_frame)  
msg_list = tkinter.Listbox(messages_frame, height=30, width=100, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()
entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()
top.protocol("WM_DELETE_WINDOW", on_closing)

# get the socket information
HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

BUFSIZ = 4096
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
AES_key = generate_key(client_socket)
iv = generate_key(client_socket)
AES_key = padding(AES_key)
iv = padding(iv)

#generate RSA key pair
rsa = RSA.generate(2048,Random.new().read)

#send the RSA public key to server
message = AES_encrypt(AES_key,str(rsa.e),iv)
client_socket.sendall(message)

#send the RSA public modular to server
message = AES_encrypt(AES_key,str(rsa.n),iv)
client_socket.sendall(message)

#receive the server public key
server_public = int(AES_decrypt(AES_key,client_socket.recv(BUFSIZ),iv))

#receive the server modular
server_modular = int(AES_decrypt(AES_key,client_socket.recv(BUFSIZ),iv))
rsa1 = RSA.construct((server_modular,server_public))
receive_thread = Thread(target=receive,args=(client_socket,))
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.

