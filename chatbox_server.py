#!/usr/bin/env python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import random
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256
import time

def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print(client)
        # this keys is the AES key.
        AES_key = get_session_key(client)
        
        #this is the initial vector for the AES
        iv = get_session_key(client)
        
        # padding the key and iv if they are not 16 bit long
        AES_key = padding(AES_key)
        iv = padding(iv)
        print("AES key ",AES_key)
        print("iv      ",iv)
        
        #save the AES and iv fpr this client
        AES_key_bank[client.getpeername()[1]] = AES_key
        iv_bank[client.getpeername()[1]] = iv
        
        #get the client public key  save it
        client_public = int(AES_decrypt(AES_key,client.recv(BUFSIZ),iv))
        print("client public key ",client_public)
        public_key_bank[client.getpeername()[1]] = client_public
       
        #get the client public key  save it
        client_modular = int(AES_decrypt(AES_key,client.recv(BUFSIZ),iv))
        print("client mudular ",client_modular)
        modular_bank[client.getpeername()[1]] = client_modular
        
        #send the RSA public key to client
        message = AES_encrypt(AES_key,str(rsa.e),iv)
        client.sendall(message)
        
        #send the public modular
        message = AES_encrypt(AES_key,str(rsa.n),iv)
        client.sendall(message)
        time.sleep(0.05)
        temp = log_in(client)
        while  temp == 1 :
            temp = log_in(client)
        if temp == 0:
            continue
        print("%s:%s has connected." % client_address)
        print("AES_KEY_BANK : ",AES_key_bank)
        print("IV BANK      : ",iv_bank)
        send_message("Greetings from the cave!",client)

        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()
        
# AES encryption 
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
    print("Received ciphertext from the client : ",string)
    key = bytes(k1,"utf8")
    IV = bytes(iv,"utf8")
    decipher = AES.new(key, AES.MODE_CFB,IV)
    plaintext = decipher.decrypt(string).decode("utf8")
    return plaintext

# used to exhcange and construct the AES key and iv    
def get_session_key(client):
    primes = [i for i in range(500000,700000) if isPrime(i)]
    
    #get commonly known g
    g = client.recv(BUFSIZ).decode("utf8")
    g = int(g)
        
    # pick a commonly known p
    p = random.randint(2**50,2**56)
    client.sendall(bytes(str(p),"utf8"))
                
    #get the prime number
    prime_a = random.choice(primes)
                
    #compute the half session key
    half_key = pow(g,prime_a,p)
                
    #send the g^a mod p to the client
    client.sendall(bytes(str(half_key),"utf8"))
                
    #get the prime b from the client
    prime_b = int(client.recv(BUFSIZ).decode("utf8"))
                
    #compute the session key for the server to the client.
    session_key = pow(prime_b,prime_a,p)
    
    return session_key
    
# padding the key if they are not 16 bytes long or more than 16 bytes    
def padding(string):
    temp = str(string)
    if len(temp) < 16:
        for i in range(0,16-len(temp)):
            temp+='0';
    elif len(temp) > 16:
        temp = temp[0:16]
    return temp

#thread used to handle the clients message and message distribution      
def handle_client(client):  # Takes client socket as argument.
    key = AES_key_bank[client.getpeername()[1]]
    iv = iv_bank[client.getpeername()[1]]
    name = find_name_bank(socket_user[client])
    if name == -1:
        send_message("Seems you havent set a name yet! Please input a name.",client)
        name =  get_message(client)
        update_name_bank((socket_user[client],name))
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    send_message(welcome,client)
    msg = "%s has joined the chat!" % name
    broadcast(msg)
    clients[client] = name
    while True:
        msg = get_message(client)
        if msg != "{quit}":
            broadcast(name+": "+msg)
        else:
            client.close()
            del clients[client]
            broadcast("%s has left the chat." % name)
            break

# send the message to all client in the network
def broadcast(msg):  
    #Broadcasts a message to all the clients.
    for sock in clients:
        send_message(msg,sock)

# check a number is a prime number 
def isPrime(num):
    for i in range(2,int(num**0.5)+1):
        if ( num % i  == 0) and ( i != num ):
            return False
    return True

# function used to sign the message with the private key   
def signer(message):
    hash = SHA256.new()
    hash.update(message.encode())
    signer = PKCS1_v1_5.new(rsa)
    signature = signer.sign(hash)
    return str(signature)

# function used to verify the message and the signature
def verifier(message, name,signature):
    rsa = RSA.construct((modular_bank[name],public_key_bank[name]))
    hash = SHA256.new()
    hash.update(message.encode())
    ver = PKCS1_v1_5.new(rsa)
    try:
        ver.verify(hash,signature)
    except:
        print("message corrupted!")
        return False
    return True

# the routine used to send the message to the client    
def send_message(message,client):
    print("Server sending the message          : ",message)
    key = AES_key_bank[client.getpeername()[1]]
    iv = iv_bank[client.getpeername()[1]]
    client.sendall(AES_encrypt(key,message,iv))
    time.sleep(0.01)
    signature = signer(message)
    client.sendall(AES_encrypt(key,signature,iv))
    return

# the routine used to get the message from the client
def get_message(client):
    key = AES_key_bank[client.getpeername()[1]]
    iv = iv_bank[client.getpeername()[1]]
    message = AES_decrypt(key,client.recv(BUFSIZ),iv)
    signture = AES_decrypt(key,client.recv(BUFSIZ),iv)
    if verifier(message,client.getpeername()[1],signture) == False:
        return ""
    return message

# the login routine for the client connection 
def log_in(socket):
    send_message("Do you have account? (Y/N) N for register and login, type any other for exit",socket)
    message = get_message(socket)
    if message == "Y":
        send_message("Please input your user name",socket)
        user_name = get_message(socket)
        send_message("Please input the password",socket)
        password1 = get_message(socket)
        user_hash = make_a_hash(user_name)
        if user_hash not in salty_dict:
            send_message("No such user",socket)
            return 1
        salt = salty_dict[user_hash]
        password = salt + password1
        password_hash = make_a_hash(password)
        result = check_identity((user_hash,password_hash))
        if result == True:
            send_message("Authorized",socket)
            socket_user[socket] = user_hash
            return 2
        else:
            send_message("Incorrect password or no such user!",socket)
            return 1
            
    elif message == "N":
        send_message("Please input the user name",socket)
        user_name = get_message(socket)
        send_message("Please input the password (must have length at least 8, have number, upper character, lower character",socket)
        password = get_message(socket)
        
        send_message("Please re-enter the  password",socket)
        password1 = get_message(socket)
        temp = make_a_hash(user_name)
        if password != password1:
            send_message("The password is not the same",socket)
            return 1
        elif temp in identity:
            send_message("User name already existed",socket)
            return 1
        elif check_password(password) == False:
            send_message("Password is not valid",socket)
            return 1
        else:
            user_hash = make_a_hash(user_name)
            salt = make_and_save_salt(user_hash)
            password1 = salt+ password
            password_hash = make_a_hash(password1)
            update_identity((user_hash,password_hash))
            identity[user_hash] = password_hash
            send_message("Registered and authorized",socket)
            socket_user[socket] = user_hash
            return 2
    else:
        send_message("Ending session! You can close the window now",socket)
        socket.close()
        return 0

# update the identity txt file with the newly added user
def update_identity(new_ident):
    file = open("identity.txt","a+")
    string = str(new_ident[0])+" "+str(new_ident[1])+"\n"
    file.write(string)
    file.close()
    return 

# check whatever the identity is correct
def check_identity(ident):
    if ident[0] in identity:
        if identity[ident[0]] == ident[1]:
            return True
    return False

# hash the message using SHA256
def make_a_hash(message):
    hash = SHA256.new()
    hash.update(message.encode())
    digest = hash.hexdigest()
    return digest

# check whatever the pw correct
def check_password(pw):
    if len(pw) < 8:
        return False
    if any(char.isdigit() for char in pw) == False:
        return False
    if any(char.isalpha() for char in pw) == False:
        return False
    if any(char.islower() for char in pw) == False:
        return False
    if any(char.isupper() for char in pw) == False:
        return False
    return True

# update the name bank with the new user and their name 
def update_name_bank(pair):
    file = open("name_bank.txt","a+")
    string = str(pair[0])+" "+str(pair[1])+"\n"
    file.write(string)
    file.close()
    return 

# find the name of the user if the user have no name then return -1    
def find_name_bank(user):
    if user in name_bank:
        return name_bank[user]
    else:
        return -1

# make a salt and save it externally together with the username hash
def make_and_save_salt(user_hash):
    salt = random.randint(1000,9999)
    salty_dict[user_hash] = str(salt)
    file = open("salty.txt","a+")
    temp = str(user_hash)+" "+str(salt)+"\n"
    file.write(temp)
    file.close()
    return str(salt)

# load the file content from outside to the program 
def get_file(filename):
    temp_dict = dict()
    try:
        file = open(filename,"r+")
    except:
        file = open(filename,"w+")
        file.close()
        return temp_dict
    line = file.readline()
    if line == '\n':
        file.close()
        return temp_dict
    while line:
        pair = line.split()
        temp_dict[pair[0]]=pair[1]
        line = file.readline()
    file.close()
    return temp_dict


#this stores the client socket
clients = {}
addresses = {}

# (user_name, password) 
# {
#    "gary":"12345",
#    "wing":"15348"
# }
identity = {}
identity.update(get_file("identity.txt"))
salty_dict ={}
salty_dict.update(get_file("salty.txt"))
AES_key_bank = {}
iv_bank = {}
modular_bank = {}
public_key_bank = {}
name_bank = dict()
name_bank.update(get_file("name_bank.txt"))
socket_user = {}

HOST = input("please enter the IP :")
PORT = input("please input the port number :")

PORT = int(PORT)
BUFSIZ = 4096
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)
rsa = RSA.generate(2048,Random.new().read)

if __name__ == "__main__":
    SERVER.listen(100)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
