import hashlib
import base64
from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import os
import time
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def respond(socket, data):
    if isinstance(data,str):
        socket.send(bytes(data,'utf-8'))
    else:
        socket.send(bytes(data))
    return


## Legitimate Synchronous
def ls(serversocket):
    global tokenfile
    respond(serversocket,'request')
    while True:
        payload=serversocket.recv(400).decode('utf-8')


        if payload.startswith('n.'):
            challenge = payload + "mysecretpassword"
            token = 't.' + str(hashlib.sha3_512(challenge.encode('utf-8')).hexdigest())
            open(tokenfile,'a').write(token[2:]+'\n')


            respond(serversocket, token)

        elif payload == "authenticated":
            respond(serversocket,'request')
        elif payload == "declined":
            respond(serversocket,'request')
        else:
            pass



## Legitimate Asynchronous
def la(serversocket):
    global tokenfile
    global pub_challenger
    global priv_prover
    respond(serversocket,'request')
    while True:
        payload=serversocket.recv(800).decode('utf-8')


        if payload == "authenticated":
            respond(serversocket,'request')
        elif payload == "declined":
            respond(serversocket,'request')

        else:
            token_challenger = base64.b64decode(payload)
            nonce= priv_prover.decrypt(
                    token_challenger,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            token_prover= pub_challenger.encrypt(
                    nonce,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            open(tokenfile,'a').write(str(base64.b64encode(token_prover))[2:-1]+'\n')

            data= base64.b64encode(token_prover)

            respond(serversocket, data)



## Covert Synchronous
def cs(serversocket):
    global tokenfile
    global covert_message
    global alphabet
    global idx_cm
    global chars_at_once
    respond(serversocket,'request')
    while True:
        payload=serversocket.recv(800).decode('utf-8')


        if payload.startswith('n.'):
            ## extend value at currend position in covert_message
            try:
                challenge = payload + "mysecretpassword" + ''.join(covert_message[idx_cm:idx_cm+chars_at_once])
            except:
                pass
            #print(covert_message[idx_cm])
            ## set index to next element
            idx_cm +=chars_at_once
            ## create token and encrypt element
            token = 't.' + str(hashlib.sha3_512(challenge.encode('utf-8')).hexdigest())
            open(tokenfile,'a').write(token[2:]+'\n')
            respond(serversocket, token)
    

        elif payload == "authenticated":
            respond(serversocket,'request')
        elif payload == "declined":
            idx_cm = idx_cm - 1
            respond(serversocket,'request')

        else:
            exit(2)


## Covert Asynchronous
def ca(serversocket):
    global tokenfile
    global covert_message
    global idx_cm
    global nr_chars
    global pub_challenger
    global priv_prover
    global msg_len
    respond(serversocket,'request')
    while True:
        payload=serversocket.recv(400).decode('utf-8')


        if payload == "authenticated":
            respond(serversocket,'request')
        elif payload == "declined":
            idx_cm = idx_cm - nr_chars - 1
            respond(serversocket,'request')

        else:
            token_challenger = base64.b64decode(payload)
            token= priv_prover.decrypt(
                    token_challenger,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            nonce = token.decode('utf-8')

            idx_ende = idx_cm + nr_chars
            hi = covert_message[idx_cm:idx_ende]
            secret_str = nonce + hi
            secret = secret_str.encode('utf-8')

            idx_cm = idx_ende

            token_prover= pub_challenger.encrypt(
                    secret,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            open(tokenfile,'a').write(str(base64.b64encode(token_prover))[2:-1]+'\n')
            data= base64.b64encode(token_prover)

            respond(serversocket, data)
            if idx_ende > msg_len: exit(0)



if __name__ == '__main__':
    ## Modes:
    # ls: legitimate synchronous
    # la: legitimate asynchronous
    # cs: covert synchronous
    # ca: covert asynchronous
    mode = sys.argv[1]
    global covert_message
    global alphabet
    global idx_cm
    global nr_chars
    global pub_challenger
    global priv_prover
    global msg_len
    global tokenfile
    global chars_at_once
    cm_num=3



    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect(("192.168.3.29",10001))


    if mode == 'ls':
        tokenfile=sys.argv[2]
        ls(soc)

    elif mode == 'la':
        tokenfile=sys.argv[2]
        with open("public_key_challenger.pem", 'rb') as pub_keyfile:
            pub_challenger= serialization.load_pem_public_key(
                pub_keyfile.read(),
                backend=default_backend()
                )

        with open("private_key_prover.pem", 'rb') as priv_keyfile:
            priv_prover= serialization.load_pem_private_key(
                priv_keyfile.read(),
                password=None,
                backend=default_backend()
                )
        la(soc)

    elif mode == 'cs':
        covert_file = sys.argv[2]
        alphabet_file =sys.argv[3]
        tokenfile=sys.argv[4]
        chars_at_once=int(sys.argv[5])


        ## load alphabet and split by line

        with open(alphabet_file) as file:
            alphabet_raw = file.readlines()
            alphabet = [] 
            for line in alphabet_raw:
                ## skip newline
                if line not in ['\n']:
                    ##skip blank
                    if line not in [' \n']:
                        alphabet.append(line.rstrip())
                    else:
                        alphabet.append(' ')
                else:
                    alphabet.append(line)
        
        #load covert message
        covert_message_complete=''
        i = 0
        while i < cm_num:
            i+=1
            covert_message_complete = covert_message_complete + open(covert_file, 'r').read()
        #covert_message_complete = open(covert_file, 'r').read()
        idx_covert_message = 0
        covert_message= [''] * len(covert_message_complete) *cm_num
        prev_chars = ''
        contains = 0
        #split covert message in a list of chars and codewords according to alphabet
        firstrun = 1
        for char in covert_message_complete:
            if firstrun == 0:
                prev_chars += char
                contains = 0
                for s in alphabet:
                    if s.startswith(prev_chars):
                        contains= 1
                if contains == 0:
                    covert_message[idx_covert_message] = prev_chars[:-1]
                    prev_chars = prev_chars[-1]
                    idx_covert_message +=1
                    
                elif contains == 1:
                    pass
                    

            else:
                firstrun = 0
                prev_chars += char
        idx_cm=0
        #print(covert_message)
        #exit(0)
        cs(soc)


    elif mode == 'ca':
        covert_file = sys.argv[2]
        nr_chars= int(sys.argv[3])
        tokenfile=sys.argv[4]

        idx_cm = 0
        covert_message=''
        i = 0
        while i < cm_num:
            i+=1
            covert_message = covert_message + open(covert_file, 'r').read()
        #covert_message = open(covert_file, 'r').read()
        msg_len= len(covert_message) * cm_num


        with open("public_key_challenger.pem", 'rb') as pub_keyfile:
            pub_challenger= serialization.load_pem_public_key(
                pub_keyfile.read(),
                backend=default_backend()
                )

        with open("private_key_prover.pem", 'rb') as priv_keyfile:
            priv_prover= serialization.load_pem_private_key(
                priv_keyfile.read(),
                password=None,
                backend=default_backend()
                )

        ca(soc)

    else:
        exit(1)
