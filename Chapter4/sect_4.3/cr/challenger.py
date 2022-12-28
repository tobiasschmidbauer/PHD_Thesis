import hashlib
import base64
import sys
import os
import time
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import socket


def get_nonce():
    return str('n.' + str(uuid.uuid4()))

def respond(socket, data):
    if isinstance(data,str):
        socket.send(bytes(data,'utf-8'))
    else:
        socket.send(bytes(data))
    return


## Legitimate Synchronous
def ls(clientsocket):
    global prev_nonce
    while True:
        payload= clientsocket.recv(400).decode('utf-8')


        if payload == "request":
            prev_nonce = get_nonce()
       
            respond(clientsocket, prev_nonce)

        elif payload.startswith("t."):
            pw=prev_nonce + "mysecretpassword"
            token = 't.' + str(hashlib.sha3_512(pw.encode('utf-8')).hexdigest())
            if token == payload:

                respond(clientsocket, 'authenticated')
            else:
                respond(clientsocket, 'declined')
        else:
            print()
    return

## Legitimate Asynchronous
def la(clientsocket):
    global pub_prover
    global priv_challenger
    global prev_nonce
    while True:
        payload= clientsocket.recv(800).decode('utf-8')



        if payload == 'request':
            prev_nonce = get_nonce().encode('utf-8')
            token_challenger = pub_prover.encrypt(
                    prev_nonce,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            data=base64.b64encode(token_challenger)

            respond(clientsocket, data)


        else:
            token_prover= base64.b64decode(payload)
            nonce = priv_challenger.decrypt(
                    token_prover,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        
            if nonce == prev_nonce:
                with open("covert_message.txt", 'a') as txt:
                    txt.write(nonce.decode('utf-8'))
                    txt.close()

                respond(clientsocket, 'authenticated')
            else:
                respond(clientsocket, 'declined')

## Covert Synchronous
def cs(clientsocket):
    global prev_nonce
    global alphabet
    global covert_message
    global loops
    global loop_num
    global transfercounter
    
    while True:
        payload= clientsocket.recv(400).decode('utf-8')


        if payload == "request":
            prev_nonce = get_nonce()
        
            respond(clientsocket, prev_nonce)

        elif payload.startswith("t."):
            curr_loop=1
            pw_base=prev_nonce + "mysecretpassword"
            for symbol in alphabet:
                pw= pw_base + symbol
                token = 't.' + str(hashlib.sha3_512(pw.encode('utf-8')).hexdigest())
                if token == payload:
                    if symbol != 'EOF':
                        covert_message.append(symbol)
                        transfercounter += 1
                        respond(clientsocket, 'authenticated')
                    else:
                        covert_message.append(symbol)
                        message=''.join(covert_message)
                        with open("covert_message.txt", 'w') as txt:
                            txt.write(message)
                            txt.close()
                        with open("total.txt", 'w') as total:
                            total.write(str(transfercounter)+'\n')
                            total.close()
                        respond(clientsocket, 'authenticated')
        else:
            respond(clientsocket, 'declined')


## Covert Asynchronous
def ca(clientsocket):
    global pub_prover
    global priv_challenger
    global prev_nonce
    global covert_message
    global loops
    global transfercounter

    while True:
        payload= clientsocket.recv(400).decode('utf-8')

        if payload == 'request':
            prev_nonce = get_nonce()

            secret_str = prev_nonce + ";" 
            secret = secret_str.encode('utf-8')
            token_challenger = pub_prover.encrypt(
                    secret,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            data=base64.b64encode(token_challenger)

            respond(clientsocket, data)


        else:
            token_prover= base64.b64decode(payload)
            decrypted = priv_challenger.decrypt(
                    token_prover,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            decrypted_str= decrypted.decode('utf-8')

            nonce = decrypted_str[0:len(prev_nonce)]
            hi = decrypted_str[(len(prev_nonce)+1):]
        ##write message? 
            if nonce == prev_nonce:
                with open("covert_message.txt", 'a') as txt:
                    txt.write(hi)
                    txt.close()

                respond(clientsocket, 'authenticated')
            else:
                respond(clientsocket, 'declined')


if __name__ == '__main__':
    ## Modes:
    # ls: legitimate synchronous
    # la: legitimate asynchronous
    # cs: covert synchronous
    # ca: covert asynchronous
    global len_prev_nonce     #ca
    global prev_nonce         #
    global alphabet           #
    global covert_message     #
    global pub_prover         #
    global priv_challenger    #
    global loops
    global transfercounter
    global loop_num
    global max_loops
    mode = sys.argv[1]   
    loops = []
    transfercounter = 0

    soc=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.bind(("192.168.3.29",10001))
    soc.listen(5)

    clientsocket, address =soc.accept()

    if mode == 'ls':
        ls(clientsocket)

    elif mode == 'la':

        with open("public_key_prover.pem", 'rb') as pub_keyfile:
            pub_prover= serialization.load_pem_public_key(
                pub_keyfile.read(),
                backend=default_backend()
                )

        with open("private_key_challenger.pem", 'rb') as priv_keyfile:
            priv_challenger= serialization.load_pem_private_key(
                priv_keyfile.read(),
                password=None,
                backend=default_backend()
                )
        la(clientsocket)

    elif mode == 'cs':
        loop_num=0
        alphabet_file =sys.argv[2]
        num = int(sys.argv[3])

        ## load alphabet
        covert_message = [] 
        if num == 1:
            with open(alphabet_file) as file:
                alphabet_raw = file.readlines()
                alphabet = []
                for line in alphabet_raw:
                    if line not in ['\n']:
                        if line not in [' \n']:
                            alphabet.append(line.rstrip())
                        else:
                            alphabet.append(' ')
                    else:
                        alphabet.append(line)
        elif num == 2:
            with open(alphabet_file) as file:
                alphabet_raw = file.readlines()
                alphabet = []
                sym1=''
                for line1 in alphabet_raw:
                    if line1 not in ['\n']:
                        if line1 not in [' \n']:
                            sym1=(line1.rstrip())
                        else:
                            sym1=' '
                    else:
                        sym1=line1
                    for line2 in alphabet_raw:
                        if line2 not in ['\n']:
                            if line2 not in [' \n']:
                                sym2=line2.rstrip()
                            else:
                                sym2=' '
                        else:
                            sym2= line2
                        alphabet.append(sym1+sym2)
        elif num == 3:
            with open(alphabet_file) as file:
                alphabet_raw = file.readlines()
                alphabet = []
                sym1=''
                sym2=''
                for line1 in alphabet_raw:
                    if line1 not in ['\n']:
                        if line1 not in [' \n']:
                            sym1=(line1.rstrip())
                        else:
                            sym1=' '
                    else:
                        sym1=line1

                    for line2 in alphabet_raw:
                        if line2 not in ['\n']:
                            if line2 not in [' \n']:
                                sym2=line2.rstrip()
                            else:
                                sym2=' '
                        else:
                            sym2= line2
                        for line3 in alphabet_raw:
                            if line3 not in ['\n']:
                                if line3 not in [' \n']:
                                    sym3=line3.rstrip()
                                else:
                                    sym3=' '
                            else:
                                sym3= line3
                            alphabet.append(sym1+sym2+sym3)

        elif num == 4:
            with open(alphabet_file) as file:
                alphabet_raw = file.readlines()
                alphabet = []
                sym1=''
                sym2=''
                sym3=''
                for line1 in alphabet_raw:
                    if line1 not in ['\n']:
                        if line1 not in [' \n']:
                            sym1=(line1.rstrip())
                        else:
                            sym1=' '
                    else:
                        sym1=line1

                    for line2 in alphabet_raw:
                        if line2 not in ['\n']:
                            if line2 not in [' \n']:
                                sym2=line2.rstrip()
                            else:
                                sym2=' '
                        else:
                            sym2= line2
                        for line3 in alphabet_raw:
                            if line3 not in ['\n']:
                                if line3 not in [' \n']:
                                    sym3=line3.rstrip()
                                else:
                                    sym3=' '
                            else:
                                sym3= line3
                            for line4 in alphabet_raw:
                                if line4 not in ['\n']:
                                    if line4 not in [' \n']:
                                        sym4=line4.rstrip()
                                    else:
                                        sym4=' '
                                else:
                                    sym4= line4
                                alphabet.append(sym1+sym2+sym3+sym4)


        else: exit(0)
        cs(clientsocket)


    elif mode == 'ca':

        with open("public_key_prover.pem", 'rb') as pub_keyfile:
            pub_prover= serialization.load_pem_public_key(
                pub_keyfile.read(),
                backend=default_backend()
                )

        with open("private_key_challenger.pem", 'rb') as priv_keyfile:
            priv_challenger= serialization.load_pem_private_key(
                priv_keyfile.read(),
                password=None,
                backend=default_backend()
                )
        with open("covert_message.txt", 'w') as txt:
            txt.write('')
            txt.close()
        ca(clientsocket)

    else:
        exit(1)
