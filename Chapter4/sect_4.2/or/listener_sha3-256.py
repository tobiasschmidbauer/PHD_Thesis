from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket
import sys
import hashlib
import logging



def print_and_accept(pkt):
    global current_hash
    submitted_hash = ''
    next_hash = '' 
    packet = IP(pkt.get_payload())
    pkt.drop()

    try:
        submitted_hash = packet[Raw].load
        next_hash = hashlib.sha3_256(submitted_hash).hexdigest()
    except IndexError as error:
        logging.log(error)

    print(current_hash)
    print(next_hash)

    if next_hash == current_hash:
        current_hash = (packet[Raw].load).decode('utf-8')

        #packet[IP].dst = packet[IP].src
        #packet[IP].src = "192.168.0.40"
        packet[IP].dst = "192.168.0.10" 
        packet[IP].src = "192.168.0.20"
        packet[TCP].dport = packet[TCP].sport
        packet[TCP].sport = 42424
        packet[TCP].seq = packet[TCP].ack
        packet[TCP].ack = packet[TCP].seq
        packet[TCP].flags = 'A''P''F'

        packet.show2()

        #send(IP(dst=packet[IP].src) / TCP(sport =42424 ,dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq + 1, flags='A''P''F'))
        send(packet)
    else:
        print("wrong hash")





if __name__ == '__main__':
    global current_hash

    hashfile = "start_sha3-256"
    file = open(hashfile,'r')
    current_hash = file.readline()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
