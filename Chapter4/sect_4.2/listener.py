from scapy.all import *
import socket
import sys

hashfile = "password.list"


def answer(packet):
    current_hash= open(hashfile,'w')
    submitted_hash = ''
    try:
        if packet[TCP].flags == 'S':
            print("synack")
            send(IP(dst=packet[IP].src) / TCP(sport ="42424" ,dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq + 1, flags='A'))
        else :
            print("content")
    except:
        print("No Content Found in Packet")





def main():

    sniff(filter = 'dst port 42424', prn=answer, iface="lo")




if __name__ == "__main__":
    main()
