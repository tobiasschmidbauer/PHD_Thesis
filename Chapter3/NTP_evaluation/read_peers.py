#!/usr/bin/env python
from scapy.all import *
import os
import socket
import ipaddress
import fcntl
import struct
import random
import sys
import time
import datetime


basedir = '/home/tobias/master/'
configdir = basedir + 'inject_config/'
interface = 'eth0'
#ntp_server = '192.168.3.29'
ntp_server = '136.243.7.20'
#dstip = '0.0.0.0'



def send_ntp_controlmessage(ntp_server):
    #packet = IP(dst=ntp_server)/UDP(dport=123,sport=123)/("\x1e\x0c\x00\x01"+"\x00"*8)
    packet = IP(dst=ntp_server)/UDP(dport=123,sport=123)/("\x26\x0c\x00\x01"+"\x00"*8)

    #packet = IP(dst=dstip, src=srcip) / UDP(dport=123, sport=50000) / ('\x25\x02\x06\xe8\x00\x00\x02\xc1\x00\x00\x04\x04\x0a\x1e\x00\x1d' + offset + reference_timestamp + offset + origin_timestamp + offset + receiver_timestamp + offset + transmit_timstamp)
    packet.show()
    #packet2.show()
    send(packet, iface='lo')



def main():


    #while 1 == 1:
    #    send_ntp_broadcast(ntp_server)
    #    time.sleep(10)
    while 1 == 1 :
     #   ntp_server = get_ntp_ip_from_dns()

        send_ntp_controlmessage(ntp_server)

        time.sleep(0.05)

    #send_ntp_controlmessage(ntp_server)


if __name__ == "__main__":
    main()