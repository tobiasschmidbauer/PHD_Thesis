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


basedir = '/home/tobias/ntp/'
configdir = basedir + 'inject_config/'
interface = 'eth0'
#ntp_server = '192.168.3.29'
ntp_server = '192.168.3.28'
#dstip = '0.0.0.0'



def send_ntp_controlmessage(ntp_server):
    packet = IP(dst=ntp_server)/UDP(dport=123,sport=123)/("\x16\x02\x00\x01"+"\x00"*8)

    packet.show()
    send(packet, iface='eth0')



def main():


    while 1 == 1 :

        send_ntp_controlmessage(ntp_server)

        time.sleep(5)



if __name__ == "__main__":
    main()
