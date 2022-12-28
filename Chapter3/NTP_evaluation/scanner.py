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
#ntp_server = '192.168.3.27'
ntp_server = '136.243.7.20'
#dstip = '0.0.0.0'



def send_ntp_controlmessage(ntp_server):
    packet = IP(dst=ntp_server)/UDP(dport=123,sport=123)/("\x26\x0c\x00\x01"+"\x00"*8)

    packet.show()
    send(packet, iface='lo')



def main():


    for  i in (1,101):

        send_ntp_controlmessage(ntp_server)

        time.sleep(5)



if __name__ == "__main__":
    main()
