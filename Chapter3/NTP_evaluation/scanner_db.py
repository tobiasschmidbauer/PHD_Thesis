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


log = '/home/tobias/ntp_paper/db.new'
interface = 'eth0'
#dstip = '0.0.0.0'


def get_ntp_ip_from_dns():
    answer = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="pool.ntp.org")), verbose=0)
    try:
        ip = answer[DNSRR][1].rdata
    except IndexError:
        ip = "199.182.204.197"
    except TypeError:
        ip = "199.182.204.197"
    return ip


def main():


    database = open(log, 'a+')
    while 1 == 1 :
        newentry = 1
        ntp_server = get_ntp_ip_from_dns() + "\n"
        iplist=tuple(open(log, 'r'))
        for line in iplist:
            #print(line)
            if ntp_server in line:
                newentry = 0

        print(ntp_server)
        if newentry == 1:

            database.write(ntp_server)

        time.sleep(0.1)



if __name__ == "__main__":
    main()
