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
#srcip = '123.123.231.231'
srcip = '1.1.'
srcip2 = '192.168.4.'
srcip3 = '192.168.5.'
srcip4 = '192.168.6.'
srcport = 123
#ntp_server = '136.243.7.20'
ntp_server = '192.168.3.28'
#dstip = '0.0.0.0'



def to_int(plaintext):
    intarray = []
    for character in plaintext:
        intchar = int(hex(ord(character)).replace('0x', ''),16)

        intarray.append(intchar)
    while len(intarray) % 4 != 0:

        intarray.append('0')

    return intarray

def create_ips(int_message):
    message_length = len(int_message)
    #print(hex_message)
    counter= 0
    current_ip = ''
    str(current_ip)
    ip_list = []
    while counter < message_length:
        if counter % 4 == 0:
            current_ip = str(int_message[counter]) + '.'
        elif counter % 4 == 3:
            current_ip = current_ip + str(int_message[counter])
            ip_list.append(current_ip)
        else:
           current_ip = current_ip + str(int_message[counter]) + '.'
        counter = counter + 1
    #print(ip_list)
    return ip_list


def get_current_ntp_time():
    diff = datetime.datetime.now() - datetime.datetime(1900, 1, 1, 0, 0, 0)
    timestamp = diff.days * 24 * 60 * 60 + diff.seconds
    return timestamp

def timestamp_to_hex(timestamp):
    raw = str(hex(timestamp))
    raw = raw [2:18]
    formated = ''

    begin_char = 0
    end_char = 2

    while end_char <9:
        current_hex=raw[begin_char:end_char]
        formated= formated + '\\x' + current_hex
        begin_char = end_char
        end_char += 2

    return formated

def send_cc_message(src_to_inject):
    timestamp=get_current_ntp_time()

    packet = IP(dst=ntp_server,src=src_to_inject)/UDP(dport=123,sport=srcport)/NTP(mode=3,poll=6,precision=232,delay=0.0102,dispersion=0.0190,id=ntp_server,ref=timestamp,recv=timestamp,orig=timestamp,sent=timestamp)

    send(packet, iface='eth0')






def main():
    for first in range(1,254):
        for second in range(1, 254):
            curr_ip = srcip + str(first) + "."
            curr_ip = curr_ip + str(second)
            send_cc_message(curr_ip)
            #time.sleep()


            #last += last
            time.sleep(0.1)
    #send_ntp_broadcast(ip_list)


if __name__ == "__main__":
    main()
