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
dstip = '192.168.3.27'
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
    print(ip_list)
    return ip_list


def get_current_ntp_time():
    diff = datetime.datetime.utcnow() - datetime.datetime(1900, 1, 1, 0, 0, 0)
    timestamp = diff.days * 24 * 60 * 60 + diff.seconds
    #timestamp=datetime.datetime(1900, 1, 1, 0, 0, 0)
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

def send_ntp_broadcast(ip_list):
    srcip=ip_list[0]
    timestamp=get_current_ntp_time()


    #print(ip_list[0])
    #print(ascii(maclist[len(maclist) - 1]))

    #packet = IP(dst=dstip,src=srcip)/UDP(dport=123,sport=50000)/("\x25\x00\x00\x00"+"\x00"*11*4)
    #packet = IP(dst=dstip,src=srcip)/UDP(dport=123,sport=50000)/NTP(mode=5,poll=6,precision=0,delay=0.0102,dispersion=0.0190,id="131.188.3.221",ref=timestamp,recv=timestamp)
    #packet = IP(dst="192.168.3.31",src="192.168.3.26")/UDP(dport=123,sport=123)/NTP(mode=5,poll=6,precision=0,delay=0.0102,dispersion=0.0190,ref=timestamp,recv=timestamp)
    packet = IP(dst="192.168.3.31",src=ip_list)/UDP(dport=123,sport=123)/NTP(mode=5,poll=6,precision=232,delay=0.0102,dispersion=0.0190,ref=timestamp,recv=0,orig=0)
    #packet = IP(dst="192.168.3.27",src="192.168.3.26")/UDP(dport=123,sport=123)/NTP(mode=5,poll=6,precision=232,delay=0.0102,dispersion=0.0190,ref=timestamp,recv=0,orig=0)

    #packet = IP(dst=dstip, src=srcip) / UDP(dport=123, sport=50000) / ('\x25\x02\x06\xe8\x00\x00\x02\xc1\x00\x00\x04\x04\x0a\x1e\x00\x1d' + offset + reference_timestamp + offset + origin_timestamp + offset + receiver_timestamp + offset + transmit_timstamp)
    packet.show()
    #packet2.show()
    send(packet, iface='eth0')






def main():
    #print(os.path.dirname(os.path.realpath(__file__)))
    #timestamp=get_current_ntp_time()
    #print(timestamp)
    #timestamp_to_hex(timestamp)

    #message='test'

    #int_message=to_int(message)
    #ip_list=create_ips(int_message)
    #while 1 == 1:
    #    send_ntp_broadcast(ip_list)
    #    time.sleep(10)
    #send_ntp_broadcast(ip_list)
    srcip="192.168.3."
    for i in range(1,254):

        curr_ip = srcip + str(i)
        send_ntp_broadcast(curr_ip)
        time.sleep(5)

if __name__ == "__main__":
    main()