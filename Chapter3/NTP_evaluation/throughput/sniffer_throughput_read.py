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


logdir = '/home/tobias/ntp_paper/log/'
logfile_short = logdir + str(datetime.date.today()) + ".log"
logfile_duration = logdir + str(datetime.date.today()) + "_duration.log"
logfile_long = logdir + str(datetime.date.today()) + "_long.log"
logfile_ip = logdir + str(datetime.date.today()) + "_ip.log"
numbers = 0
firstrun =1
seconds = 0
wait = 15

def scan_for_ntp_control(packet):

    try:
        ## catch nonce responses and send back the mru request
        if packet[NTP].op_code == 12 and packet[NTP].response == 1 :
            source=str(packet[IP].src)
            nonce = str(packet[Raw].load)

            #fromating nonce
            nonce = nonce[:32]
            nonce = nonce[2:]

            #send mru request and return to sniffer
            send_mru_request(nonce,source)
            return

        # catch mru responses, write to logfile
        elif packet[NTP].op_code == 10 and packet[NTP].response == 1 :
            load = ''

            for charcter in packet[Raw].load:
                if charcter != 13:
                    load = load + chr(charcter)


            search_entries_duration_once(load)
            return

        # if no mru or nounce response return to sniffer
        else: return

    #when attribute op_code not found do nothing, just return
    except AttributeError:
        return




def search_entries_duration_once(liste):
    for line in liste.splitlines():
        if "addr.0" in line:
            durationlog = open(logfile_duration, 'a+')
            durationlog.write(str("0") + '\n')
            durationlog.close()
            entries = 0
        #if "123.123.231.231" in line:
        if "1.1." in line:
            durationlog = open(logfile_duration, 'a+')
            durationlog.write(str("1") + '\n')
            durationlog.close()


    return

def search_for_ip(liste):
    treffer = 0
    for line in liste.splitlines():
        now = time.time()
        #if "123.123.231.231" in line:
        if "192.168.1." in line:
            durationlog = open(logfile_duration, 'a+')
            durationlog.write(seconds + ":" + "1" + '\n')
            durationlog.close()
            treffer = 1
    if  treffer == 0 :
        durationlog = open(logfile_duration, 'a+')
        durationlog.write(seconds + ":" + "0" + '\n')
        durationlog.close()

    seconds += wait
    return

def search_extended(liste):
    entry = 0
    complete_entries = 0
    for line in liste.splitlines():

        print(complete_entries)
        if "192.168.1.2" in line:
            entry = 1
        if "addr." in line:
            complete_entries += 1
    durationlog = open(logfile_duration, 'a+')
    durationlog.write(seconds + ":" + str(complete_entries) + ":" + str(entry) + '\n')
    durationlog.close()

    seconds += wait
    return

def send_mru_request(nonce,ntp_server):
    mrurequest = IP(dst=ntp_server) / UDP(dport=123, sport=123) / ("\x26\x0a\x00\x01" + "\x00" * 7 + "\x28" + nonce + ", frags=32")
    send(mrurequest)
    return




def main():
    entries = 0
    sniff(filter="udp and port 123", prn=scan_for_ntp_control,iface="eth0")


if __name__ == "__main__":
    main()
