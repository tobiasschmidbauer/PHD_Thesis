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
            date = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            time = datetime.datetime.now().strftime("%H:%M:%S")
            #source = str(packet[IP].src)
            #load = str(packet[Raw].load)
            load = ''

            for charcter in packet[Raw].load:
                load = load + chr(charcter)

            for line in load.splitlines():
                    if "192.168.3.25" in line:
                        durationlog = open(logfile_duration, 'a+')
                        durationlog.write(time + ":" + line + '\n')
                        durationlog.close()


            return

        # if no mru or nounce response return to sniffer
        else: return

    #when attribute op_code not found do nothing, just return
    except AttributeError:
        return

def send_mru_request(nonce,ntp_server):
    mrurequest = IP(dst=ntp_server) / UDP(dport=123, sport=123) / ("\x16\x0a\x00\x01" + "\x00" * 7 + "\x28" + nonce + ", frags=32")
    send(mrurequest)
    return




def main():

    sniff(filter="udp and port 123", prn=scan_for_ntp_control,iface="eth0")


if __name__ == "__main__":
    main()
