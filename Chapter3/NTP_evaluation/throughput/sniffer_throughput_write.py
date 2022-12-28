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


logdir = '/home/tobias/'

logfile_duration = logdir + str(datetime.date.today()) + "_throughput_write.log"


def scan_for_ntp_control(packet):

    try:
        ## catch nonce responses and send back the mru request
        if packet[NTP].mode == 3 :
            source=str(packet[IP].src)

            if "1.1." in source:
                durationlog = open(logfile_duration, 'a+')
                durationlog.write(str("1") + '\n')
                durationlog.close()

            #send mru request and return to sniffer

        # if no mru or nounce response return to sniffer
        else: return

    #when attribute op_code not found do nothing, just return
    except AttributeError:
        return



def main():
    entries = 0
    sniff(filter="udp and port 123", prn=scan_for_ntp_control,iface="eth0")


if __name__ == "__main__":
    main()
