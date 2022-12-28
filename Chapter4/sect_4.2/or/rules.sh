#!/bin/bash
iptables -I INPUT -s 192.168.0.30 -p tcp --dport 42424 -j NFQUEUE --queue-num 1
