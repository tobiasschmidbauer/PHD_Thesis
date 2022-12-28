#!/bin/bash
iptables -I INPUT -s 192.168.0.20/24 -p tcp --dport 42424 -j NFQUEUE --queue-num 1
iptables -I INPUT -s 192.168.0.40/24 -p tcp --sport 42424 -j NFQUEUE --queue-num 2
