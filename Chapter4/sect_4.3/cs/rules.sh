#!/bin/bash
iptables -I INPUT -p tcp --sport 10002 -j NFQUEUE --queue-num 1
