#!/bin/bash
iptables -I INPUT -p tcp --sport 10001 -j NFQUEUE --queue-num 2
