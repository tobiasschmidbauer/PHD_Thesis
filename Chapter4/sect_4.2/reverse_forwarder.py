from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys

def print_and_accept(pkt):
    nexthop='192.168.3.26'
    my_ip= '192.168.2.146'
    scapy_package = IP(pkt.get_payload())
    pkt.drop()

    submitted_hash = scapy_package[RAW].load

    scapy_package[IP].dst = nexthop
    scapy_package[IP].src = my_ip


    send(scapy_package)



if __name__ == '__main__':
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
