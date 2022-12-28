from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import logging
from bitstring import BitArray

def print_and_accept(pkt):
    nexthop='192.168.2.145'
    my_ip= '192.168.2.146'
    encode_index = 0
    modification_counter = 0
    int_string_cc = ""
    int_string_oc = ""
    covert_hash = ""

    covert_message = open('covertmessage.txt', 'r')
    characters = open('alphabet.txt','r').read()

    alphabet = array('u',list(characters))

    covert_character = covert_message.read(1)
    new_covert_message = covert_message.read()
    covert_message.close()
    covert_message = open('covertmessage.txt', 'w')
    covert_message.write(new_covert_message[1:])
    covert_message.close()



    for characters in alphabet:
        if covert_character == characters:
            break
        else:
            encode_index = encode_index + 1



    scapy_package = IP(pkt.get_payload())
    pkt.drop()
    #scapy_package.show()


    overt_hash = scapy_package.getlayer(Raw).load
    for bytes in overt_hash:
        tempstring= ''
        for i in range(8):
            if modification_counter == encode_index:
                tempstring = str((bytes >> i & 1) ^ 1) + tempstring
                encode_index = -1

            else:
                tempstring = str(bytes >> i & 1) + tempstring
                modification_counter = modification_counter + 1
        int_string_cc = int_string_cc + tempstring

    number_of_chars_left = len(int_string_cc) / 8
    index_first_bit = 0
    while number_of_chars_left > 0:
        index_last_bit = index_first_bit + 8
        covert_hash = covert_hash + str(chr(int(int_string_cc[index_first_bit:index_last_bit],2)))
        index_first_bit = index_last_bit
        number_of_chars_left = number_of_chars_left - 1




    scapy_package[IP].dst = nexthop
    scapy_package[IP].src = my_ip
    scapy_package[Raw].load = covert_hash


    send(scapy_package)



if __name__ == '__main__':
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
