from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import logging


def print_and_accept(pkt):
    nexthop='192.168.2.145'
    my_ip= '192.168.2.146'

    covert_hash = ""
    expected_hash = open('password.list', 'r').read()
    characters = open('alphabet.txt','r').read()



    scapy_package = IP(pkt.get_payload())
    scapy_package[IP].dst = nexthop
    scapy_package[IP].src = my_ip
    pkt.drop()

    if scapy_package[Raw].load.encode('utf-8') == expected_hash:
        send(scapy_package)

    else:
        int_string_cc = ""

        # create bitstring from covert hash
        for bytes in covert_hash:
            tempstring = ''
            for byte_index in range(8):
                tempstring = str(bytes >> byte_index & 1) + tempstring

            int_string_cc = int_string_cc + tempstring

        alphabet = array('u', list(characters))
        alphabetindex = 0

        for char in alphabet:
            overt_hash = ""

            # reconstruct overt hash integer
            int_string_oc = int_string_cc[0:alphabetindex]
            alphabetindex = alphabetindex + 1
            if int_string_cc[alphabetindex] == '1':
                int_string_oc = int_string_oc + '0'
            else:
                int_string_oc = int_string_oc + '1'
            int_string_oc = int_string_oc + int_string_cc[alphabetindex:]

            # reconstruct overt hash as string
            number_of_chars_left = len(int_string_oc) / 8
            index_first_bit = 0
            while number_of_chars_left > 0:
                index_last_bit = index_first_bit + 8
                overt_hash = overt_hash + str(chr(int(int_string_oc[index_first_bit:index_last_bit], 2)))
                index_first_bit = index_last_bit
                number_of_chars_left = number_of_chars_left - 1

            # check if correct
            next_hash = hashlib.md5(overt_hash.encode("utf-8")).hexdigest()
            # next_hash = hashlib.sha3_512(overt_hash.encode("utf-8")).hexdigest()
            print(overt_hash)
            print(next_hash)
            print(expected_hash)
            if next_hash == expected_hash:
                passwordfile = open('password.list', 'w')
                passwordfile.write(next_hash)
                passwordfile.close()

                covert_message = open('submitted.txt', 'a')
                covert_message.write(char)
                covert_message.close()
                break



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
