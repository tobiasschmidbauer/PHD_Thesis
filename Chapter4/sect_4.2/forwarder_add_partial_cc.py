from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import logging
import importlib
import os
import time

#################
#####  Global Variables
#################

## Number of non CC Packages to count down from
#global send_cc_package_each_x_packages
#global package_count_since_last_cc



def print_and_accept(pkt):
    #start_accept_time = time.time()
    global send_cc_package_each_x_packages
    global package_count_since_last_cc
    nexthop='192.168.0.30'
    my_ip= '192.168.0.20'
    encode_index = 0
    modification_counter = 0
    int_string_cc = ""
    int_string_oc = ""
    covert_hash = ""
    

    global covert_message
    global characters

    global alphabet
    global pkt_count

    covert_character = covert_message[pkt_count]
    #print(covert_character)
    pkt_count += 1

    for characters in alphabet:
        if covert_character == characters:
            break
        else:
            encode_index = encode_index + 1
    #print(encode_index)


    scapy_package = IP(pkt.get_payload())
    pkt.drop()
    #scapy_package.show()
    err = 0
    try:
        overt_hash = scapy_package.getlayer(Raw).load
    except AttributeError as error:
        err= 1
    start_deconstruct = time.time()
    for bytes in overt_hash:
        tempstring= ''
        for i in range(8):
            #print(i)
            #print(modification_counter)
            #print(encode_index)
            if i == 7:
                    tempstring = str(bytes >> i & 1) + tempstring
            else:
                if modification_counter == encode_index:
                    tempstring = str((bytes >> i & 1) ^ 1) + tempstring
#                 tempstring = str((bytes >> i & 1) ^ 1) + tempstring
#                 encode_index = -1
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
    #stop_deconstruct = time.time()
    #time_deconstruct = stop_deconstruct -start_deconstruct
#debugging
    #int_string_oc = ""
    #for bytes in overt_hash:
    #    tempstring= ''
    #    for i in range(8):
    #        tempstring = str(bytes >> i & 1) + tempstring
    #    int_string_oc = int_string_oc + tempstring

   # print(int_string_oc)
   # print(int_string_cc)

    scapy_package[IP].dst = nexthop
    scapy_package[IP].src = my_ip

    ### Increase Package Count    
    package_count_since_last_cc += 1
    ### Check if CC or not
    #start_cc_impl = time.time()
    if package_count_since_last_cc == send_cc_package_each_x_packages:
        scapy_package[Raw].load = covert_hash.encode("iso-8859-15")
        package_count_since_last_cc = 0
    else:
        package_count_since_last_cc = package_count_since_last_cc
        scapy_package[Raw].load = scapy_package[Raw].load
    #stop_cc_impl = time.time()
    #time_cc_impl = stop_cc_impl - start_cc_impl
    #writer = open("modified_hashes",'a')
    #writer.write(covert_hash + '\n')
    #writer.close()
    #start_reconstruct =time.time()
    del scapy_package[IP].len
    del scapy_package[IP].chksum
    del scapy_package[TCP].chksum
    scapy_package.show2()
    if err != 1:
        send(scapy_package)
    #stop_reconstruct =time.time()
    #time_reconstruct = stop_reconstruct - start_reconstruct
    
    #stop_accept_time = time.time()
    #time_accept_time = stop_accept_time - start_accept_time

    #open('timelog.csv', 'a').write(str(time_accept_time)+";"+str(time_deconstruct)+";"+str(time_cc_impl)+";"+str(time_reconstruct)+'\n')





if __name__ == '__main__':

    global send_cc_package_each_x_packages
    global package_count_since_last_cc
    global covert_message
    global characters
    global pkt_count
    global alphabet

    covert_message = open('covertmessage.txt', 'r').read()
    characters = open('alphabet.txt','r').read()
    pkt_count = 0
    alphabet = array('u',list(characters))
    
    #### Calculation # of CC Packages per 100 Hashes sendt
    ## Amount of CC conversation in percent
    try:
       cc_amount = sys.argv[1]
    except:
       cc_amount = 100

    ## Number of non CC Packages to count down from
    try:
       send_cc_package_each_x_packages = int(100/int(cc_amount))
    except ZeroDivisionError as err:
       # If set to zero, set counter to -10 Million, so never a CC package is send
       send_cc_package_each_x_packages = -10000000
    ## Define oackages since last cc
    package_count_since_last_cc = 0


    #open('timelog.csv', 'a').write("whole;deconsruct;cc_implementation;construct_and_send\n")

    
    
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
