import sys
from scapy.all import *
from bitstring import BitArray
from operator import xor
import numpy as np
import time
import collections
import hashlib
import functools
import itertools
import os
from netaddr import *
import netifaces
import bchlib
import math
from threading import Timer


##
# define global variables
##

global cm_array ## covert message split in array of sys.argv[2] characters
global cm_array_current ## current position of message to encode
global ba_curr ## current bitarray to search for
global interface ## interface to receive and send messages
global logfile_percentCoverage_covertMessage ## file to log the percent fitting bits
global hwv4_broadcast ## MAC address for broadcasts
global ipv4_broadcast ## IP address for network broadcasts
global hwv6_broadcast ## MAC address for broadcasts
global ipv6_broadcast ## IPv6 address for broadcasts
global signal_ipv6 ## IPv6 Address that will trigger the signal
global signal_ether ## IPv6 Address that will trigger the signal
global DB
global DBtime
global encoding_method ## Method coding is achieved with
global timeslice_total ## timeslice to encode position within the hash
global timeslice_delay ## delay to calculate with for additional runtime
global latest_timestamp_cr_only
global number_of_chars
global bch
global masks
global robust
global oldPkt
global robustignore
global robustdelay
global timer
global ba_save
global sniffed_hash
global timestamp
global crit_fraction_high
global crit_fraction_low

###
# Configuration for ECC mode. This approach has not further been implemented and is experimental
###
BCH_POLYNOMIAL = 8219
BCH_BITS = 1
bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)


###
# Define collections for storage of packets
#
# DB stores hash values as bitstrings
# DBtime stores the according timestamp of each packet
###
DB = collections.deque(maxlen=20000) # 20 Pakets to store
DBtime = collections.deque(maxlen=20000) # 20 Pakets to store
#DBtime = None


####
# RepeatingTimer
#
# This is utilized for the robust mode, where a timer is set at the moment a suitable packet arrives
# The timer is aborted if there is another packet potentially threatening a correct submission
####

class RepeatingTimer(object):

    def __init__(self, interval, f, *args, **kwargs):
        self.interval = interval
        self.f = f
        self.args = args
        self.kwargs = kwargs

        self.timer = None

    def callback(self):
        self.f(*self.args, **self.kwargs)

    def reset(self):
        print("RESET Timer")
        if self.timer:
            self.timer.cancel()
            self.timer = Timer(self.interval, self.callback)
            self.timer.start()
        else:
            self.timer = Timer(self.interval, self.callback)
            self.timer.start()

    def cancel(self):
        self.timer.cancel()

    def start(self):
        self.timer = Timer(self.interval, self.callback)
        self.timer.start()



##########
#### Signalling functions
##########

##
# CR check if a signal arrived. We only utilized ARP, not IPv6 signals
##
def isSignal(packet,prot):
    global signal_ipv6
    global signal_arp
    if prot == 'ipv6' and IPv6 in packet:
        if str(packet[IPv6].dst) == signal_ipv6: return True
        else: return False
    elif prot == 'arp' and ARP in packet:
        if str(packet[ARP].pdst) == signal_arp and str(packet[ARP].psrc) == signal_arp_from: return True
        else: return False
    else :return False

###
# Determins if packet is intresting for DUST
###
def isPktOfInterest(packet):
    global hwv4_broadcast  ## MAC address for broadcasts
    global ipv4_broadcast  ## IP address for broadcasts
    global hwv6_broadcast  ## MAC address for broadcasts
    global ipv6_broadcast  ## IP address for broadcasts
    # Dummy implementation - every IPv6 Paket is "interesting"
    if isSignal(packet,'arp'):
        return False

    try:
        if IPv6 in packet:
            if str(packet[Ether].dst).startswith(hwv6_broadcast):
                return True
            elif str(packet[IPv6].dst).startswith(ipv6_broadcast):
                return True
            else:
                return False
        if IP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast:
                return True
            elif str(packet[IP].dst) == "255.255.255.255":
                return True
            elif str(packet[IP].dst) == ipv4_broadcast:
                return True
        if ARP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast and str(packet[ARP].src) != "192.168.2.1":
                return True
        else:
            return False
    except:
        return False

###
# Send a signal and tell which protocol to use
# depricated: DB_pointer and hash_pointer
###
def sendSignal(prot,addr,DB_pointer,hash_pointer):
    if prot == 'ipv6':
        sendIPv6(addr)
    elif prot == 'arp':
        sendARP(addr)
    else:
        pass

###
# send an ARP signal
###
def sendARP(addr):
    global interface
    global ba_curr
    global cm_array_current
    global cm_array
    global logfile_percentCoverage_covertMessage
    global ba_save
    global sniffed_hash
    global timestamp
    global encoding_method
    #command= "arping -c 1 -I" + interface + " " +addr
    #os.system(command)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr),iface=interface)
    if robust:
        if encoding_method.startswith("trivial"):
            cm_array_current += 1
            ba_curr = getStringToBinary(cm_array[cm_array_current])
        elif encoding_method.startswith("ext"):
            cm_array_current += 1
            ba_temp = getStringToBinary(cm_array[cm_array_current])
            ba_curr = ba_temp + getCheckSum(ba_temp)
        elif encoding_method.startswith("ECC"):
            cm_array_current += 1
            ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])

        with open(logfile_percentCoverage_covertMessage, 'a') as log:
                log.write(str(timestamp) + ";" + str(sniffed_hash) + ";" + str(ba_save) + ";" + str(
                getMatchPercent(list(ba_save), list(sniffed_hash))) + ";" + str(True) +'\n')
        log.close()
    return


###
# Send IPv6 signal, not utilized in this script
###
def sendIPv6(addr):
    global interface
    command= "ndisc6" + " " + addr + " "+ interface
    os.system(command)
    return



###################
##### Converting functions
###################
##
# decode bits to string
##
def getBinaryToString(bits):
    return bits.decode('utf-8')

##
# Join bitstrings to strings
##
def getBitStringToString(bits):
    return ''.join(chr(int(bits[i*8:i*8+8],2)) for i in range(len(bits)//8))
 
##
# Get a binary value from a string by encoding
##
def getStringToBinary(string):
    bin_value=BitArray(string.encode('utf-8')).bin
    return bin_value

##
# ECC reversion like above examples for non ECC approaches
# experimental
##
def getStringToBinary_BCH(string):
    global bch
    bin_value=BitArray(string.encode('utf-8'))
    ecc = bch.encode(bin_value.bytes)
    return bin_value.bin + BitArray(ecc).bin

##
# ECC reversion like above examples for non ECC approaches
# experimental
##
def getBinaryToString_BCH(bits):
    global bch
    inputBytes = BitArray(bin=bits).bytes
    data, ecc = inputBytes[:-bch.ecc_bytes], inputBytes[-bch.ecc_bytes:]
    bitflips, newData, newECC = bch.decode(data, ecc)
    try:
        string_to_return = newData.decode('utf-8')
    except  UnicodeDecodeError: ##catch decode errors by bits not contained in utf8
        string_to_return=""
    return string_to_return



########
### Getting values from packets, dbs
########

###
# create hash value from input
###
def getHashValue(input):
    try:
        hash = hashlib.sha512(input)
    except TypeError:
        hash= hashlib.sha512(input.encode('utf-8'))
    return hash


###
# create hash input values from packet and timestamp
###
def getInputValues(packet):
    string = ""
    if robust:
        timestamp = str(int(time.time()))
    else:
        timestamp = str(int(time.time()/10))
    if IPv6 in packet:
        string = str(packet[IPv6].src) + timestamp
    elif IP in packet:
        string = str(packet[IP].chksum) + timestamp
    elif ARP in packet:
        string = str(packet[ARP].pdst) + str(packet[ARP].psrc) + timestamp

    return string

###
# extract a bitstring from the DB at position X
###
def getBitstringFromDB(DB_position):
    try:
        res = BitArray(bytes=DB[DB_position].digest()).bin
    except:
        res = ''
    return res


###
# extract a specific DB position
# Binary position is depricated
###
def getSniffedHash(DB_position, Binary_position):
    global ba_curr
    global DB
    begin = Binary_position * len(ba_curr)
    end =(Binary_position+1)*len(ba_curr)
    #return getStringToBinary(DB[DB_position].hexdigest())[begin:end]
    return getBitstringFromDB(DB_position)[begin:end]


###
# extract time from DBtime
###
def getSniffedTime(DB_position):
    global DBtime
    return DBtime[DB_position]

###
# get a chunked hash split into n bytes, dependent on the chunk input argument
###
def getSniffedHashList(DB_position):
    global ba_curr
    global DB

    try:
        number_of_vals = len(getBitstringFromDB(DB_position)) / len(ba_curr)
        #number_of_vals = len(getStringToBinary(DB[DB_position].hexdigest())) / len(ba_curr)
    except AttributeError:
        number_of_vals = 0

    hashlist = []
    counter = 0
    while counter < number_of_vals:
        hashlist.append(getSniffedHash(DB_position,counter))
        counter +=1

    return hashlist





##########
#### Special ext-mode functions for checksums and reversions
##########

###
# Test if checksum fits
###
def testCheckSum(hash):
    if number_of_chars == 1:
        return(list(map(int,list('{0:04b}'.format(np.count_nonzero(np.array(hash[:-4]).astype(int)))))) == hash[-4:])
    elif number_of_chars == 2:
        return(list(map(int,list('{0:05b}'.format(np.count_nonzero(np.array(hash[:-5]).astype(int)))))) == hash[-5:])
    else:
        print("Checksum not Calculated")
        exit(100)


###
# Get bitflip masks
###
def getMask(n,k):
    result = []
    for i in range(k+1):
        res = kbits(n,i)
        res.reverse()
        result.append(res)
        #if i> 10: break
    ret = [item for sublist in result for item in sublist]
    ret = list(map(list,ret))
    ret = list(map(lambda x: [int(y) for y in x],ret))
    return ret


###
# generate checksum of a hash
###
def getCheckSum(hash):
    if number_of_chars == 1:
        return('{0:04b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    elif number_of_chars == 2:
        return('{0:05b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    else:
        print("Checksum not Calculated")
        exit(100)


###
# Check if the first bitflip with correct checksum contains the correct message
# else return false as the CR will not be able to revert the correct message
###
def checkBitFlips(hash, orig):
    global masks
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length to long")
        exit(100)
    for i in masks:
        cur_flipped = list(map(lambda x,y: x ^ int(y), hash ,list(i)))
        if (testCheckSum(cur_flipped)):
            if(cur_flipped[:cflen] == orig[:cflen]):
                return True
            else:
                return False
        else:
            pass
    return False

###
# bitflip reversion on CR side
###
def revertBitFlip(hash):
    global masks
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length to long")
        exit(100)

    for i in masks:
        cur_flipped = list(map(lambda x,y: x ^ int(y), hash ,list(i)))
        if (testCheckSum(cur_flipped)):
            return cur_flipped[:cflen]
        else:
            pass

###
# utilied for creating bitflip masks
###
def kbits(n, k):
    result = []
    for bits in itertools.combinations(range(n), k):
        s = ['0'] * n
        for bit in bits:
            s[bit] = '1'
        result.append(''.join(s))
    return result


#####
# ext mode coverage check, determines if packet can potentially utilized
#####
def getMatchPercent(a,b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b))/len(a)



##########
##### Main functions for CS and CR
##########

####
## CS main function performin all the actions
####
def cs_sniffing(packet):
    global DB
    global signal_ipv6
    global cm_array
    global cm_array_current
    global ba_curr
    global logfile_percentCoverage_covertMessage
    global timestamp
    global sniffed_hash
    global robust
    global oldPkt
    global robustdelay
    global timer
    global ba_save
    global crit_fraction_high
    global crit_fraction_low
    sig_send = False


    ## Packet is interesting
    if isPktOfInterest(packet):
        ## Robust mode additions
        # ignore packets, that cause race conditions and cancel the timer if suitable packet is found
        if robust:
            if (oldPkt is None):
                oldPkt = packet
            elif (float(packet.time - oldPkt.time) < robustdelay):
                oldPkt = packet
                try:
                    timer.cancel()
                except:
                    pass
                return

        ba_save=ba_curr ## save ba for logging issues after signal is send
        timestamp = time.time() + timeslice_delay
        critical_fraction, seconds = math.modf(timestamp)

        ## determine if the time has critical fraction (timstamp usage for hashing) 
        ##if fraction is critial insert pseudo hexdigest, causing an empty binary if reverted
        if (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low):
            DB.appendleft("")
            isCritFraction = True
        else:
            input1 = getInputValues(packet)
            hash = getHashValue(input1)
            DB.appendleft(hash)
            isCritFraction = False

        ## get the latest hash from the db to check
        ## if critical fraction occure, the DB has not hash, so catch this error and set an empty string
        try:
            sniffed_hash = getSniffedHashList(0)[0]
        except IndexError:
            sniffed_hash = ""


        #####
        ## Depending on the encodin method, check if hash matches to the expected value ba_curr
        #####

        ##Trivial encoding
        if encoding_method.startswith("trivial"):
            #only send the signal if the strings match and timing is not critical
            if ba_curr == sniffed_hash and not(isCritFraction):
                ##if robus start the timer, that will send the signal after it reached zero
                if robust:
                    timer.start()
                ##else send signal
                else:
                    cm_array_current+=1
                    ba_curr = getStringToBinary(cm_array[cm_array_current])
                    print("Found correct hash")

                    sendSignal('arp',signal_arp,0,0)
                    sig_send = True
            else:
                print("NoMatch")

        ###
        # extenden encoding witch checksums
        ###
        elif encoding_method.startswith("ext"):
            ## if more than 80% of the bits match, try to correct bitflips
            if sniffed_hash != "" and getMatchPercent(list(sniffed_hash),list(ba_curr)) >= 0.8 and not isCritFraction:
                sniffed_hash_int= list(map(int,sniffed_hash))
                ba_curr_int= list(map(int,ba_curr))
                ## if bitflips can be converted correctly, send a signal
                if checkBitFlips(sniffed_hash_int,ba_curr_int):
                    #if robus start the timer, that will send the signal after it reached zero
                    if robust:
                        timer.start()
                    # else send signal
                    else:
                        cm_array_current+=1
                        ba_temp = getStringToBinary(cm_array[cm_array_current])
                        ba_curr = ba_temp + getCheckSum(ba_temp)
                        print("Found correct hash")

                        sendSignal('arp',signal_arp,0,0)
                        sig_send = True
                else:
                    print("NoMatch")
            else:
                print("NoMatch")


        ###
        # experimental, not further used for DUST
        ###
        elif encoding_method.startswith("ECC"):
            #only send the signal if the strings match and timing is not critical
            if getBinaryToString_BCH(sniffed_hash) == getBinaryToString_BCH(ba_curr) and not(isCritFraction):
                if robust:
                    timer.start()
                else:
                    cm_array_current += 1
                    ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])
                    print("Found correct hash")
                    sendSignal('arp', signal_arp)
                    sig_send = True


        ####
        # Logging
        ####

        ##
        # Print output on stdout
        ##
        print("Sniffed Hash: \t",sniffed_hash)
        print("Target Hash: \t", ba_save)
        try:
            print("Match Percent: \t", getMatchPercent(list(ba_save), list(sniffed_hash)))
        except ValueError:
            print("Critical Second Fraction Detected")
        print("----")

        ##
        # log statistics
        ##
        with open(logfile_percentCoverage_covertMessage, 'a') as log:
            try:
                log.write(str(timestamp) + ";" + str(sniffed_hash) + ";" + str(ba_save) + ";" + str(
                getMatchPercent(list(ba_save), list(sniffed_hash))) + ";" + str(sig_send) +'\n')
            except ValueError:
                log.write(str(sniffed_hash) + ";" + str(ba_save) + ";;" + str(sig_send)+  '\n')
        log.close()


    else:
        # Packet not interesting
        pass

####
## CR main function performing all actions
####
def cr_sniffing(packet):
    global DB
    global latest_timestamp_cr_only
    global DBtime
    global robust
    global crit_fraction_high
    global crit_fraction_low

    ##CR has seen a signal and starts reversion
    if isSignal(packet,'arp'):
        print("WOW! That's a signal!")
        packet.show()
        string_message= ""
        binary_message= ""

        ####
        # reversion depending on encoding mode
        ####
        if encoding_method.startswith("trivial"):
            ## for robust, ignore concurrent packets that may have arrived after the signal was send
            if robust:
                rob_timestamp=time.time()
                for pckCount in range(0,200):
                    print(getBitStringToString(getSniffedHash(pckCount,0)))
                    if getSniffedTime(pckCount) <= (rob_timestamp-robustignore):
                        binary_message= getSniffedHash(pckCount,0)
                        break

            else:
                binary_message = getSniffedHash(0,0)
            string_message = getBitStringToString(binary_message)

        elif encoding_method.startswith("ext"):
            ## for robust, ignore concurrent packets that may have arrived after the signal was send
            if robust:
                rob_timestamp = time.time()
                for pckCount in range(0, 19):
                    if (getSniffedHash(pckCount, 0)).time <= (rob_timestamp - robustignore):
                        binary_message = getSniffedHash(pckCount, 0)
                        break
            else:
                binary_message = getSniffedHash(0,0)
            binary_message_int= list(map(int,binary_message))
            binary_message_without_cs = revertBitFlip(binary_message_int)
            string_message = getBitStringToString("".join(str(x) for x in binary_message_without_cs))

        ###
        # experimental
        ###
        elif encoding_method.startswith("ECC"):
            ## for robust, ignore concurrent packets that may have arrived after the signal was send
            if robust:
                rob_timestamp = time.time()
                for pckCount in range(0, 19):
                    if (getSniffedHash(pckCount, 0)).time <= (rob_timestamp - robustignore):
                        binary_message = getSniffedHash(pckCount, 0)
                        break
            else:
                binary_message = getSniffedHash(0, 0)
            string_message= getStringToBinary_BCH(binary_message)

        ##
        # logging the message
        ##
        with open(logfile_received_message, 'a') as file_received_message:
            file_received_message.write(string_message)
            file_received_message.close()

    ## not a signal, but a potential data carrier arrived
    elif isPktOfInterest(packet):
        latest_timestamp_cr_only = time.time() + timeslice_delay

        timestamp = time.time() + timeslice_delay
        critical_fraction, seconds = math.modf(timestamp)
        input1 = getInputValues(packet)
        hash = getHashValue(input1)
        if (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low):
            DB.appendleft("")
        else:
            DB.appendleft(hash)

        #DB.appendleft(hash)
        ##also log arrival time if robust is activated
        if robust:
            DBtime.appendleft(packet.time)

        ##
        # logging for statistics
        ##
        with open(logfile_percentCoverage_covertMessage, 'a') as log:
            try:
                log.write(str(latest_timestamp_cr_only) + ";" + str(getSniffedHash(0,0) + '\n'))
            except:
                log.write(str("") + ";" + str(ba_curr) + ";" + '\n')
        log.close()



if sys.argv[1] == "--help" or sys.argv[1] == "-h":
    print("Usage:")
    print("DUST.py <Covert Message File> <# of bytes at once> <interface> <logfile> <mode [cs,cr]> <coding method [trivial, trivial_robust, ext, ext_robust, ECC(experimental)]> "
          "<ARP Broadcast Target IP> <CR: ARP Broadcast Source IP> <CR: message logging file>")
    exit(100)

print("========Loading configuration=========")
###
# Define variables and read the input parameters
###
covert_message_file = sys.argv[1]
number_of_chars = int(sys.argv[2])
interface=sys.argv[3]
logfile_percentCoverage_covertMessage=sys.argv[4]
mode=sys.argv[5]
hwv4_broadcast = "ff:ff:ff:ff:ff:ff"
ipv4_broadcast = str(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['broadcast'])
hwv6_broadcast = "33:33"
ipv6_broadcast = "ff0"
signal_ipv6 = "fe80::1:1"
timeslice_delay = 0.007
encoding_method = sys.argv[6]
signal_arp = sys.argv[7] 
signal_arp_from = ""
robust=False
oldPkt=None
timer=None
ba_save=None
robustdelay=0.0
robustignore=0.0
if mode == 'cr':
    signal_arp_from = sys.argv[8]
    logfile_received_message = sys.argv[9]
targetCount= 2
###
# set critical fractions
###
crit_fraction_high = 0.95
crit_fraction_low = 0.05


print("========Reading Covert Message=========")
###
# Split the Message to transfer into n Byte chunks and encode them according to the choosen encoding method (trivial, ext, ECC)
###
covert_message = open(covert_message_file, 'r').read()
cm_array_current = 0

cm_array = [covert_message[i:i+number_of_chars] for i in range(0, len(covert_message), number_of_chars)]
if encoding_method.startswith("trivial"):
    ba_curr = getStringToBinary(cm_array[cm_array_current])

elif encoding_method.startswith("ext"):

    ba_temp= getStringToBinary(cm_array[cm_array_current])
    ba_curr =  ba_temp + getCheckSum(list(ba_temp))
#    masks = getMask(len(list(ba_curr + getCheckSum(list(ba_curr)))),
#                    len(list(ba_curr + getCheckSum(list(ba_curr)))) - targetCount)
    masks = getMask(len(list(ba_curr)),
                    len(list(ba_curr)) - targetCount)
    res = []
    lastHit = 0

elif encoding_methodstartswith("ECC"):
    ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])
else:
    print("Encoding method must either be 'trivial_single', 'ext' or 'ECC' - > exiting")
    exit(1)

###
# Set robust flag, add delay and ignore deltas for robustness, define a timer
###
if encoding_method.endswith("robust"):
    robust=True
    robustdelay=0.5
    robustignore=0.3
    timer = RepeatingTimer(robustdelay,sendARP,signal_arp)

###
# Depending on the mode, set a function to execute for sniffed packets
###
print("========Starting Sniffing=========")
if mode == 'cs':
    sniff(iface=interface, prn =cs_sniffing)
elif mode == 'cr':
    sniff(iface=interface, prn=cr_sniffing)

