from struct import pack
import sys

from scapy.all import *
from bitstring import BitArray
from operator import xor
import numpy as np
import hashlib
from netaddr import *
import bchlib
import math

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
global encoding_method ## Method coding is achieved with
global timeslice_total ## timeslice to encode position within the hash
global timeslice_delay ## delay to calculate with for additional runtime
global number_of_chars
global bch

BCH_POLYNOMIAL = 8219
BCH_BITS = 1
bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)


def getStringToBinary(string):
    bin_value=BitArray(string.encode('utf-8')).bin
    return bin_value

def getStringToBinary_BCH(string):
    global bch
    bin_value=BitArray(string.encode('utf-8'))
    ecc = bch.encode(bin_value.bytes)
    #print('ECC: ',BitArray(ecc).bin, "\nBIN: ", bin_value.bin)
    return bin_value.bin + BitArray(ecc).bin

def getMatchPercent(a,b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b))/len(a)

def getMatchCount(a,b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b))

def getHashValue(input):
    #hash = hashlib.sha512(input)
    try:
        hash = hashlib.sha512(input)
    except TypeError:
        hash= hashlib.sha512(input.encode('utf-8'))
    return hash

def getInputValues(packet):
    string = ""
    timestamp = str(packet.time)
    if IPv6 in packet:
        string = str(packet[IPv6].src) + timestamp
    elif IP in packet:
        string = str(packet[IP].chksum) + timestamp
    elif ARP in packet:
        string = str(packet[ARP].pdst) + str(packet[ARP].psrc) + timestamp

    #s1= str(pkt[IPv6].fl).encode('utf-8') ## utilize the flow label (like id for ipv4)
    #s2= str(pkt[IPv6].fl)
    #s3= str(pkt[IPv6].cksum)

    return string

def isPktOfInterest(packet):
    global hwv4_broadcast  ## MAC address for broadcasts
    global ipv4_broadcast  ## IP address for broadcasts
    global hwv6_broadcast  ## MAC address for broadcasts
    global ipv6_broadcast  ## IP address for broadcasts

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
            if str(packet[Ether].dst) == hwv4_broadcast:
                return True
        else:
            return False
    except:
        return False

def kbits(n, k):
    result = []
    for bits in itertools.combinations(range(n), k):
        s = ['0'] * n
        for bit in bits:
            s[bit] = '1'
        result.append(''.join(s))
    return result

def getMask(n,k):
    result = []
    for i in range(k+1):
        res = kbits(n,i)
        res.reverse()
        result.append(res)
    ret = [item for sublist in result for item in sublist]
    ret = list(map(list,ret))
    ret = list(map(lambda x: [int(y) for y in x],ret))
    return ret

def getCheckSum(hash):
    if number_of_chars == 1:
        return('{0:04b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    elif number_of_chars == 2:
        return('{0:05b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    else:
        print("Checksum not Calculated")
        exit(100)

def testCheckSum(hash):
    if number_of_chars == 1:
        return(list(map(int,list('{0:04b}'.format(np.count_nonzero(np.array(hash[:-4]).astype(int)))))) == hash[-4:])
    elif number_of_chars == 2:
        return(list(map(int,list('{0:05b}'.format(np.count_nonzero(np.array(hash[:-5]).astype(int)))))) == hash[-5:])
    else:
        print("Checksum not Calculated")
        exit(100)

def checkBitFlips(hash, orig):
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
            if(cur_flipped[:cflen] == orig):
                return True
            else:
                return False
        else:
            pass
    return False


counter_interest = 0
counter_total = 0
crit_fraction_high = 0.95
crit_fraction_low= 0.05
oldPkt = None
badPkt = None
sentPkt = None

delay = 0.5
X = 0.125

def offlineMode_Basic(packet):
    global counter_total
    global counter_interest
    global crit_fraction_high
    global crit_fraction_low
    global ba_curr
    global cm_array_current
    global res
    global lastHit
    global oldPkt
    global badPkt
    global sentPkt

    counter_total += 1

    if (not isPktOfInterest(packet)):
        return

    if (oldPkt is None and badPkt is None):
        oldPkt = packet
        return
    elif (oldPkt is not None and float(packet.time - oldPkt.time) < delay):
        oldPkt = None
        badPkt = packet
        return
    elif (badPkt is not None and float(packet.time - badPkt.time) <= delay):
        badPkt = packet
        return
    elif(badPkt is not None and float(packet.time - badPkt.time) > delay):
        oldPkt = packet
        badPkt = None
        return
    else:
        currTarget = ba_curr
        currTarget = list(map(int,currTarget))
        counter_interest += 1
        critical_fraction, seconds = math.modf(oldPkt.time)
        if (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low):
            res.append("{},{},{},{},{},{}\n".format(False, counter_interest, counter_total, -1, oldPkt.time, -1))
            oldPkt=packet
            return

        hash = getHashValue(getInputValues(oldPkt))
        hash = list(map(int,list(BitArray(bytes=hash.digest()).bin[:len(currTarget)])))
        matchPerc = getMatchPercent(hash,list(currTarget))

        if (matchPerc == 1.0):
            if lastHit != 0:
                res.append("{},{},{},{},{},{}\n".format(True, counter_interest, counter_total, matchPerc, oldPkt.time, (oldPkt.time-lastHit)))
            else:
                res.append("{},{},{},{},{},{}\n".format(True, counter_interest, counter_total, matchPerc, oldPkt.time, -1))
            cm_array_current+=1
            ba_curr = getStringToBinary(cm_array[cm_array_current])
            lastHit = oldPkt.time
            sentPkt = oldPkt
        else:
            res.append("{},{},{},{},{},{}\n".format(False, counter_interest, counter_total, matchPerc, oldPkt.time, -1))

        oldPkt=packet

def offlineMode_Ext(packet):
    global counter_total
    global counter_interest
    global crit_fraction_high
    global crit_fraction_low
    global ba_curr
    global cm_array_current
    global res
    global lastHit
    global oldPkt
    global badPkt
    global sentPkt

    counter_total += 1

    if (not isPktOfInterest(packet)):
        return

    if (oldPkt is None and badPkt is None):
        oldPkt = packet
        return
    elif (oldPkt is not None and float(packet.time - oldPkt.time) < delay):
        oldPkt = None
        badPkt = packet
        return
    elif (badPkt is not None and float(packet.time - badPkt.time) < delay):
        badPkt = packet
        return
    elif(badPkt is not None and float(packet.time - badPkt.time) > delay):
        oldPkt = packet
        badPkt = None
        return
    else:
        currTarget = ba_curr+getCheckSum(list(ba_curr))
        currTarget = list(map(int,currTarget))
        counter_interest += 1
        critical_fraction, seconds = math.modf(oldPkt.time)
        if (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low):
            res.append("{},{},{},{},{},{}\n".format(False, counter_interest, counter_total, -1, oldPkt.time, -1))
            oldPkt=packet
            return

        
        hash = getHashValue(getInputValues(oldPkt))
        hash = list(map(int,list(BitArray(bytes=hash.digest()).bin[:len(currTarget)])))
        matchCount = getMatchCount(hash,list(currTarget))

        if (matchCount >= targetCount):
            if checkBitFlips(hash,ba_curr):
                if lastHit != 0:
                    res.append("{},{},{},{},{},{}\n".format(True, counter_interest, counter_total, matchCount, oldPkt.time, (oldPkt.time-lastHit)))
                else:
                    res.append("{},{},{},{},{},{}\n".format(True, counter_interest, counter_total, matchCount, oldPkt.time, -1))
                cm_array_current+=1
                ba_curr = getStringToBinary(cm_array[cm_array_current])
                lastHit = oldPkt.time
                sentPkt = oldPkt
            else:
                res.append("{},{},{},{},{},{}\n".format(False, counter_interest, counter_total, matchCount, oldPkt.time,-1))


        else:
            res.append("{},{},{},{},{},{}\n".format(False, counter_interest, counter_total, matchCount, oldPkt.time,-1))
        oldPkt = packet



if sys.argv[1] == "--help" or sys.argv[1] == "-h":
    print("Minimal history covert channel\n===Offline Mode===")
    print("Usage:")
    print("offlineMode.py <Covert Message File> <# of bytes at once> <pcap File> <mode [basic,ext]> <broadcast IP of recording> <output File> [<Match Count>]")
    exit(5)

print("========Loading configuration=========")
covert_message_file = sys.argv[1]
number_of_chars = int(sys.argv[2])
inputFile = sys.argv[3]
mode = sys.argv[4]
hwv4_broadcast = "ff:ff:ff:ff:ff:ff"
ipv4_broadcast = sys.argv[5]
hwv6_broadcast = "33:33"
ipv6_broadcast = "ff0"
output = sys.argv[6]
if len(sys.argv) > 7:
    targetCount = int(sys.argv[7])
else:
    targetCount = 0


print("========Reading Covert Message=========")
covert_message = open(covert_message_file, 'r').read()
cm_array_current = 0
cm_array = [covert_message[i:i+number_of_chars] for i in range(0, len(covert_message), number_of_chars)]
ba_curr = getStringToBinary(cm_array[cm_array_current])

masks = getMask(len(list(ba_curr+getCheckSum(list(ba_curr)))),len(list(ba_curr+getCheckSum(list(ba_curr))))-targetCount)
res = []
lastHit = 0

print("========Starting Offline Mode=========")
if mode == 'basic':
    sniff(offline=inputFile, prn = offlineMode_Basic)
elif mode == 'ext':
    sniff(offline=inputFile, prn = offlineMode_Ext)

print("Opening Output File ", output)
with open(output, 'w') as f:
    f.write("match,counter_interest,counter_total,matchPerc,matchTime,timeSinceLastHit\n")
    for i in res:
        f.write(i)
    f.close()

print("-------- PoI ---------")
print(counter_interest)