import sys
from scapy.all import *



def main():
    file_with_hashes = sys.argv[1]
    target = sys.argv[2]

    number_of_hashes= len(open(file_with_hashes,'r').readlines()) - 1
    list_of_hashes = open(file_with_hashes,'r').readlines()

    while number_of_hashes > 1:
        number_of_hashes -= 1
        current_hash = list_of_hashes[number_of_hashes][:-1]

        packet = IP(dst=target) /TCP (dport =42424, sport=random.randint(1025,65500), flags ='S')/current_hash
        send(packet)
        time.sleep(5)

if __name__ == "__main__":
    main()
