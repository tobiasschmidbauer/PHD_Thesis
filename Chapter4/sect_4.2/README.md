##textsandalphabets
Contains example texts and aplhabets utilized for the PhD thesis

##or
Contains Overt Receiver Scripts for each hash algorithm utilized and the first hash, that is expected by the OR for 5,000 or 20,000 hashes

##alphabet_analyzer.py <input file> <output file basename>
  creates best and worst alphabet for the text given in the input file

##forwareder_add_cc.py 
Covert Sender adds CI, but each packet is altered to carry CI

##forwarder_add_partial_cc.py 
Covert Sender adds CI and share can be defined as integer from 0 to 100 by the first argument

##forwarder_remove_cc.py
Covert Receiver Script to remove CI and reverse covert to original traffic, if CI are carried

##reverse_forwarder.py
Script is needed at CS and CR to pipe traffic back to the OS

##rules.sh
iptables rules for CS and CR to forward traffic to scripts

##send_hashes.py <file with hashes> <target system>
OS script to send list of hashes to OR
