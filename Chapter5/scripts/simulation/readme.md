# Simulation
Simulation tool, to simulate Dust-Ext mode.
## Compilation

- compile match-simu.c
  - ```gcc match-simu.c -o sim.out```
- reads in aes.h aes.c
- reads in sha3.h sha3.c if HASHSHA3 defined
- compilation tested with gcc on windows

## Command Line Parameters:
- `-s ulong`: seed for PRNG
- `-b uint`: bit length of secret message, i.e., h-c, h<=32
- `-c uint`: bit length of checksum, i.e., c 
- `-f string`: file name for output
- `-m uint`: secret message

## In current version:
Tests DUST-Ext according to clps and settings:

- HASHSHA3: if defined, SHA3 used for checksum
- HASHCRC: if defined, CRC8 used for checksum
- cannot be defined both
- if neither defined, ad hoc checksum is used

Alternative uses explained in `main()`
  