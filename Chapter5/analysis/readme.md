# analysis-CCS-2022.xlsx
The file contains multiple sheets:

- Basic dist+bw contains calculation of distance and bandwith for DUST-Basic according to formulae from paper
  plus simulation results from match-simu.c

- Ext dist+bw contains calculation of distance and bandwidth for DUST-Ext according to formulae from paper
  plus simulation results from match-simu.c for different checksums and different seeds

- Ext-ECC dist+bw contains calculations of distance and bandwidth for DUST-Ext with ECC instead of checksum according to formulae from paper

- Cloud contains copies of distance/bandwidth pairs from all calulations and simulations above, plus visualisation.
  Sorting in order of distance (starting in column T) used to create zooms. \
  Sorting in order of distance separately for Basic and Ext (starting in column AK) used to create zooms with differing colors for Basic and Ext.

- Front contains copies of distance/bandwidth pairs from all calulations and simulations above. \
  Sorting according to distance. Yellow marks: multiple variants with same distance and bandwidth.
  Red marks: dominated variants, not on Pareto front.