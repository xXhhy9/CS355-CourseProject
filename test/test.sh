#!/bin/bash

# Number of times to run the scripts
num_runs=1
rm ../alice/seg* ../bob/seg*
# Loop to run the scripts multiple times
for ((i=1; i<=num_runs; i++)); do
    echo "Run #$i"
    # Run generate_bins.sh
    ./ABsameBins.sh
    # Run test_correct.sh
    ./testOutput.sh
    echo "-----------------------"
done
rm ../alice/seg* ../bob/seg*
for ((i=num_runs + 1; i<=2*num_runs; i++)); do
    echo "Run #$i"
    # Run generate_bins.sh
    ./ABdiffBins.sh
    # Run test_correct.sh
    ./testOutput.sh
    echo "-----------------------"
done
rm ../alice/seg* ../bob/seg*
echo "Finished all runs."