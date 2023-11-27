#!/bin/bash

# Number of times to run the scripts
num_runs=1
echo "NONE RANDOM ALL RIGHT"
# Loop to run the scripts multiple times
for ((i=1; i<=num_runs; i++)); do
    echo "Run #$i"

    # Run generate_bins.sh
    ./ABsameBins.sh
    # Run test_correct.sh
    ./testOutput.sh

    echo "Completed run #$i"
    echo "-----------------------"
done

echo "ALL RANDOM ALL WRONG"
for ((i=num_runs + 1; i<=2*num_runs; i++)); do
    echo "Run #$i"

    # Run generate_bins.sh
    ./ABdiffBins.sh
    # Run test_correct.sh
    ./testOutput.sh

    echo "Completed run #$i"
    echo "-----------------------"
done
echo "Finished all runs."

# clean up bins
rm ../alice/*.bin ../bob/*.bin
