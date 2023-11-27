#!/bin/bash

# Number of times to run the scripts
num_runs=10
echo "NONE RANDOM ALL RIGHT"
# Loop to run the scripts multiple times
for ((i=1; i<=num_runs; i++)); do
    echo "Run #$i"

    # Run generate_bins.sh
    ./generate_bins.sh
    # Run test_correct.sh
    ./test_correct.sh

    echo "Completed run #$i"
    echo "-----------------------"
    sleep 10
done
echo "ALL RANDOM ALL WRONG"
for ((i=num_runs + 1; i<=2*num_runs; i++)); do
    echo "Run #$i"

    # Run generate_bins.sh
    ./generate_bins2.sh
    # Run test_correct.sh
    ./test_correct.sh

    echo "Completed run #$i"
    echo "-----------------------"
    sleep 10
done
echo "Finished all runs."
