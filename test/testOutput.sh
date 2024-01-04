#!/bin/bash

# Directories for .bin files and Python scripts
alice_bin_files_directory="../alice"
bob_bin_files_directory="../bob"
bob_script_directory="../bob"
alice_script_directory="../alice"
# Running bob.py in the background
# echo "Running bob.py..."
bob_bin_files=($(ls "${bob_bin_files_directory}" | grep 'segment.*\.bin' | head -n 5))
python3 "${bob_script_directory}/bob.py" "${bob_bin_files[@]/#/${bob_bin_files_directory}/}" > bob_output.txt &bob_pid=$!

# Wait for the server to be ready
sleep 2

# Running alice.py and capturing output
alice_bin_files=($(ls "${alice_bin_files_directory}" | grep 'segment.*\.bin' | head -n 5))
$(python3 "${alice_script_directory}/alice.py" "${alice_bin_files[@]/#/${alice_bin_files_directory}/}" > alice_output.txt) 

./testEnc.sh >> bob_output.txt
./testEnc.sh >> alice_output.txt
# Function to extract names and verifications from output
extract_alice_connection() {
    awk 'Failed to connect to Bob' "$1"
}
extract_bob_connection() {
    awk 'error on socket creation' "$1" 
}

extract_verification_info() {
    awk '/segment[0-9]+\.bin matches with segment #[0-9]+/' "$1" | sort
}
extract_encryption_same() {
    awk '/segment[0-9]+\.bin: Files are the same\./' "$1" | sort
}

extract_encryption_diff() {
    awk '/segment[0-9]+\.bin: Files are different\./' "$1" | sort
}
extract_encryption_nonexistent() {
    awk '/segment[0-9]+\.bin: One or both files do not exist\./' "$1" | sort
}

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
# Extract and compare verification info
bob_connect=$(extract_bob_connection bob_output.txt)
alice_connect=$(extract_alice_connection alice_output.txt)
bob_verification_info=$(extract_verification_info bob_output.txt; extract_encryption_same bob_output.txt; extract_encryption_diff bob_output.txt; extract_encryption_nonexistent bob_output.txt;)
alice_verification_info=$(extract_verification_info alice_output.txt; extract_encryption_same alice_output.txt; extract_encryption_diff alice_output.txt; extract_encryption_nonexistent alice_output.txt)

if [ "$bob_connect" != "" ] || [ "$alice_connect" != "" ]; then
    echo -e "Connection failed ${RED}✘${NC}"
fi

if [ "$bob_verification_info" == "$alice_verification_info" ] && [ "$bob_connect" == "" ] && [ "$alice_connect" == "" ]; then
    echo -e "Test passed ${GREEN}✔${NC}"
else
    echo -e "Test failed ${RED}✘${NC}"
fi