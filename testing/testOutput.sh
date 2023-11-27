#!/bin/bash

# Directories for .bin files and Python scripts
alice_bin_files_directory="./alice"
bob_bin_files_directory="./bob"
bob_script_directory="./bob"
alice_script_directory="./alice"
# Running bob.py in the background
# echo "Running bob.py..."
bob_bin_files=($(ls "${bob_bin_files_directory}" | grep 'segment.*\.bin' | head -n 5))
python3 "${bob_script_directory}/bob.py" "${bob_bin_files[@]/#/${bob_bin_files_directory}/}" > bob_output.txt &bob_pid=$!

# Wait for the server to be ready
sleep 2

# Running alice.py and capturing output
# echo "Running alice.py..."

alice_output=$(python3 "${alice_script_directory}/alice.py" "${bob_bin_files[@]/#/${bob_bin_files_directory}/}" > alice_output.txt) 

# # Check if Bob's process is still running and kill it
# if ps -p $bob_pid > /dev/null
#    kill $bob_pid

# Function to extract names and verifications from output
extract_verification_info() {
    cat "$1" | awk '/segment[0-9]+\.bin matches with segment #[0-9]+/' | sort
}


# Extract and compare verification info
bob_verification_info=$(extract_verification_info bob_output.txt)
alice_verification_info=$(extract_verification_info alice_output.txt)

if [ "$bob_verification_info" == "$alice_verification_info" ]; then
    echo "Test case is correct. Verification info matches."
else
    echo "Test case is incorrect. Verification info does not match."
fi

# Cleanup
# rm bob_output.txt alice_output.txt
