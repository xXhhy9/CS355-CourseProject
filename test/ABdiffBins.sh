#!/bin/bash

# Directories to store files
dir1="../alice"
dir2="../bob"


# Delete existing 'segment' files in both directories
rm -f "${dir1}/segment"*.bin
rm -f "${dir2}/segment"*.bin

# Number of files to generate
num_files=5


# Generate at least 5 binary files and store in directories
for ((i=1; i<=num_files; i++)); do
    output_file="segment${i}.bin"

    dd if=/dev/urandom of="${dir1}/${output_file}" bs=1M count=500 &>/dev/null
    dd if=/dev/urandom of="${dir2}/${output_file}" bs=1M count=500 &>/dev/null
done