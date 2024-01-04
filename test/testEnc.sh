#!/bin/bash

for i in {1..5}
do
    # Construct file names
    file_bob="../bob/segment${i}.bin"
    file_alice="../alice/segment${i}.bin"

    # Check if files exist
    if [[ -f "$file_bob" && -f "$file_alice" ]]; then
        # Calculate hash values using sha256sum
        hash_bob=$(shasum "$file_bob" | awk '{ print $1 }')
        hash_alice=$(shasum "$file_alice" | awk '{ print $1 }')

        # Compare hash values
        if [ "$hash_bob" == "$hash_alice" ]; then
            echo "segment${i}.bin: Files are the same."
            
        else
            echo "segment${i}.bin: Files are different."
        fi
    else
        echo "segment${i}.bin: One or both files do not exist."
    fi
done
