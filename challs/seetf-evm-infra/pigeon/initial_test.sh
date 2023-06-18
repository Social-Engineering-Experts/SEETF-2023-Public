#!/bin/bash

RED='\033[0;31m'

# Get current directory name
current_dir=${PWD##*/}

# Append with "test_folder"
forge_folder=${current_dir}_test_folder

# Check if the directory already exists
if [ -d "$forge_folder" ]; then
    # If it does, delete it
    echo -e "${RED}Directory $forge_folder exists. Deleting...${NC}"
    rm -rf $forge_folder
fi

# Run forge init with the new folder name
forge init $forge_folder

# Delete the src folder in the new forge folder
rm -rf ./$forge_folder/src

# Copy src files from current directory to new forge folder's src
cp -r ./src ./$forge_folder/

# Change directory into new forge folder
cd $forge_folder

# Run forge remappings and save output to remappings.txt
forge remappings > remappings.txt

# Change directory back to the original location
cd ..

echo "Operation completed successfully."
