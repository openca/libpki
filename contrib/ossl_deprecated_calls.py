#!/usr/bin/env python3

import os
import re
import argparse

# Create the parser and add arguments
parser = argparse.ArgumentParser()
parser.add_argument('--path', default='./src', help='Path to the source code directory')
parser.add_argument('--output', default='ossl_deprecated_calls.txt', help='Output file')
parser.add_argument('--deprecated', default='README.OSSL_DEPRECATED', help='File with list of deprecated functions')
args = parser.parse_args()

# Read the list of deprecated functions
with open(args.deprecated, 'r') as f:
    deprecated_functions = [line.strip() for line in f]
    
# Directory of your source code
source_code_dir = args.path

with open(args.output, 'w') as output_file:
    for root, dirs, files in os.walk(source_code_dir):
        for file in files:
            if file.endswith(".c") or file.endswith(".h"):
                with open(os.path.join(root, file), "r") as f:
                    lines = f.readlines()
                    file_printed = False
                    for i, line in enumerate(lines, start=1):
                        if line.strip() == "":
                            continue
                        for function in deprecated_functions:
                            if function == "":
                                continue
                            if re.search(rf"\b{function}\b", line):
                                if not file_printed:
                                    output_file.write(f"\nFile: {os.path.join(root, file)}\n")
                                    file_printed = True
                                output_file.write(f"  - Line: {i}, Function: {function}()\n")