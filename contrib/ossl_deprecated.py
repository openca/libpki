#!/usr/bin/env python3

import os
import re
import argparse

# Create the parser and add arguments
parser = argparse.ArgumentParser()
parser.add_argument('--path', default='./', help='Path to the source code directory')
parser.add_argument('--output', default='ossl_deprecated.txt', help='Output file')
args = parser.parse_args()

# Directory of your source code
source_code_dir = args.path

pattern = re.compile(r'OSSL_DEPRECATEDIN_.+?\s*\(.*?\)')

with open(args.output, 'w') as output_file:
    for root, dirs, files in os.walk(source_code_dir):
        for file in files:
            if file.endswith(".c") or file.endswith(".h"):
                with open(os.path.join(root, file), "r") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines, start=1):
                        if pattern.search(line):
                            # output only the name of the deprecated function
                            match = pattern.search(line)
                            if match:
                                deprecated_func = match.group().split('(')[0].split()[-1]
                                if deprecated_func == 'int':
                                    deprecated_func = match.group().split('(')[0].split()[-2]
                                if not 'OSSL_DEPRECATEDIN_' in deprecated_func and not 'OSSL_DEPRECATED' in deprecated_func:
                                    output_file.write(f"{deprecated_func.lstrip('*')}\n")
                                # output_file.write(f"[{os.path.join(root, file)}:{i}] {deprecated_func}\n")
                                # output_file.write(f"[{os.path.join(root, file)}:{i}] {line.strip()}\n")