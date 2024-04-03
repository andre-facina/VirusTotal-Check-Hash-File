#!/usr/bin/env python3

# Author: Andre Facina
# This script will generate the SHA256 hash from a input file -f and you submit to VirusTotal. The result is if the file is malicious or not

import argparse
import hashlib
import requests


# Put here your VirusTotal API KEY
VIRUSTOTAL_API_KEY = 'CHANGEIT'

# Calculate the Hash
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

# Submit the hash to VirusTotal
def check_file_hash(file_path):
    sha256_hash = calculate_sha256(file_path)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': sha256_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        result = response.json()
        if 'positives' in result:
            if result['positives'] > 0:
                print("The file is malicious")
            else:
                print("The file is not detected as malicious")
        else:
            print("VirusTotal doesn't have a report for this file hash yet")
    else:
        print("Error")


def main():
    parser = argparse.ArgumentParser(description='Check if a file is malicious using VirusTotal.')
    parser.add_argument('-f', '--file', help='Path to the file to check', required=True)
    args = parser.parse_args()

    check_file_hash(args.file)


if __name__ == "__main__":
    main()
