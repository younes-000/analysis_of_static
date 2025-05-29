# this script will take .exe and .dll files and analyze them using static analysis techniques

import hashlib # this module is used to calculate the hash of the files
import pefile  # this module is used to parse PE files (Portable Executable files)
import sys
import re
import os




def calcultae_file_hash(file_path):
    hashes = {
        'MD5': hashlib.md5(), # MD5 hash object
        'SHA1': hashlib.sha1(), # SHA1 hash object
        'SHA256': hashlib.sha256() # SHA256 hash object
    }
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192): # Read the file in chunks of 8192 bytes
            # Update each hash object with the chunk of data read from the file
            for hash_name, hash_obj in hashes.items():
                hash_obj.update(chunk)
    # Return the calculated hashes as a dictionary
    return {hash_name: hash_obj.hexdigest() for hash_name, hash_obj in hashes.items()}



def extract_strings(file_path, min_length=4): # Extract printable strings from a binary file
    strings = [] # List to hold the extracted strings
    with open(file_path, 'rb') as f: # Open the file in binary mode
        data = f.read() # Read the entire file content
        
        strings = re.findall(rb'[ -~]{%d,}' % min_length, data) # Find all sequences of printable ASCII characters of at least min_length
    # Decode bytes to string and return the list of strings
    return [s.decode('utf-8', errors='ignore') for s in strings] #  Decode bytes to string and return the list of strings



def parse_pe(file_path): # Parse the PE file and extract relevant information
    pe = pefile.PE(file_path) # Load the PE file using pefile
    info = { 
        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), # Entry point of the PE file
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase), # Base address of the image
        'sections': [], # List to hold section information
    }
    for section in pe.sections: # Iterate through each section in the PE file
        info['sections'].append({
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_address': hex(section.VirtualAddress),
            'size': section.SizeOfRawData,
            'entropy': section.get_entropy(),
        })
    return info


def detect_indicators(strings): # Detect indicators of compromise (IOCs) in the extracted strings
    indicators = {'ips': [], 'urls': [], 'file_paths': []} # Dictionary to hold detected indicators
    ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b') # Regex to match IPv4 addresses
    url_regex = re.compile(r'https?://[^\s]+') # Regex to match URLs
    path_regex = re.compile(r'[A-Z]:\\[^:*?"<>|\r\n]+') # Regex to match Windows file paths

    for s in strings:
        if ip_regex.search(s):
            indicators['ips'].append(s)
        if url_regex.search(s):
            indicators['urls'].append(s)
        if path_regex.search(s):
            indicators['file_paths'].append(s)

    return indicators


file_path = sys.argv[1]

hashes = calcultae_file_hash(file_path)
strings = extract_strings(file_path)
pe_info = parse_pe(file_path)
ioc_hits = detect_indicators(strings)

print("\n=== Hashes ===")
print(hashes)

print("\n=== PE Info ===")
print(pe_info)

print("\n=== Strings (First 30) ===")
print(strings[:30])

print("\n=== Detected Indicators ===")
print(ioc_hits)
