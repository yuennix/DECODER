import base64
import codecs
import binascii
import zlib
import bz2
import re
import sys

def print_header():
    print("""
  _____       _____            _ 
 |  __ \     |  __ \          | |
 | |  | | ___| |  | | __ _  __| |
 | |  | |/ _ \ |  | |/ _` |/ _` |
 | |__| |  __/ |__| | (_| | (_| |
 |_____/ \___|_____/ \__,_|\__,_|  Made by Double
    """)

def extract_b64_from_obfuscated(text):
    patterns = [
        r"base64\.b64decode\(b['\"]([A-Za-z0-9+/=]+)['\"]",
        r"base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]",
        r"exec\(base64\.b64decode\(b['\"]([A-Za-z0-9+/=]+)['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None

def read_multiline_input(prompt):
    print(prompt)
    print("(Paste your input below. Enter a blank line when done)")
    lines = []
    while True:
        try:
            line = input()
            if line == "" and lines:
                break
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines)

print_header()

print("Choose decoding type:")
print("1. Base64")
print("2. URL Encoding")
print("3. Hexadecimal")
print("4. Zlib Compression")
print("5. Bzip2 Compression")

decoding_type = input("Enter decoding type number: ")

raw_input_text = read_multiline_input("Enter encoded code:")

encoded_code = raw_input_text.strip()

if decoding_type == "1":
    extracted = extract_b64_from_obfuscated(encoded_code)
    if extracted:
        print("[*] Detected obfuscated Python file — extracted Base64 string automatically.")
        encoded_code = extracted
    try:
        decoded_code = base64.b64decode(encoded_code).decode("utf-8")
    except Exception as e:
        print(f"Error decoding Base64: {e}")
        sys.exit(1)

elif decoding_type == "2":
    try:
        decoded_code = codecs.decode(encoded_code, 'unicode_escape')
    except Exception as e:
        print(f"Error decoding URL encoding: {e}")
        sys.exit(1)

elif decoding_type == "3":
    try:
        decoded_code = binascii.unhexlify(encoded_code).decode("utf-8")
    except Exception as e:
        print(f"Error decoding Hexadecimal: {e}")
        sys.exit(1)

elif decoding_type == "4":
    try:
        decoded_code = zlib.decompress(encoded_code.encode("utf-8")).decode("utf-8")
    except Exception as e:
        print(f"Error decompressing Zlib: {e}")
        sys.exit(1)

elif decoding_type == "5":
    try:
        decoded_code = bz2.decompress(base64.b64decode(encoded_code)).decode("utf-8")
    except Exception as e:
        print(f"Error decompressing Bzip2: {e}")
        sys.exit(1)

else:
    print("Invalid decoding type.")
    sys.exit(1)

print("\nDecoded code:")
print(decoded_code)
