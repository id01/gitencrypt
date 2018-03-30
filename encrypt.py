#!/usr/bin/python3

import sys, os
import zlib, hmac, hashlib
from base64 import b85encode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
backend = default_backend()

# Default config
SECRET_PASSWORD=b"some secret key here"
PASSWORD_SALT=b"\xc4X\xd2\x03\xa7q\x08O \xc7\x01BJX\xa7\xab\xee\xa6\x182\xd1\x08\xcb6\xbf\xb4I\xf2\x81\x05m\x99"

# Check if sys.argv has arguments. Set myFile accordingly. Usage is ./file [inFile] [passwordhex] [salthex]
if len(sys.argv) >= 2:
	myFile = open(sys.argv[1], "r")
if len(sys.argv) >= 3:
	SECRET_PASSWORD=bytes.fromhex(sys.argv[2])
if len(sys.argv) >= 4:
	PASSWORD_SALT=bytes.fromhex(sys.argv[3])
if len(sys.argv) == 1:
	myFile = sys.stdin

# Generate secret key from password and salt 
MASTER_KEY=Scrypt(salt=PASSWORD_SALT, length=32, n=65536, r=8, p=1, backend=backend).derive(SECRET_PASSWORD)

# Initialize hmac for file
filehmac = hmac.new(MASTER_KEY);

# Loop through lines in stdin
for lineraw in myFile:
	line = bytes(lineraw.rstrip('\n'), 'UTF-8')

	if line:
		# Add line to hmac
		filehmac.update(line)

		# Generate salt and key deterministically. I'm worried about people using the salt to bruteforce lines.
		linehash = hmac.new(MASTER_KEY, line, hashlib.sha512).digest()
		lineseed = hmac.new(MASTER_KEY, linehash, hashlib.md5).digest() # I need to change this to a more secure (and efficient) method
		linekey = hmac.new(MASTER_KEY, lineseed, hashlib.sha256).digest()
		linesalt = hmac.new(PASSWORD_SALT, lineseed, hashlib.md5).digest()

		# Compress, Encrypt, Encode in base85, Concatenate with Seed
		compressor = zlib.compressobj(level=6, wbits=-15)
		compressed = compressor.compress(line) + compressor.flush(zlib.Z_FINISH)
		encryptor = Cipher(algorithms.ChaCha20(linekey, linesalt), None, backend=backend).encryptor()
		encrypted = encryptor.update(compressed) + encryptor.finalize()
		encoded = b85encode(lineseed) + b' ' + b85encode(encrypted)

		# Print to stdout
		print(str(encoded, 'ASCII'))
	else:
		# Empty line. Add newline to hmac.
		filehmac.update(b'\n')
		print()

# Print final hash
print('H: ' + str(b85encode(filehmac.digest()), 'ASCII'))