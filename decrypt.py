#!/usr/bin/python3

import sys, os, struct
import zlib, hmac, hashlib
from base64 import b85decode

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
MASTER_KEY=Scrypt(salt=PASSWORD_SALT, length=32, n=32768, r=8, p=1, backend=backend).derive(SECRET_PASSWORD)

# Initialize hmac for file
filehmac = hmac.new(MASTER_KEY);
realhmac = b'';

# Get version
VERSION = struct.unpack('>I', b85decode(bytes(myFile.readline().rstrip('\n'), 'ASCII')))[0]
if VERSION not in [1]:
	raise ValueError("Version unsupported")

# Loop through lines in stdin
for encodedraw in myFile:
	encoded = encodedraw.rstrip('\n')

	if encoded:
		encodedsplit = encoded.split(' ')
		if encodedsplit[0] == 'H:':
			# Copy over hmac
			realhmac = b85decode(bytes(encodedsplit[1], 'ASCII'))
		else:
			# Generate salt and key from deterministically generated seed.
			lineseed = b85decode(bytes(encodedsplit[0], 'ASCII'))
			linekey = hmac.new(MASTER_KEY, lineseed, hashlib.sha256).digest()
			linesalt = hmac.new(PASSWORD_SALT, lineseed, hashlib.md5).digest()

			# Decode from base85, Decrypt, Decompress
			encrypted = b85decode(bytes(encodedsplit[1], 'ASCII'))
			decryptor = Cipher(algorithms.ChaCha20(linekey, linesalt), None, backend=backend).decryptor()
			compressed = decryptor.update(encrypted) + decryptor.finalize()
			decompressor = zlib.decompressobj(wbits=-15)
			line = decompressor.decompress(compressed)

			# Add line to hmac
			filehmac.update(line)

			# Print to stdout
			print(line.decode('utf-8'))
	else:
		# Empty line. Add newline to hmac.
		filehmac.update(b'\n')
		print()

# Verify final hash. If invalid, exit failure
if not hmac.compare_digest(filehmac.digest(), realhmac):
	raise ValueError("Invalid HMAC")