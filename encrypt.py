#!/usr/bin/python3

import sys, os, struct
import hmac, hashlib
from base64 import b85encode

import pyshoco, zlib, lzma

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
backend = default_backend()

# Default config and version.
SECRET_PASSWORD=b"some secret key here" # Should be specified by the user
PASSWORD_SALT=b"\x00" # I really need to find a better source of entropy for this
LINETYPES={'uncompressed': 0, 'shoco': 1, 'zlib_small': 2, 'zlib_large': 3, 'lzma': 4}
VERSION=4

# Check if sys.argv has arguments. Set myFile accordingly. Usage is ./file [inFile] [passwordhex] [salthex]
if len(sys.argv) >= 2:
	myFile = open(sys.argv[1], "r")
if len(sys.argv) >= 3:
	SECRET_PASSWORD=bytes.fromhex(sys.argv[2])
if len(sys.argv) == 1:
	myFile = sys.stdin

# Generate secret key from password and salt
MASTER_KEY=Scrypt(salt=PASSWORD_SALT, length=32, n=16384, r=8, p=1, backend=backend).derive(SECRET_PASSWORD)

# Initialize hmac for file
filehmac = hmac.new(MASTER_KEY, None, hashlib.sha256);

# Print version
print(b85encode(struct.pack('>I', VERSION)).decode('ASCII'))

# Loop through lines in stdin
for lineraw in myFile:
	line = bytes(lineraw.rstrip('\n'), 'UTF-8')

	if line:
		# Add line to hmac
		filehmac.update(line)

		# Compress line based on length
		if len(line) > 512: # Test lzma and zlib for over 512 bytes
			compressor = zlib.compressobj(level=6, wbits=-15) # Max (default) window for zlib
			compressed_zlib = compressor.compress(line) + compressor.flush(zlib.Z_FINISH)
			compressed_lzma = lzma.compress(line, format=lzma.FORMAT_RAW, check=-1, preset=None, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}])
			if len(compressed_lzma) < len(compressed_zlib):
				compressed = compressed_lzma
				linetype = bytes((LINETYPES['lzma'],))
			else:
				compressed = compressed_zlib
				linetype = bytes((LINETYPES['zlib_large'],))
		elif len(line) > 64: # Test zlib, shoco, and uncompressed for between 64-512 bytes
			compressor = zlib.compressobj(level=6, wbits=-9) # 512 byte window for zlib
			compressed_zlib = compressor.compress(line) + compressor.flush(zlib.Z_FINISH)
			compressed_shoco = pyshoco.compress(line)
			if len(compressed_zlib) < len(compressed_shoco) and len(compressed_zlib) < len(line):
				compressed = compressed_zlib
				linetype = bytes((LINETYPES['zlib_small'],))
			elif len(compressed_shoco) < len(line):
				compressed = compressed_shoco
				linetype = bytes((LINETYPES['shoco'],))
			else:
				compressed = line
				linetype = bytes((LINETYPES['uncompressed'],))
		else: # Test shoco and uncompressed for under 64 bytes
			compressed = pyshoco.compress(line)
			linetype = bytes((LINETYPES['shoco'],))
			if len(compressed) >= len(line):
				compressed = line
				linetype = bytes((LINETYPES['uncompressed'],))

		# Generate salt and key deterministically.
		linehash = hmac.new(MASTER_KEY, line, hashlib.sha512).digest()
		lineseed = linetype + hmac.new(MASTER_KEY, linehash, hashlib.md5).digest() # An awkward 17-byte seed
		linekey = hmac.new(MASTER_KEY, lineseed, hashlib.sha256).digest()
		linesalt = hmac.new(PASSWORD_SALT, lineseed, hashlib.md5).digest()

		# Encrypt, Encode in base85, Concatenate with Seed
		encryptor = Cipher(algorithms.ChaCha20(linekey, linesalt), None, backend=backend).encryptor()
		encrypted = encryptor.update(compressed) + encryptor.finalize()
		encoded = b85encode(lineseed+encrypted)

		# Print to stdout
		print(str(encoded, 'ASCII'))
	else:
		# Empty line. Add newline to hmac.
		filehmac.update(b'\n')
		print()

# Print final hash
print('H ' + str(b85encode(filehmac.digest()), 'ASCII'))