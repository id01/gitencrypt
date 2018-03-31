#!/usr/bin/python3

import sys, os, struct
import hmac, hashlib
from base64 import b85decode

import pyshoco, zlib, lzma

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
backend = default_backend()

# Default config and version.
SECRET_PASSWORD=b"some secret key here" # Should be specified by the user
PASSWORD_SALT=b"\x00" # I really need to find a better source of entropy for this
LINETYPES={'uncompressed': 0, 'shoco': 1, 'zlib_small': 2, 'zlib_large': 3, 'lzma': 4}

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
realhmac = b'';

# Get version
VERSION = struct.unpack('>I', b85decode(bytes(myFile.readline().rstrip('\n'), 'ASCII')))[0]
if VERSION not in [4]:
	raise ValueError("Version unsupported")

# Loop through lines in stdin
for encodedraw in myFile:
	encoded = encodedraw.rstrip('\n')

	if encoded:
		if encoded[:2] == 'H ':
			# Copy over hmac
			realhmac = b85decode(bytes(encoded[2:], 'ASCII'))
		else:
			decoded = b85decode(bytes(encoded, 'ASCII'))

			# Generate salt and key from deterministically generated seed.
			lineseed = decoded[:17]
			linekey = hmac.new(MASTER_KEY, lineseed, hashlib.sha256).digest()
			linesalt = hmac.new(PASSWORD_SALT, lineseed, hashlib.md5).digest()

			# Decode from base85, Decrypt
			encrypted = decoded[17:]
			decryptor = Cipher(algorithms.ChaCha20(linekey, linesalt), None, backend=backend).decryptor()
			compressed = decryptor.update(encrypted) + decryptor.finalize()

			# Get linetype and decompress accordingly
			linetype = decoded[0]
			if linetype == LINETYPES['uncompressed']:
				line = compressed
			elif linetype == LINETYPES['shoco']:
				line = pyshoco.decompress(compressed)
			elif linetype == LINETYPES['zlib_small']:
				decompressor = zlib.decompressobj(wbits=-9)
				line = decompressor.decompress(compressed)
			elif linetype == LINETYPES['zlib_large']:
				decompressor = zlib.decompressobj(wbits=-15)
				line = decompressor.decompress(compressed)
			elif linetype == LINETYPES['lzma']:
				line = lzma.decompress(compressed, format=lzma.FORMAT_RAW, check=-1, preset=None, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}])
			else:
				raise ValueError("Invalid Line Type Header %x" % linetype);

			# Verify single line
			linehash = hmac.new(MASTER_KEY, line, hashlib.sha512).digest()
			if not hmac.compare_digest(hmac.new(MASTER_KEY, linehash, hashlib.md5).digest(), lineseed[1:]):
				raise ValueError("Integrity Check Failed: Invalid Line HMAC");

			# Add line to file hmac
			filehmac.update(line)

			# Print to stdout
			print(line.decode('utf-8', 'replace'))
	else:
		# Empty line. Add newline to hmac.
		filehmac.update(b'\n')
		print()

# Verify final hash. If invalid, exit failure
if not hmac.compare_digest(filehmac.digest(), realhmac):
	raise ValueError("Integrity Check Failed: Invalid File HMAC")