// Headers
#include "header/includes.h"
#include "header/config.h"
#include "header/utilities.h"
#include "header/wrappers.h"

/* MAIN FUNCTIONS */
// Function Prototypes
enum status runEncrypt(FILE* inFile, FILE* outFile, byte* MASTER_KEY);
enum status runDecrypt(FILE* inFile, FILE* outFile, byte* MASTER_KEY);

// Constants
const unsigned int LINESEED_LEN=16, SHA256_LEN=32; // Note: Only the first 16 bytes of linesalt will be used.

// Main function
int main(int argc, char* argv[]) {
	// Check input
	if (argc != 4) {
		perror("Usage: ./gitcrypt [encrypt|decrypt] [file] [secret_password]");
		return 254;
	}

	// Set mode
	if (argv[1][0] != 'e' && argv[1][0] != 'd') {
		perror("Invalid input.");
		return 254;
	}
	unsigned char mode = argv[1][0];

	// Open input file
	FILE* inFile = fopen(argv[2], "r");

	// Generate master key from password using scrypt-16384-8-1
	unsigned char* MASTER_KEY = malloc(MASTER_KEY_LEN);
	scrypt(argv[3], strlen(argv[3]), "", 0, 13, 3, 0, MASTER_KEY, MASTER_KEY_LEN); // argv[3] is secret_password

	// Run encrypt/decrypt
	if (mode == 'e') {
		return runEncrypt(inFile, stdout, MASTER_KEY);
	} else {
		return runDecrypt(inFile, stdout, MASTER_KEY);
	}
}

// Function to encrypt/compress a file
enum status runEncrypt(FILE* inFile, FILE* outFile, unsigned char* MASTER_KEY) {
	// Initialize hmac for file
	HMAC_CTX* fileHMAC;
	fileHMAC = HMAC_CTX_new();
	HMAC_Init_ex(fileHMAC, MASTER_KEY, MASTER_KEY_LEN, EVP_sha256(), NULL);

	// Swap version bytes to big-endian, encode in base85, then output and update HMAC
	uint32_t VERSION_SWAP = htonl(VERSION);
	char VERSION_ENCODED[7];
	Z85_encode((byte*)(&VERSION_SWAP), VERSION_ENCODED, 4);
	VERSION_ENCODED[5] = '\n'; VERSION_ENCODED[6] = 0;
	fputs(VERSION_ENCODED, outFile);
	if (HMAC_Update(fileHMAC, (byte*)(&VERSION_SWAP), 4) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }

	// Loop through lines in inFile
	char *line, *encoded; size_t line_len, encoded_len, encoded_max_len;
	byte *compressed, *encrypted, linetype; size_t compressed_len, encrypted_len;
	unsigned int dummy; // Dummy value
	byte lineseed[LINESEED_LEN], linekey[SHA256_LEN], linesalt[SHA256_LEN];
	while (!feof(inFile) && !ferror(inFile)) {
		// Get next line and length
		line = NULL; line_len = 0;
		line_len = getline(&line, &line_len, inFile);

		// Perform operation on line
		if (line_len == -1) { // Failed to read line
			// Do nothing
		} else if (line[0] == '\n') { // Empty Line. Print newline and update HMAC with only newline.
			fputc('\n', outFile);
			if (HMAC_Update(fileHMAC, "\n", 1) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }
		} else { // Line with stuff
			// Remove newline if it exists. Otherwise, this is the last line, but it doesn't matter here.
			line_len -= (line[line_len-1] == '\n');

			// Update HMAC without newline
			if (HMAC_Update(fileHMAC, line, line_len) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }

			// Generate seed deterministically using Scrypt 4-2-1. Line cannot be bruteforced (as it cannot be verified without the master key). Then, compress line and xor linetype with lineseed.
			scrypt(MASTER_KEY, MASTER_KEY_LEN, line, line_len, 1, 1, 0, lineseed, LINESEED_LEN);
			linetype = full_compress(line, line_len, &compressed, &compressed_len);
			if (linetype == LINETYPES_ERROR) {
				return ERR_COMPRESSION;
			}
			lineseed[0] ^= linetype;

			// Generate salt and key from seed
			HMAC(EVP_sha256(), MASTER_KEY, MASTER_KEY_LEN, lineseed, LINESEED_LEN, linekey, &dummy);
			HMAC(EVP_sha256(), MASTER_KEY, MASTER_KEY_LEN, lineseed, LINESEED_LEN, linesalt, &dummy);

			// Encrypt using chacha20 (does not increase size), then free unencrypted compressed line. Concatenate seed with encrypted.
			encrypted = malloc(compressed_len+LINESEED_LEN);
			if ((encrypted_len = encrypt_chacha20(compressed, compressed_len, encrypted+LINESEED_LEN, compressed_len, linekey, linesalt)+LINESEED_LEN) <= LINESEED_LEN) { handleErrors("Encryption Error"); return ERR_ENCRYPTION; }
			wipe(&compressed, compressed_len);
			memcpy(encrypted, lineseed, LINESEED_LEN);

			// Encode encrypted value in base85, then free final binary line
			encoded_max_len = Z85_encode_with_padding_bound(encrypted_len)+1;
			encoded = malloc(encoded_max_len);
			encoded_len = Z85_encode_with_padding(encrypted, encoded, encrypted_len);
			encoded[encoded_len] = 0;
			dealloc(&encrypted);

			// Print encoded and newline to file, then free encoded line
			fputs(encoded, outFile); fputc('\n', outFile);
			dealloc((byte**)(&encoded));
		}
	}

	// Wipe lineseed, linekey, and linesalt
	for (size_t i=0; i<LINESEED_LEN; i++) {
		lineseed[i] = 0;
	}
	for (size_t i=0; i<SHA256_LEN; i++) {
		linekey[i] = linesalt[i] = 0;
	}

	// Get Final Hash, Encode and Print
	unsigned int digest_len = 32; byte digest[digest_len];
	if (HMAC_Final(fileHMAC, digest, &digest_len) != 1) {
		handleErrors("Error on HMAC finalization");
		return ERR_HMAC_FINALIZATION;
	}
	size_t encodedDigest_max_len = Z85_encode_with_padding_bound(encrypted_len)+1, encodedDigest_len;
	byte encodedDigest[encodedDigest_max_len];
	encodedDigest_len = Z85_encode_with_padding(digest, encodedDigest, digest_len);
	encodedDigest[encodedDigest_len] = 0;
	fprintf(outFile, "~%s\n", encodedDigest);
	return SUCCESS;
}

// Function to decrypt a file
enum status runDecrypt(FILE* inFile, FILE* outFile, unsigned char* MASTER_KEY) {
	// Initialize hmac for file
	HMAC_CTX* fileHMAC;
	fileHMAC = HMAC_CTX_new();
	HMAC_Init_ex(fileHMAC, MASTER_KEY, MASTER_KEY_LEN, EVP_sha256(), NULL);

	// Get version bytes from first line, decode in base85, then check compatibility and update HMAC
	char VERSION_ENCODED[8];
	fgets(VERSION_ENCODED, 7, inFile);
	uint32_t VERSION_SWAP;
	Z85_decode(VERSION_ENCODED, (byte*)(&VERSION_SWAP), 5);
	if (VERSION_SWAP != htonl(VERSION)) {
		handleErrors("Incompatible version");
		return ERR_INCOMPATIBLE_VERSION;
	}
	if (HMAC_Update(fileHMAC, (byte*)(&VERSION_SWAP), 4) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }

	// Loop through lines in inFile
	char *encoded; size_t encoded_len;
	byte *line, *compressed, *encrypted, linetype; size_t line_len, compressed_len, encrypted_len, encrypted_max_len;
	unsigned int dummy; // Dummy value
	byte linekey[SHA256_LEN], linesalt[SHA256_LEN];
	while (!feof(inFile) && !ferror(inFile)) {
		// Get next line and length
		encoded = NULL; encoded_len = 0;
		encoded_len = getline(&encoded, &encoded_len, inFile);

		// Perform operation on encoded
		if (encoded_len == -1) { // Failed to read line
			// Do nothing
		} else if (encoded[0] == '\n') { // Empty Line. Print newline and update HMAC with only newline.
			fputc('\n', outFile);
			if (HMAC_Update(fileHMAC, "\n", 1) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }
		} else if (encoded[0] == '~') { // Final line. Break the loop. This should always be triggered at the end of the file.
			break;
		} else { // Line with stuff
			// Remove newline if it exists. Otherwise, this is the last line, but it doesn't matter here.
			encoded_len -= (encoded[encoded_len-1] == '\n');

			// Decode Line and free. Note that encrypted includes first 16 bytes of seed
			encrypted_max_len = Z85_decode_with_padding_bound(encoded, encoded_len);
			encrypted = malloc(encrypted_max_len);
			encrypted_len = Z85_decode_with_padding(encoded, encrypted, encoded_len);
			dealloc((byte**)(&encoded));

			// Generate salt and key from seed located @ encrypted
			HMAC(EVP_sha256(), MASTER_KEY, MASTER_KEY_LEN, encrypted, LINESEED_LEN, linekey, &dummy);
			HMAC(EVP_sha256(), MASTER_KEY, MASTER_KEY_LEN, encrypted, LINESEED_LEN, linesalt, &dummy);

			// Decrypt using chacha20 (removes seed). Concatenate seed with encrypted.
			compressed_len = encrypted_len-LINESEED_LEN;
			compressed = malloc(compressed_len);
			if (!(compressed_len = decrypt_chacha20(encrypted+LINESEED_LEN, compressed_len, compressed, compressed_len, linekey, linesalt))) { handleErrors("Decryption Error"); return ERR_ENCRYPTION; }

			// Decompress line using a very convoluted process, then deallocate encrypted line and wipe compressed line. (Encrypted is used for seed)
			linetype = full_decompress_verify(compressed, compressed_len, &line, &line_len, encrypted, LINESEED_LEN, MASTER_KEY, MASTER_KEY_LEN) ;
			if (linetype == LINETYPES_ERROR) {
				return ERR_COMPRESSION;
			}
			dealloc(&encrypted);
			wipe(&compressed, compressed_len);

			// Update HMAC without newline
			if (HMAC_Update(fileHMAC, line, line_len) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }

			// Print line with newline to file, then wipe line
			fputs(line, outFile); fputc('\n', outFile);
			wipe(&line, line_len);
		}
	}

	// Finalize HMAC.
	unsigned int digest_len = 32; byte digest[digest_len];
	if (HMAC_Final(fileHMAC, digest, &digest_len) != 1) {
		handleErrors("Error on HMAC finalization");
		return ERR_HMAC_FINALIZATION;
	}
	// Decode HMAC from file.
	if (encoded[encoded_len-1] == '\n') {
		encoded_len--;
	}
	unsigned int verif_max_len = Z85_decode_with_padding_bound(encoded+1, encoded_len-1);
	byte verif[verif_max_len];
	encrypted_len = Z85_decode_with_padding(encoded+1, verif, encoded_len-1);
	// Compare.
	if (memcmp(digest, verif, digest_len) != 0) {
		handleErrors("Error: Corrupted File");
		return ERR_CORRUPTED_FILE;
	}
	dealloc((byte**)(&encoded));

	// Wipe linekey and linesalt
	for (size_t i=0; i<SHA256_LEN; i++) {
		linekey[i] = linesalt[i] = 0;
	}
	return SUCCESS;
}