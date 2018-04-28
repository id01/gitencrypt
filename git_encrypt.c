// Headers
#include "header/includes.h"
#include "header/config.h"
#include "header/utilities.h"
#include "header/wrappers.h"

/* MAIN FUNCTIONS */
// Function Prototypes
enum status runEncrypt(FILE* inFile, FILE* outFile, char* password, char* saltFileName);
enum status runDecrypt(FILE* inFile, FILE* outFile, char* password, char* saltFileName);

// Constants
const unsigned int LINESEED_LEN=16, SHA256_LEN=32; // Note: Only the first 16 bytes of linesalt will be used.

// Main function
int main(int argc, char* argv[]) {
	// Check input
	if (argc != 4 && argc != 5) {
		perror("Usage: ./gitcrypt [encrypt|decrypt] [file] [secret_password] [stdin mode y/n]");
		return ERR_SYNTAX;
	}

	// Set mode (encrypt/decrypt) and stdin mode (y/n)
	char mode = argv[1][0];
	char stdinmode = 'n';
	if (argc == 5) {
		stdinmode = argv[4][0];
	}

	// Get input file name and input file salt file name, open input file
	size_t inFileName_len = strlen(argv[2])+1;
	size_t saltFileName_len = inFileName_len+saltFileExtension_len;
	char* inFileName = malloc(inFileName_len);
	char* saltFileName = malloc(saltFileName_len);

	memcpy(inFileName, argv[2], inFileName_len);
	memcpy(saltFileName, argv[2], inFileName_len);
	memcpy(saltFileName+inFileName_len-1, saltFileExtension, saltFileExtension_len);

	FILE* inFile = stdin;
	if (stdinmode != 'y') {
		inFile = fopen(inFileName, "r");
	}

	// Check if inFile exists
	if (inFile == NULL) {
		system("pwd 1>&2"); perror(saltFileName); perror(inFileName); system("pwd 1>&2");
		handleErrors("File not found");
		return ERR_FILE_NOT_FOUND;
	}

	// Run encrypt/decrypt, close inFile, and return result
	enum status res;
	if (mode == 'e') {
		res = runEncrypt(inFile, stdout, argv[3], saltFileName);
		fclose(inFile);
	} else if (mode == 'd') {
		res = runDecrypt(inFile, stdout, argv[3], saltFileName);
		fclose(inFile);
	} else {
		perror("Invalid mode");
		return ERR_SYNTAX;
	}
	return res;
}

// Function to encrypt/compress a file
enum status runEncrypt(FILE* inFile, FILE* outFile, char* password, char* saltFileName) {
	// Swap version bytes to big-endian, encode in base85, then output
	uint32_t VERSION_SWAP = htonl(VERSION);
	char VERSION_ENCODED[7];
	Z85_encode((byte*)(&VERSION_SWAP), VERSION_ENCODED, 4);
	VERSION_ENCODED[5] = '\n'; VERSION_ENCODED[6] = 0;
	fputs(VERSION_ENCODED, outFile);

	// Get salt
	FILE* saltFile = fopen(saltFileName, "r");
	unsigned char saltZ85[saltCharsEncoded+2], salt[saltChars];
	if (saltFile != NULL) { // Salt file already exists
		// Get salt from salt file and decode it. Close salt file.
		fgets(saltZ85, saltCharsEncoded+1, saltFile); // Note that we need 1 additional char because on some systems this includes the null terminator
		Z85_decode(saltZ85, salt, saltCharsEncoded);
		fclose(saltFile);
	} else { // Salt file doesn't exist
		// Generate salt, encode it, and write to salt file. Close salt file.
		saltFile = fopen(saltFileName, "w");
		if (getrandom(salt, saltChars, 0) == -1) {
			handleErrors("Error on random salt generation");
			return ERR_RANDOM_GEN;
		}
		Z85_encode(salt, saltZ85, saltChars);
		saltZ85[saltCharsEncoded] = 0;
		fputs(saltZ85, saltFile);
		fclose(saltFile);
	}

	// Generate master key from password using scrypt-16384-8-1
	unsigned char* MASTER_KEY = malloc(MASTER_KEY_LEN);
	scrypt(password, strlen(password), salt, saltChars, 13, 3, 0, MASTER_KEY, MASTER_KEY_LEN); // argv[3] is secret_password

	// Initialize hmac for file
	HMAC_CTX* fileHMAC;
	fileHMAC = HMAC_CTX_new();
	HMAC_Init_ex(fileHMAC, MASTER_KEY, MASTER_KEY_LEN, EVP_sha256(), NULL);

	// Update HMAC with version
	if (HMAC_Update(fileHMAC, (byte*)(&VERSION_SWAP), 4) != 1) { handleErrors("Error on HMAC Update"); return ERR_HMAC_UPDATE; }

	// Print salt as first line of non-version output to outFile
	fprintf(outFile, "%s\n", saltZ85);

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
enum status runDecrypt(FILE* inFile, FILE* outFile, char* password, char* saltFileName) {
	// Get version bytes from first line, decode in base85, then check compatibility
	char VERSION_ENCODED[8];
	fgets(VERSION_ENCODED, 7, inFile);
	uint32_t VERSION_SWAP;
	Z85_decode(VERSION_ENCODED, (byte*)(&VERSION_SWAP), 5);
	if (VERSION_SWAP != htonl(VERSION)) {
		handleErrors("Incompatible version");
		return ERR_INCOMPATIBLE_VERSION;
	}

	// Get salt
	FILE* saltFile = saltFile = fopen(saltFileName, "r");
	unsigned char saltZ85[saltCharsEncoded+3], salt[saltChars], saltZ85Check[saltCharsEncoded+2];
	if (saltFile != NULL) { // Salt file already exists
		// Get salt from salt file and salt from inFile.
		fgets(saltZ85, saltCharsEncoded+2, inFile); // This will get newline and null terminator, but doesn't matter
		fgets(saltZ85Check, saltCharsEncoded+1, saltFile); // Note that we need 1 additional char because on some systems this includes the null terminator
		// If the two salts differ, throw error.
		if (memcmp(saltZ85, saltZ85Check, saltCharsEncoded)) {
			handleErrors("Wrong salt");
			return ERR_WRONG_SALT;
		}
		// Decode saltZ85, close saltFile and continue
		Z85_decode(saltZ85, salt, saltCharsEncoded);
		fclose(saltFile);
	} else { // Salt file doesn't exist
		// Get salt from inFile and write to saltFile.
		saltFile = fopen(saltFileName, "w");
		fgets(saltZ85, saltCharsEncoded+2, inFile); // This will get newline and null terminator, but doesn't matter
		fwrite(saltZ85, saltCharsEncoded, 1, saltFile);
		// Decode salt from inFile and close saltFile
		Z85_decode(saltZ85, salt, saltCharsEncoded);
		fclose(saltFile);
	}

	// Generate master key from password using scrypt-16384-8-1
	unsigned char* MASTER_KEY = malloc(MASTER_KEY_LEN);
	scrypt(password, strlen(password), salt, saltChars, 13, 3, 0, MASTER_KEY, MASTER_KEY_LEN); // argv[3] is secret_password

	// Initialize hmac for file
	HMAC_CTX* fileHMAC;
	fileHMAC = HMAC_CTX_new();
	HMAC_Init_ex(fileHMAC, MASTER_KEY, MASTER_KEY_LEN, EVP_sha256(), NULL);

	// Update version HMAC
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