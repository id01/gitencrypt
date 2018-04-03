#include "includes.h"

/* WRAPPER FUNCTIONS */
/* ENCODING/COMPRESSION */
// Function to encrypt a string
size_t encrypt_chacha20(byte* plaintext, size_t plaintext_len, byte* ciphertext, size_t ciphertext_max_len, byte* key, byte* salt) {
	if (ciphertext_max_len < plaintext_len) {
		return 0; // Error
	}
	// Encrypt using chacha20 (does not change size).
	EVP_CIPHER_CTX* ctx;
	unsigned int ciphertext_len, dummy;
	if (!(ctx = EVP_CIPHER_CTX_new())
		|| (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, salt) != 1)
//		|| (EVP_EncryptInit_ex(ctx, EVP_enc_null(), NULL, key, salt) != 1) // For testing only
		|| (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1)
		|| (EVP_EncryptFinal_ex(ctx, ciphertext+ciphertext_len, &dummy) != 1)) {
		return 0; // Error
	}
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

// Compression wrapper for libdeflate
size_t deflate_compress(byte* input, size_t input_len, byte** output) {
	struct libdeflate_compressor* compressor = libdeflate_alloc_compressor(9);
	size_t output_max_len = libdeflate_deflate_compress_bound(compressor, input_len), output_len;
	*output = malloc(output_max_len);
	output_len = libdeflate_deflate_compress(compressor, input, input_len, *output, output_max_len);
	libdeflate_free_compressor(compressor);
	return output_len;
}

// Full compression function. Returns linetype.
byte full_compress(byte* line, size_t line_len, byte** compressed_line, size_t* compressed_line_len) {
	// Allocate variables
	byte* compressed_deflate; size_t compressed_deflate_len, compressed_deflate_max_len;
	byte* compressed_shoco; size_t compressed_shoco_len, compressed_shoco_max_len;
	byte linetype;

	// Compress line with shoco, and with deflate if over 64 bytes. Check for errors. Choose best algorithm.
	compressed_shoco_max_len = line_len*2+1;
	compressed_shoco = malloc(compressed_shoco_max_len);
	compressed_shoco_len = shoco_compress(line, line_len, compressed_shoco, compressed_shoco_max_len);
	if (line_len >= 64) { // Only try deflating if line is >=64 bytes. Otherwise it'll be ineffective anyway.
		compressed_deflate_len = deflate_compress(line, line_len, &compressed_deflate);
	} else {
		compressed_deflate = NULL; // Don't use deflate if under 64 bytes
		compressed_deflate_len = compressed_shoco_len+1;
	}
	if (compressed_deflate_len == 0 || compressed_shoco_len == 0) {
		return LINETYPES_ERROR; // Compression Error
	}

	// Choose compression algorithm first by size then by speed. XOR algorithm used with seed, then free unnecessary compressed lines.
	if (compressed_deflate_len < compressed_shoco_len && compressed_deflate_len < line_len) {
		*compressed_line = compressed_deflate;
		*compressed_line_len = compressed_deflate_len;
		linetype = LINETYPES_DEFLATE;
		wipe(&compressed_shoco, compressed_shoco_len);
		wipe(&line, line_len);
	} else if (compressed_shoco_len < line_len) {
		*compressed_line = compressed_shoco;
		*compressed_line_len = compressed_shoco_len;
		linetype = LINETYPES_SHOCO;
		wipe(&compressed_deflate, compressed_deflate_len);
		wipe(&line, line_len);
	} else {
		*compressed_line = line;
		*compressed_line_len = line_len;
		linetype = LINETYPES_UNCOMPRESSED;
		wipe(&compressed_shoco, compressed_shoco_len);
		wipe(&compressed_deflate, compressed_deflate_len);
	}

	return linetype;
}

/* DECODING/DECOMPRESSION */
// Function to decrypt a string
size_t decrypt_chacha20(byte* ciphertext, size_t ciphertext_len, byte* plaintext, size_t plaintext_max_len, byte* key, byte* salt) {
	if (plaintext_max_len < ciphertext_len) {
		return 0; // Error
	}
	// Decrypt using chacha20 (does not change size).
	EVP_CIPHER_CTX* ctx;
	unsigned int plaintext_len, dummy;
	if (!(ctx = EVP_CIPHER_CTX_new())
		|| (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, salt) != 1)
//		|| (EVP_DecryptInit_ex(ctx, EVP_enc_null(), NULL, key, salt) != 1) // For testing only
		|| (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) != 1)
		|| (EVP_DecryptFinal_ex(ctx, plaintext+plaintext_len, &dummy) != 1)) {
		return 0; // Error
	}
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

// Decompression wrapper for libdeflate
size_t deflate_decompress(byte* input, size_t input_len, byte** output) {
	struct libdeflate_decompressor* decompressor = libdeflate_alloc_decompressor();
	enum libdeflate_result output_result = LIBDEFLATE_INSUFFICIENT_SPACE;
	size_t output_test_len = input_len*4, output_len;
	*output = NULL;
	while (output_result == LIBDEFLATE_INSUFFICIENT_SPACE) { // Keep trying to decompress, doubling size of buffer each time there is not enough space
		if (*output != NULL) { wipe(output, output_test_len); }
		if (output_test_len > 4194304) { return 0; } // Let's stop at 4MB and treat it as an error
		output_test_len *= 2;
		*output = malloc(output_test_len);
		output_result = libdeflate_deflate_decompress(decompressor, input, input_len, *output, output_test_len-1, &output_len);
	}
	(*output)[output_len] = 0; // Null terminator
	if (output_result != LIBDEFLATE_SUCCESS) {
		return 0; // Error
	}
	libdeflate_free_decompressor(decompressor);
	return output_len;
}

// Full decompression and verification function. Returns what compression algorithm was used, or LINETYPES_ERROR on failure.
byte full_decompress_verify(byte* compressed_line, size_t compressed_line_len, byte** line, size_t* line_len, byte* lineseed, unsigned int lineseed_len, byte* MASTER_KEY, size_t MASTER_KEY_LEN) {
	// Allocate variables
	byte* decompressed_attempt; size_t decompressed_attempt_len, decompressed_attempt_max_len;
	byte attempt_hash[lineseed_len];

	// Attempt no decompression (memcpy)
	scrypt(MASTER_KEY, MASTER_KEY_LEN, compressed_line, compressed_line_len, 1, 1, 0, attempt_hash, lineseed_len);
	attempt_hash[0] ^= LINETYPES_UNCOMPRESSED;
	if (memcmp(attempt_hash, lineseed, lineseed_len) == 0) { // If success allocate a buffer and copy over
		*line = malloc(compressed_line_len+2);
		memcpy(*line, compressed_line, compressed_line_len);
		(*line)[compressed_line_len] = 0;
		*line_len = compressed_line_len;
		return LINETYPES_UNCOMPRESSED;
	}

	// Attempt shoco decompression
	decompressed_attempt_max_len = compressed_line_len*12+1;
	decompressed_attempt = malloc(decompressed_attempt_max_len);
	decompressed_attempt_len = shoco_decompress(compressed_line, compressed_line_len, decompressed_attempt, decompressed_attempt_max_len); // Decompress function adds null terminator already
	if (decompressed_attempt_len != -1) { // If not error
		scrypt(MASTER_KEY, MASTER_KEY_LEN, decompressed_attempt, decompressed_attempt_len, 1, 1, 0, attempt_hash, lineseed_len);
		attempt_hash[0] ^= LINETYPES_SHOCO; // XOR this to match the compression algorithm
		if (memcmp(attempt_hash, lineseed, lineseed_len) == 0) { // If success copy over decompressed_attempt to line and return shoco
			*line = decompressed_attempt;
			*line_len = decompressed_attempt_len;
			return LINETYPES_SHOCO;
		}
		wipe(&decompressed_attempt, decompressed_attempt_len); // If failure, wipe allocated buffer up to the length it was written
	} else { // Error happened. Deallocate only.
		dealloc(&decompressed_attempt);
	}

	// Attempt deflate (inflate) decompression
	decompressed_attempt_len = deflate_decompress(compressed_line, compressed_line_len, &decompressed_attempt); // Adds null terminator already
	if (decompressed_attempt_len != 0) { // If not error
		scrypt(MASTER_KEY, MASTER_KEY_LEN, decompressed_attempt, decompressed_attempt_len, 1, 1, 0, attempt_hash, lineseed_len);
		attempt_hash[0] ^= LINETYPES_DEFLATE; // XOR this to match the compression algorithm
		if (memcmp(attempt_hash, lineseed, lineseed_len) == 0) { // If success copy over decompressed_attempt to line and return deflate
			*line = decompressed_attempt;
			*line_len = decompressed_attempt_len;
			return LINETYPES_DEFLATE;
		}
		wipe(&decompressed_attempt, decompressed_attempt_len); // If failure, wipe allocated buffer up to the length it was written
	}

	// Oh no! Nothing worked! Integrity check failed.
	return LINETYPES_ERROR;
}