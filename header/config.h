/* CONFIGURATION VARIABLES */
typedef unsigned char byte;

// General
enum status {SUCCESS=0, ERR_HMAC_UPDATE, ERR_COMPRESSION, ERR_ENCRYPTION, ERR_HMAC_FINALIZATION, ERR_CORRUPTED_FILE, ERR_INCOMPATIBLE_VERSION, ERR_RANDOM_GEN, ERR_WRONG_SALT, ERR_FILE_NOT_FOUND, ERR_SYNTAX=254};
const byte LINETYPES_UNCOMPRESSED = 0, LINETYPES_SHOCO = 1, LINETYPES_DEFLATE = 2, LINETYPES_ERROR = 255;
const uint32_t VERSION = 6;
const size_t MASTER_KEY_LEN = 32;

// Salt
const char saltFileExtension[] = ".salt";
size_t saltFileExtension_len = sizeof(saltFileExtension);
unsigned int saltChars = 32; // Should be divisible by 4
unsigned int saltCharsEncoded = 40; // Should be exactly 5/4 saltChars