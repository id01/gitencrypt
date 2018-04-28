// Standard libs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/random.h>

// Openssl libs (-lcrypto)
#include <openssl/sha.h>
#include <openssl/hmac.h>

// Deflate lib (-ldeflate)
#include <libdeflate.h>

// Custom libs provided by submodules
#include "shoco/shoco.h"
#include "scrypt-jane/scrypt-jane.h"
#include "z85/src/z85.h"