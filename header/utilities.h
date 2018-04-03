#include "includes.h"

/* UTILITY FUNCTIONS */
// Function to responsibly handle errors
void handleErrors(const char* errorName) {
	perror(errorName);
}

// Function to free and null
void dealloc(byte** buf_ptr) {
	free(*buf_ptr);
	*buf_ptr = NULL;
}

// Function to wipe, free, and null
void wipe(byte** buf_ptr, size_t buf_len) {
	if (*buf_ptr != NULL) {
		for (size_t i=0; i<buf_len; i++) {
			(*buf_ptr)[i] = 0;
		}
		dealloc(buf_ptr);
	}
}