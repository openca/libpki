/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <libpki/pki.h>

int PKI_RAND_get( unsigned char **buf, size_t num) {

	int ret = 0;
		// OSSL return code

	// Input Checks
	if (!buf || num <= 0) return PKI_ERR;

	// Allocates the buffer if not already allocated
	if ((*buf == NULL) && ((*buf = malloc( num )) == NULL)) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	// Gets the random data
	ret = RAND_bytes(*buf, (int)num);
	if (ret != 1) {
		PKI_DEBUG("Failed to retrieve (%d) random bytes (code: %d)", num, ret);
		return PKI_ERR;
	}

	// All Done
	return ret;
}