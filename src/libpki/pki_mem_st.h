/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/
#ifndef _LIBPKI_PKI_MEM_ST_H
#define _LIBPKI_PKI_MEM_ST_H
# pragma once

// OpenSSL Includes
#include <openssl/bio.h>

// LibPKI Includes
#include <libpki/compat.h>

BEGIN_C_DECLS

						// ===============
						// Data Structures
						// ===============

typedef struct pki_mem_st {
	unsigned char * data;
	size_t 			size;
} PKI_MEM;

END_C_DECLS

#endif // End of _LIBPKI_PKI_MEM_ST_H
