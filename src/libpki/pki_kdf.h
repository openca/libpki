/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2013 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/

#ifndef _LIBPKI_PKI_KDF_H
#define _LIBPKI_PKI_KDF_H

#ifndef OPENSSL_EVP_H
#include <openssl/evp.h>
#endif

#ifndef OPENSSL_KDF_H
#include <openssl/kdf.h>
#endif

int PKI_KDF_derive(const EVP_MD   * md,
				   unsigned char  * label,
				   size_t           labelen, 
				   unsigned char  * key, 
				   size_t           keylen, 
				   unsigned char  * data, 
				   size_t           datalen, 
				   unsigned char ** out, 
				   size_t         * outlen);

#endif
