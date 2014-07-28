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

#ifndef _LIBPKI_PKI_HMAC_H
#define _LIBPKI_PKI_HMAC_H

typedef struct pki_hmac_st {

	// Digest Algoritm to use. Default is SHA-1
	PKI_DIGEST_ALG *digestAlg;

	// Keeps track of the initialization status (0 = false, 1 = true)
	int initialized;
	
	// The PKI_MEM that retains the current value (available after finalize)
	PKI_MEM *value;

	// The PKI_MEM that holds the key to be used
	PKI_MEM *key;

	// Internal Use
	HMAC_CTX ctx;

} PKI_HMAC;

PKI_HMAC *PKI_HMAC_new_null(void);
PKI_HMAC *PKI_HMAC_new(unsigned char *key, size_t key_size, PKI_DIGEST_ALG *digest, HSM *hsm);
PKI_HMAC *PKI_HMAC_new_mem(PKI_MEM *key, PKI_DIGEST_ALG *digest, HSM *hsm);

int PKI_HMAC_init(PKI_HMAC *hmac, unsigned char *key, size_t key_size, PKI_DIGEST_ALG *digest, HSM *hsm);

int PKI_HMAC_update(PKI_HMAC *hmac, unsigned char *data, size_t data_size);
int PKI_HMAC_update_mem(PKI_HMAC *hmac, PKI_MEM *data);

int PKI_HMAC_finalize(PKI_HMAC *hmac);

PKI_MEM *PKI_HMAC_get_value(PKI_HMAC *hmac);
PKI_MEM *PKI_HMAC_get_value_b64(PKI_HMAC *hmac);

void PKI_HMAC_free(PKI_HMAC *hmac);

#endif
