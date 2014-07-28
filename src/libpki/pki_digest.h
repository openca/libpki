/* libpki/pki_digest.h */

#ifndef _LIBPKI_DIGEST_H
#define _LIBPKI_DIGEST_H

void PKI_DIGEST_free ( PKI_DIGEST *data );
PKI_DIGEST *PKI_DIGEST_new ( PKI_DIGEST_ALG *alg, 
					unsigned char *data, size_t size );
PKI_DIGEST *PKI_DIGEST_new_by_name ( char *alg_name, 
					unsigned char *data, size_t size );
PKI_DIGEST *PKI_DIGEST_MEM_new ( PKI_DIGEST_ALG *alg, PKI_MEM *data );
PKI_DIGEST *PKI_DIGEST_MEM_new_by_name ( char *alg_name, PKI_MEM *data );
PKI_DIGEST *PKI_DIGEST_URL_new ( PKI_DIGEST_ALG *alg, URL *url );
PKI_DIGEST *PKI_DIGEST_URL_new_by_name ( char *alg_name, URL *url );

ssize_t PKI_DIGEST_get_size ( PKI_DIGEST_ALG *alg );
char * PKI_DIGEST_get_parsed ( PKI_DIGEST *digest );

/* Default Algorithm */
#define PKI_DIGEST_DEFAULT_ALG PKI_DIGEST_ALG_SHA256

#endif
