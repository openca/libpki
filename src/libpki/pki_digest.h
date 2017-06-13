/* libpki/pki_digest.h */

#ifndef _LIBPKI_DIGEST_H
#define _LIBPKI_DIGEST_H

void PKI_DIGEST_free ( PKI_DIGEST *data );
PKI_DIGEST *PKI_DIGEST_new(const PKI_DIGEST_ALG *alg, 
			   const unsigned char *data, size_t size );
PKI_DIGEST *PKI_DIGEST_new_by_name(const char *alg_name, 
				   const unsigned char *data, size_t size );
PKI_DIGEST *PKI_DIGEST_MEM_new(const PKI_DIGEST_ALG *alg, const PKI_MEM *data );
PKI_DIGEST *PKI_DIGEST_MEM_new_by_name(const char *alg_name,
		                       const PKI_MEM *data );
PKI_DIGEST *PKI_DIGEST_URL_new(const PKI_DIGEST_ALG *alg, const URL *url );
PKI_DIGEST *PKI_DIGEST_URL_new_by_name(const char *alg_name,const URL *url );

ssize_t PKI_DIGEST_get_size(const PKI_DIGEST_ALG *alg );
char * PKI_DIGEST_get_parsed(const PKI_DIGEST *digest );

/* Default Algorithm */
#define PKI_DIGEST_DEFAULT_ALG PKI_DIGEST_ALG_SHA256

#endif
