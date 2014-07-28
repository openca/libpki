/* libpki/pki_algor.h */

#ifndef _LIBPKI_ALGOR_H
#define _LIBPKI_ALGOR_H

/* Get the SCHEME algorithm (e.g., RSA-SHA224, DSA-SHA1, ECDSA-SHA1) */
PKI_ALGOR *PKI_ALGOR_get ( PKI_ALGOR_ID algor );
PKI_ALGOR *PKI_ALGOR_get_by_name ( const char *alg_s );
void PKI_ALGOR_free( PKI_ALGOR *algor);

/* Get PKI_ALGOR_IDs */
PKI_ALGOR_ID PKI_ALGOR_get_id ( PKI_ALGOR * algor );
PKI_DIGEST_ALG *PKI_ALGOR_get_digest ( PKI_ALGOR * algor );
PKI_ALGOR_ID PKI_ALGOR_get_digest_id ( PKI_ALGOR *algor );
PKI_SCHEME_ID PKI_ALGOR_get_scheme ( PKI_ALGOR * algor );
const char * PKI_ALGOR_get_parsed ( PKI_ALGOR * algor );

/* SCHEME ID */
const char * PKI_SCHEME_ID_get_parsed ( PKI_SCHEME_ID id );

/* Get the DIGEST algorithm */
PKI_DIGEST_ALG *PKI_DIGEST_ALG_get_by_key ( PKI_X509_KEYPAIR *pkey );
PKI_DIGEST_ALG *PKI_DIGEST_ALG_get_by_name( const char *name );
PKI_DIGEST_ALG *PKI_DIGEST_ALG_get( PKI_ALGOR_ID alg );
const char * PKI_DIGEST_ALG_get_parsed ( PKI_DIGEST_ALG * alg );

/* Get list of supported algorithms for a particular scheme */
PKI_ALGOR_ID *PKI_ALGOR_list ( PKI_SCHEME_ID scheme );
PKI_ALGOR_ID *PKI_DIGEST_ALG_list( void );

/* Returns the size of a list of a PKI_ALGOR_ID */
size_t PKI_ALGOR_list_size( PKI_ALGOR_ID * list );

/* Get a string describing the algor */
char *PKI_ALGOR_ID_txt ( PKI_ALGOR_ID algor );

#endif

