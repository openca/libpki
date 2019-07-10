/* libpki/pki_algor.h */

#ifndef _LIBPKI_PKI_ALGOR_VALUE_H
#define _LIBPKI_PKI_ALGOR_VALUE_H

// --------------------------- PKI_X509_ALGOR_VALUE --------------------------- //

/*! \brief Returns an empty PKI_X509_ALGOR_VALUE value */
PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new ();

/*! \brief Frees the memory associated with a PKI_X509_ALGORITHM_VALUE */
void PKI_X509_ALGORITHM_VALUE_free ( PKI_X509_ALGOR_VALUE *a );

/*! \brief Returns a new PKI_X509_ALGORITHM_VALUE of the identified type */
PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_type ( int type );

/*! \brief Returns a new PKI_X509_ALGORITHM_VALIE from the passed PKI_DIGEST_ALG structure */
PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_digest ( PKI_DIGEST_ALG *alg );

/* Get the SCHEME algorithm (e.g., RSA-SHA256, DSA-SHA1, ECDSA-SHA224) */
PKI_X509_ALGOR_VALUE *PKI_X509_ALGOR_VALUE_get ( PKI_ALGOR_ID algor );

PKI_X509_ALGOR_VALUE *PKI_X509_ALGOR_VALUE_get_by_name ( const char *alg_s );

void PKI_X509_ALGOR_VALUE_free( PKI_X509_ALGOR_VALUE *algor);

// -------------------------- PKI_X509_ALGOR_VALUE_ID --------------------------- //

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_id (const PKI_X509_ALGOR_VALUE * algor );

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_digest_id (const PKI_X509_ALGOR_VALUE *algor );

const char * PKI_X509_ALGOR_VALUE_get_parsed (const PKI_X509_ALGOR_VALUE * algor );

// ------------------------------- PKI_SCHEME_ID ------------------------------- //

PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme (const PKI_X509_ALGOR_VALUE * algor );

PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme_by_txt(const char * data);

const char * PKI_SCHEME_ID_get_parsed ( PKI_SCHEME_ID id );

// ------------------------------ PKI_DIGEST_ALG ------------------------------- //

PKI_DIGEST_ALG *PKI_X509_ALGOR_VALUE_get_digest (const PKI_X509_ALGOR_VALUE * algor );

PKI_DIGEST_ALG *PKI_DIGEST_ALG_get_by_key (const PKI_X509_KEYPAIR *pkey );

PKI_DIGEST_ALG *PKI_DIGEST_ALG_get_by_name( const char *name );

PKI_DIGEST_ALG *PKI_DIGEST_ALG_get( PKI_ALGOR_ID alg );

const char * PKI_DIGEST_ALG_get_parsed (const PKI_DIGEST_ALG * alg );

// --------------------------- PKI_ALGOR_ID Lists ------------------------------- //

// Returns the List of supported Algorithms
const PKI_ALGOR_ID *PKI_ALGOR_ID_list ( PKI_SCHEME_ID scheme );

// Returns the List of supported Digest Algorithms
const PKI_ALGOR_ID *PKI_DIGEST_ALG_ID_list( void );

// Returns the size of a list of a PKI_ALGOR_ID
size_t PKI_ALGOR_ID_list_size( const PKI_ALGOR_ID * const list );

// Get a string describing the algor
char *PKI_ALGOR_ID_txt ( PKI_ALGOR_ID algor );


#endif

