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

/*! \brief Get the SCHEME algorithm (e.g., RSA-SHA256, DSA-SHA1, ECDSA-SHA224) */
PKI_X509_ALGOR_VALUE *PKI_X509_ALGOR_VALUE_get ( PKI_ALGOR_ID algor );

/*! \brief Build a PKI_ALGOR structure from its name (char *)
 *
 * The function returns the pointer to a PKI_ALGOR structure based on the
 * name. Names are in the form of "RSA-SHA1", "RSA-SHA512", or "DSA-SHA1".
 * 
 * @param alg_s The string describing the algorithm name
 * @retval The pointer to the newly allocated PKI_X509_ALGOR_VALUE
 */
PKI_X509_ALGOR_VALUE *PKI_X509_ALGOR_VALUE_get_by_name ( const char *alg_s );

void PKI_X509_ALGOR_VALUE_free( PKI_X509_ALGOR_VALUE *algor);

// -------------------------- PKI_X509_ALGOR_VALUE_ID --------------------------- //

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_id (const PKI_X509_ALGOR_VALUE * algor );

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_digest_id (const PKI_X509_ALGOR_VALUE *algor );

/*! 
 * \brief Returns a text representation of the algorithm identifier
 */
const char * PKI_X509_ALGOR_VALUE_get_parsed (const PKI_X509_ALGOR_VALUE * algor );

// ------------------------------- PKI_SCHEME_ID ------------------------------- //

PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme (const PKI_X509_ALGOR_VALUE * algor );

/*!
 * \brief Returns the PKI_SCHEME_ID from the passed string
 */
PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme_by_txt(const char * data);

const char * PKI_SCHEME_ID_get_parsed ( PKI_SCHEME_ID id );

/*!
 * \brief Determines if the passed scheme supports multiple key components.
 *
 * This function checks if the passed PKI_SCHEME_ID supports the use of multiple
 * components algorithm for the key. Examples of schemes that support multiple
 * keys are:
 * - Generic Composite (PKI_ALGOR_ID_COMPOSITE)
 * - Explicit Composite (PKI_ALGOR_ID_COMPOSITE_EXPLICIT_ ... )
 * - Generic Multikey (PKI_ALGOR_ID_COMBINED)
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme is composite, PKI_ERR otherwise
 */
int PKI_SCHEME_ID_supports_multiple_components(PKI_SCHEME_ID id);

/*!
 * \brief Determines if the passed scheme is composite.
 *
 * This function checks if the passed PKI_SCHEME_ID is indeed a composite type,
 * either a Generic or an Explicit Composite.
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme is composite, PKI_ERR otherwise
 */
int PKI_SCHEME_ID_is_composite(PKI_SCHEME_ID id);

/*!
 * \brief Determines if the passed scheme is explicit composite.
 *
 * This function checks if the passed PKI_SCHEME_ID is indeed an explicit
 * composite scheme. This function only checks for explicit composite OIDs
 * and does not check for the generic composite or the generic multikey ones.
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme is explicit composite, PKI_ERR otherwise
 */
int PKI_SCHEME_ID_is_explicit_composite(PKI_SCHEME_ID id);

/*!
 * \brief Determines if the passed scheme is combined (alternative keys).
 *
 * This function checks if the passed PKI_SCHEME_ID is indeed a combined type,
 * either a Generic an Explicit Combined type.
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme is combined, PKI_ERR otherwise
 */
int PKI_SCHEME_ID_is_combined(PKI_SCHEME_ID id);

/*!
 * \brief Determines if the passed scheme is post-quantum.
 *
 * This function checks if the passed PKI_SCHEME_ID is indeed a post-quantum
 * algorithm or a classic one.
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme is post-quantum, PKI_ERR otherwise
 */
int PKI_SCHEME_ID_is_post_quantum(PKI_SCHEME_ID id);

/*!
 * \brief Determines if the passed scheme requires the use of hash-n-sign.
 *
 * This function checks if the passed PKI_SCHEME_ID requires the use of a
 * digest (hash function) as intermediate step for signing or if arbitrary
 * data can be signed without the use of hash-n-sign paradigm.
 * 
 * @param id The scheme that is being checked
 * @retval Returns PKI_OK if the scheme requires a digest, PKI_ERR otherwise.
 */
int PKI_SCHEME_ID_requires_digest(PKI_SCHEME_ID id);

// ------------------------------ PKI_DIGEST_ALG ------------------------------- //

const PKI_DIGEST_ALG * PKI_X509_ALGOR_VALUE_get_digest (const PKI_X509_ALGOR_VALUE * algor );

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get_by_key (const PKI_X509_KEYPAIR *pkey );

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get_by_name( const char *name );

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get( PKI_ALGOR_ID alg );

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get_default(const PKI_X509_KEYPAIR * const x);

const char * PKI_DIGEST_ALG_get_parsed (const PKI_DIGEST_ALG * alg );

// --------------------------- PKI_ALGOR_ID Lists ------------------------------- //

/*! 
 * \brief Returns the List of supported Algorithms
 */
const PKI_ALGOR_ID *PKI_ALGOR_ID_list ( PKI_SCHEME_ID scheme );

/*!
 * \brief Returns the List of supported Digest Algorithms
 */
const PKI_ALGOR_ID *PKI_DIGEST_ALG_ID_list( void );

/*!
 * \brief Returns the size of a list of a PKI_ALGOR_ID
 */
size_t PKI_ALGOR_ID_list_size( const PKI_ALGOR_ID * const list );

/*! 
 * \brief Returns a text string with the algorithm identifier
 */
char *PKI_ALGOR_ID_txt ( PKI_ALGOR_ID algor );

#endif

