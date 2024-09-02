/* openssl/CRYPTO_KEYPARAMS.c */

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif


#ifndef _LIBPKI_CRYPTO_KEYPARAMS_H
#define _LIBPKI_CRYPTO_KEYPARAMS_H


/*! \brief Allocates a new CRYPTO_KEYPARAMS structure
 *
 * This function allocates a new CRYPTO_KEYPARAMS structure and returns a pointer
 * to it.  The scheme parameter is used to specify the scheme of the CRYPTO_KEYPARAMS
 * object to be created.  If the scheme is not supported, the function will return
 * NULL.
 * 
 * @param scheme The scheme of the CRYPTO_KEYPARAMS object to be created
 * @param conf The PKI_CONFIG object to be used with the CRYPTO_KEYPARAMS object
 * @return A pointer to the newly created CRYPTO_KEYPARAMS object
 */
CRYPTO_KEYPARAMS *CRYPTO_KEYPARAMS_new(CRYPTO_TYPE algor, const PKI_CONFIG *conf);

/*! \breif Frees the CRYPTO_KEYPARAMS structure
 *
 * This function frees the CRYPTO_KEYPARAMS structure and all of its associated
 * memory.
 * 
 * @param kp A pointer to the CRYPTO_KEYPARAMS structure to be freed
 */
void CRYPTO_KEYPARAMS_free(CRYPTO_KEYPARAMS *params);
 
/*! \brief Returns the type of the CRYPTO_KEYPARAMS structure
 *
 * This function returns the type of the CRYPTO_KEYPARAMS structure.
 * 
 * @param kp The CRYPTO_KEYPARAMS structure
 * @return The type of the CRYPTO_KEYPARAMS structure
 */
CRYPTO_TYPE CRYPTO_KEYPARAMS_type(const CRYPTO_KEYPARAMS * params);


/*!
 * @brief Sets the scheme and security bits in the CRYPTO_KEYPARAMS structure
 *
 * This function sets the scheme and security bits in the CRYPTO_KEYPARAMS
 * structure.  If the scheme is not supported, the function will return
 * PKI_ERR.
 * 
 * @param kp The CRYPTO_KEYPARAMS structure to set
 * @param scheme_id The requested scheme to set in the structure
 * @param sec_bits The requested security bits
 * @retval PKI_OK on success, PKI_ERR on failure
 */
int CRYPTO_KEYPARAMS_set_type(CRYPTO_KEYPARAMS * params, CRYPTO_TYPE algor);

/*!
 * @brief Sets the size (in bits) for the RSA key type
 *
 * This function sets the size (in bits) for the RSA key type in the
 * CRYPTO_KEYPARAMS structure.
 * 
 * @param kp The CRYPTO_KEYPARAMS structure to set
 * @param bits The size (in bits) to set
 * @retval PKI_OK on success, PKI_ERR on failure
 * @see CRYPTO_KEYPARAMS
 */
int CRYPTO_KEYPARAMS_RSA_set(CRYPTO_KEYPARAMS * kp, int bits);

/*! \brief Sets the parameters for the EC key type
 *
 * This function sets the parameters for the EC key type in the CRYPTO_KEYPARAMS
 * structure.  The curveName parameter is used to specify the curve to be used.
 * The curveForm parameter is used to specify the form of the curve.  The ans1flags
 * parameter is used to specify the flags to be used.
 * 
 * @param kp The CRYPTO_KEYPARAMS structure to set
 * @param curveName The name of the curve to set
 * @param curveForm The form of the curve to set
 * @param ans1flags The flags to set
 * @retval PKI_OK on success, PKI_ERR on failure
 * @see CRYPTO_KEYPARAMS
 */
int CRYPTO_KEYPARAMS_ECDSA_set(CRYPTO_KEYPARAMS * kp, 
                               const char       * curveName, 
                               CRYPTO_EC_FORM     curveForm,
                               int                ans1flags);

// ========================
// Composite Crypto Support
// ========================

#ifdef ENABLE_COMPOSITE

/*! \brief Adds a key to the list of keys for Composite keys */
int CRYPTO_KEYPARAMS_add_key(CRYPTO_KEYPARAMS * kp, PKI_X509_KEYPAIR * key);

/*! \brief Sets the k_of_n parameter for Composite keys */
int CRYPTO_KEYPARAMS_set_kofn(CRYPTO_KEYPARAMS * kp, int kofn);

#endif // End of ENABLE_COMPOSITE

// =========================
// Open Quantum Safe Support
// =========================

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

int CRYPTO_KEYPARAMS_MLDSA_set(CRYPTO_KEYPARAMS * params, PKI_ALGOR_OQS_PARAM algParam);

#endif // End of ENABLE_OQS

#endif // _LIBPKI_CRYPTO_KEYPARAMS_H
