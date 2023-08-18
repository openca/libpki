/* openssl/pki_keyparams.c */

#ifndef _LIBPKI_PKI_KEYPARAMS_H
#define _LIBPKI_PKI_KEYPARAMS_H

/* Memory Management */
PKI_KEYPARAMS *PKI_KEYPARAMS_new(PKI_SCHEME_ID scheme,
				 const PKI_X509_PROFILE *prof);

void PKI_KEYPARAMS_free(PKI_KEYPARAMS *kp);
 
/* Functions */
PKI_SCHEME_ID PKI_KEYPARAMS_get_type(const PKI_KEYPARAMS *kp );


/*!
 * @brief Sets the scheme and security bits in the PKI_KEYPARAMS structure
 *
 * This function sets the scheme and security bits in the PKI_KEYPARAMS
 * structure.  If the scheme is not supported, the function will return
 * PKI_ERR.
 * 
 * @param kp The PKI_KEYPARAMS structure to set
 * @param scheme_id The requested scheme to set in the structure
 * @param sec_bits The requested security bits
 * @retval PKI_OK on success, PKI_ERR on failure
 */
int PKI_KEYPARAMS_set_scheme(PKI_KEYPARAMS * kp, PKI_SCHEME_ID schemeId, int sec_bits);

int PKI_KEYPARAMS_set_security_bits(PKI_KEYPARAMS * kp, int sec_bits);

/*! 
 * \brief Sets the bits size for key generation 
 *
 * This function sets the bits size for key generation.  If the bits
 * size is not supported, the function will return PKI_ERR.
 * 
 * @param kp The PKI_KEYPARAMS structure to set
 * @param bits The requested bits size
 * @retval PKI_OK on success, PKI_ERR on failure
 */
int PKI_KEYPARAMS_set_key_size(PKI_KEYPARAMS * kp, int bits);

int PKI_KEYPARAMS_set_curve(PKI_KEYPARAMS   * kp, 
                            const char      * curveName, 
                            PKI_EC_KEY_FORM   curveForm,
                            PKI_EC_KEY_ASN1   ans1flags);

// ========================
// Composite Crypto Support
// ========================

#ifdef ENABLE_COMPOSITE

/*! \brief Adds a key to the list of keys for Composite keys */
int PKI_KEYPARAMS_add_key(PKI_KEYPARAMS * kp, PKI_X509_KEYPAIR * key);

/*! \brief Sets the k_of_n parameter for Composite keys */
int PKI_KEYPARAMS_set_kofn(PKI_KEYPARAMS * kp, int kofn);

#endif // End of ENABLE_COMPOSITE

// =========================
// Open Quantum Safe Support
// =========================

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

int PKI_KEYPARAMS_set_oqs_key_params(PKI_KEYPARAMS * kp, PKI_ALGOR_OQS_PARAM algParam);

#endif // End of ENABLE_OQS

#endif // _LIBPKI_PKI_KEYPARAMS_H
