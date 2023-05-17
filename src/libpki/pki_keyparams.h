/* openssl/pki_keyparams.c */

#ifndef _LIBPKI_PKI_KEYPARAMS_H
#define _LIBPKI_PKI_KEYPARAMS_H

/* Memory Management */
PKI_KEYPARAMS *PKI_KEYPARAMS_new(PKI_SCHEME_ID scheme,
				 const PKI_X509_PROFILE *prof);

void PKI_KEYPARAMS_free(PKI_KEYPARAMS *kp);
 
/* Functions */
PKI_SCHEME_ID PKI_KEYPARAMS_get_type(const PKI_KEYPARAMS *kp );
int PKI_KEYPARAMS_set_scheme(PKI_KEYPARAMS * kp, PKI_SCHEME_ID schemeId);

int PKI_KEYPARAMS_bits_get(PKI_KEYPARAMS * kp, int * bits);
int PKI_KEYPARAMS_bits_set(PKI_KEYPARAMS * kp, int bits);

int PKI_KEYPARAMS_sec_bits_get(PKI_KEYPARAMS * kp, int * sec_bits);
int PKI_KEYPARAMS_sec_bits_set(PKI_KEYPARAMS * kp, int sec_bits);

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

#ifdef ENABLE_OQS

int PKI_KEYPARAMS_set_oqs_key_params(PKI_KEYPARAMS * kp, PKI_ALGOR_OQS_PARAM algParam);

#endif // End of ENABLE_OQS

#endif // _LIBPKI_PKI_KEYPARAMS_H
