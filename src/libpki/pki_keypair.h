/* pki_keypair.h */

#ifndef _LIBPKI_X509_KEYPAIR_HEADER_H
#define _LIBPKI_X509_KEYPAIR_HEADER_H

#ifdef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/datatypes.h>
#endif

typedef struct pw_cb_data {
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

#define PKI_X509_KEYPAIR_new_RSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new( PKI_SCHEME_RSA,a,l,c,h );
		
#define PKI_X509_KEYPAIR_new_DSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new( PKI_SCHEME_DSA,a,l,c,h );

#ifdef ENABLE_ECDSA
#define PKI_X509_KEYPAIR_new_ECDSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new(PKI_SCHEME_ECDSA,a,l,c,h);
#endif

/* ------------------------ Memory Management ----------------------- */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_null ();

void PKI_X509_KEYPAIR_free( PKI_X509_KEYPAIR *key );

void PKI_X509_KEYPAIR_free_void ( void *key );

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new(PKI_SCHEME_ID   type,
	                                     int             bits, 
                                       char          * label,
                                       PKI_CRED      * cred,
                                       HSM           * hsm);

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_kp(PKI_KEYPARAMS * kp,
                                          char          * label,
                                          PKI_CRED      * cred,
                                          HSM           * hsm);

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url(PKI_SCHEME_ID   type,
	                                         int             bits, 
                                           URL           * url,
                                           PKI_CRED      * cred,
                                           HSM           * hsm);

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url_kp(PKI_KEYPARAMS * kp,
                                              URL           * url,
                                              PKI_CRED      * cred,
                                              HSM           * hsm);

/* ------------------------ General Functions ----------------------- */

char *PKI_X509_KEYPAIR_get_parsed(const PKI_X509_KEYPAIR *pkey );

PKI_SCHEME_ID PKI_X509_KEYPAIR_get_scheme(const PKI_X509_KEYPAIR *k);

PKI_X509_ALGOR_VALUE * PKI_X509_KEYPAIR_get_algor(const PKI_X509_KEYPAIR *k);

int PKI_X509_KEYPAIR_get_id(const PKI_X509_KEYPAIR * key);

int PKI_X509_KEYPAIR_VALUE_get_id(const PKI_X509_KEYPAIR_VALUE * pkey);

/// @brief Returns the ID of the default digest algorithm for a PKI_X509_KEYPAIR
/// @param key A PKI_X509_KEYPAIR data structure
/// @return The PKI_ID of the identified algorithm or PKI_ID_UNKNOWN
int PKI_X509_KEYPAIR_get_default_digest(const PKI_X509_KEYPAIR * key);

/// @brief Returns the ID of the default digest algorithm for a PKI_X509_KEYPAIR_VALUE 
/// @param pkey A PKI_X509_KEYPAIR_VALUE data structure
/// @return The PKI_ID of the identified algorithm or PKI_ID_UKNOWN
int PKI_X509_KEYPAIR_VALUE_get_default_digest(const PKI_X509_KEYPAIR_VALUE * pkey);

/// @brief Returns PKI_OK if the digest algorithm is supported by the Public Key
/// @param k A pointer to the PKI_X509_KEYPAIR data structure
/// @param digest A pointer to te PKI_DIGEST_ALG
/// @return The PKI_OK value if the digest is supported, PKI_ERR otherwise
int PKI_X509_KEYPAIR_is_digest_supported(const PKI_X509_KEYPAIR * k, const PKI_DIGEST_ALG * digest);

/// @brief Returns if the passed digest is supported by the Public Key
/// @param k A pointer to the PKI_X509_KEYPAIR_VALUE data structure
/// @param digest A pointer to te PKI_DIGEST_ALG
/// @return The PKI_OK value if the digest is supported, PKI_ERR otherwise
int PKI_X509_KEYPAIR_VALUE_is_digest_supported(const PKI_X509_KEYPAIR_VALUE * pkey, const PKI_DIGEST_ALG * digest);

int PKI_X509_KEYPAIR_get_size(const PKI_X509_KEYPAIR *k);

PKI_MEM *PKI_X509_KEYPAIR_get_pubkey(const PKI_X509_KEYPAIR *kp);

PKI_MEM *PKI_X509_KEYPAIR_get_privkey(const PKI_X509_KEYPAIR *kp);

PKI_DIGEST *PKI_X509_KEYPAIR_VALUE_pub_digest(const PKI_X509_KEYPAIR_VALUE * pkey,
                                              const PKI_DIGEST_ALG         * md );

PKI_SCHEME_ID PKI_X509_KEYPAIR_VALUE_get_scheme(const PKI_X509_KEYPAIR_VALUE *pVal);

PKI_X509_ALGOR_VALUE * PKI_X509_KEYPAIR_VALUE_get_algor (const  PKI_X509_KEYPAIR_VALUE *pVal );

int PKI_X509_KEYPAIR_VALUE_get_size (const  PKI_X509_KEYPAIR_VALUE *pKey );

PKI_DIGEST *PKI_X509_KEYPAIR_pub_digest (const PKI_X509_KEYPAIR * pkey, 
                                         const PKI_DIGEST_ALG   * md);

/* ------------------------ EC Specific ------------------------------ */

int PKI_X509_KEYPAIR_get_curve(const PKI_X509_KEYPAIR *kp);

/* ----------------------- PKCS#8 Format ----------------------------- */

PKI_MEM *PKI_X509_KEYPAIR_get_p8(const PKI_X509_KEYPAIR *key );

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_p8(const PKI_MEM *buf );

#endif
