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

/*!
 * @brief Checks if a kepair requires a digest algorithm for signing
 * @param k The PKI_X509_KEYPAIR data structure
 * @return PKI_OK if a digest is required, PKI_ERR otherwise
 */
int PKI_X509_KEYPAIR_requires_digest(const PKI_X509_KEYPAIR * k);

/*!
 * @brief Checks if a kepair requires a digest algorithm for signing
 * @param k The PKI_X509_KEYPAIR_VALUE data structure
 * @return PKI_OK if a digest is required, PKI_ERR otherwise
 */
int PKI_X509_KEYPAIR_VALUE_requires_digest(const PKI_X509_KEYPAIR_VALUE * pkey);

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

/*!
 * \brief Returns the PKI_ID of the EC curve of the Key (EC keys only)
 */
int PKI_X509_KEYPAIR_get_curve(const PKI_X509_KEYPAIR *kp);

/* ----------------------- PKCS#8 Format ----------------------------- */

PKI_MEM *PKI_X509_KEYPAIR_get_p8(const PKI_X509_KEYPAIR *key );

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_p8(const PKI_MEM *buf );

/* --------------------- PKEY Encrypt/Decrypt --------------------------- */

/*! @brief This function encrypts the input data under a keypair and a padding scheme.
 *
 * @param pVal is the PKI_X509_KEYPAIR_VALUE that will be used for encryption
 * @param data is the pointer to the input data
 * @param data_len is the size of the input data
 * @param pad is the padding scheme to use (def. OAEP)
 * @return A pointer to a PKI_MEM structure that contains the encrypted data.
 */
PKI_MEM * PKI_X509_KEYPAIR_VALUE_encrypt(const PKI_X509_KEYPAIR_VALUE * pVal, 
                                         const unsigned char          * const data, 
                                         size_t                         const data_len,
                                         int                            const flags);

/*! @brief This function encrypts the input data under a keypair and a padding scheme.
 *
 * @param pVal is the PKI_X509_KEYPAIR that will be used for encryption
 * @param data is the pointer to the input data
 * @param data_len is the size of the input data
 * @param pad is the padding scheme to use (def. OAEP)
 * @return A pointer to a PKI_MEM structure that contains the encrypted data.
 */
PKI_MEM * PKI_X509_KEYPAIR_encrypt(const PKI_X509_KEYPAIR * keypair, 
                                   const unsigned char    * const data, 
                                   size_t                   const data_len,
                                   int                      const flags);

/*! @brief This function decrypts the input data via a keypair and a padding scheme.
 *
 * @param pVal is the PKI_X509_KEYPAIR_VALUE that was used to encrypt the data
 * @param data is the pointer to the encrypted data
 * @param data_len is the length of the encrypted data (bytes)
 * @param padding is the selected padding mode (def. OAEP)
 * @return a pointer to a PKI_MEM that contains the decrypted data.
 */ 
PKI_MEM * PKI_X509_KEYPAIR_VALUE_decrypt(const PKI_X509_KEYPAIR_VALUE * pVal, 
                                         const unsigned char          * const data, 
                                         size_t                         const data_len,
                                         int                            const flags);

/*! @brief This function decrypts the input data via a keypair and a padding scheme.
 *
 * @param pVal is the PKI_X509_KEYPAIR that was used to encrypt the data
 * @param data is the pointer to the encrypted data
 * @param data_len is the length of the encrypted data (bytes)
 * @param padding is the selected padding mode (def. OAEP)
 * @return a pointer to a PKI_MEM that contains the decrypted data.
 */ 
PKI_MEM * PKI_X509_KEYPAIR_decrypt(const PKI_X509_KEYPAIR * keypair, 
                                   const unsigned char    * const data, 
                                   size_t                   const data_len,
                                   int                      const flags);

/*! \brief Exports a raw public key value into a PKI_MEM 
 *
 * This function returns the internal structure of a public key in
 * its DER representation from a PKI_X509_KEYPAIR data structure.
 * For example, for RSA keys this function exports the following
 * data:
 * 
 *   rsaKey := SEQUENCE {
 *      modulus             INTEGER, 
 *      publicExponent      INTEGER }
 * 
 * in DER format in the output buffer. If the @pki_mem parameter
 * or the deferred pointer (@*pki_mem) are NULL, a new PKI_MEM
 * structure will be allocated and returned. In case the *pki_mem
 * is not NULL, the passed PKI_MEM structure will be used (if
 * any data is present it will be first freed with PKI_Free).
 * The function returns NULL in case of errors.
 * 
 * @param k_val The pointer to the PKI_X509_KEYPAIR to use
 * @param pki_mem The output structure where to store the data
 * @retval A pointer to the PKI_MEM with the retrieved data.
*/
PKI_MEM *PKI_X509_KEYPAIR_get_public_bitstring(const PKI_X509_KEYPAIR  * const k_val, 
							  	               PKI_MEM          	  ** pki_mem);

/*! \brief Exports a raw public key value into a PKI_MEM 
 *
 * This function returns the internal structure of a public key in
 * its DER representation from a PKI_X509_KEYPAIR_VALUE pointer.
 * For example, for RSA keys this function exports the following
 * data:
 * 
 *   rsaKey := SEQUENCE {
 *      modulus             INTEGER, 
 *      publicExponent      INTEGER }
 * 
 * in DER format in the output buffer. If the @pki_mem parameter
 * or the deferred pointer (@*pki_mem) are NULL, a new PKI_MEM
 * structure will be allocated and returned. In case the *pki_mem
 * is not NULL, the passed PKI_MEM structure will be used (if
 * any data is present it will be first freed with PKI_Free).
 * The function returns NULL in case of errors.
 * 
 * @param k_val The pointer to the PKI_X509_KEYPAIR_VALUE to use
 * @param pki_mem The output structure where to store the data
 * @retval A pointer to the PKI_MEM with the retrieved data.
*/
PKI_MEM *PKI_X509_KEYPAIR_VALUE_get_public_bitstring(const PKI_X509_KEYPAIR_VALUE  * const k_val, 
							  		                 PKI_MEM          		      ** pki_mem);

#endif
