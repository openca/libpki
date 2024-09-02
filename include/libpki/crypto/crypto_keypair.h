/* crypto_keypair.h */

#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_KEYPAIR_H
#define _LIBPKI_CRYPTO_KEYPAIR_H

int CRYPTO_KEYPAIR_new(CRYPTO_KEYPAIR ** out,
                       HSM             * hsm);

void CRYPTO_KEYPAIR_free(CRYPTO_KEYPAIR *key);

int CRYPTO_KEYPAIR_generate(CRYPTO_KEYPAIR *key, const CRYPTO_KEYPARAMS * params, char * label);

int CRYPTO_KEYPAIR_clear(CRYPTO_KEYPAIR *key);

int CRYPTO_KEYPAIR_get(unsigned char        ** privkey, /* p8 */
                       size_t                * privkey_size,
                       unsigned char        ** pubkey, /* pub bitstring */
                       size_t                * pubkey_size,
                       PKI_CRED              * cred,
                       const CRYPTO_KEYPAIR  * key);

int CRYPTO_KEYPAIR_set(CRYPTO_KEYPAIR      ** key, 
                       const unsigned char  * in, /* p8 */
                       size_t                 size,
                       PKI_CRED             * cred);

CRYPTO_HASH CRYPTO_KEYPAIR_info(int * size, int * requires_hash, int * default_hash, 
    int * key_type, int * curve, int * bits, char * label, int * id, const CRYPTO_KEYPAIR * key);


// // CRYPTO_KEYPAIR *CRYPTO_KEYPAIR_new_kp(PKI_KEYPARAMS * kp,
// //                                       PKI_CRED      * cred,
// //                                       char          * label,
// //                                       HSM           * hsm);

// // CRYPTO_KEYPAIR *CRYPTO_KEYPAIR_new_url(CRYPTO_TYPE   type,
// // 	                                         int             bits, 
// //                                            URL           * url,
// //                                            PKI_CRED      * cred,
// //                                            HSM           * hsm);

// // CRYPTO_KEYPAIR *CRYPTO_KEYPAIR_new_url_kp(PKI_KEYPARAMS * kp,
// //                                               URL           * url,
// //                                               PKI_CRED      * cred,
// //                                               HSM           * hsm);

// // /* ------------------------ General Functions ----------------------- */

// // char *CRYPTO_KEYPAIR_get_parsed(const CRYPTO_KEYPAIR *pkey );

// // CRYPTO_TYPE CRYPTO_KEYPAIR_get_scheme(const CRYPTO_KEYPAIR *k);

// // void * CRYPTO_KEYPAIR_get_algor(const CRYPTO_KEYPAIR * k, 
// //                                                   const PKI_DIGEST_ALG   * digest);

// // int CRYPTO_KEYPAIR_get_id(const CRYPTO_KEYPAIR * key);

// // int CRYPTO_KEYPAIR_VALUE_get_id(const CRYPTO_KEYPAIR_VALUE * pkey);

// // // /*!
// // //  * \brief Returns the OSSL key type of the keypair
// // //  *
// // //  * This function returns the OSSL key type of the keypair. The
// // //  * returned value can be used to compare with PKEY_METHOD backed
// // //  * keys.
// // //  * 
// // //  * @param pkey A pointer to the CRYPTO_KEYPAIR_VALUE data structure
// // //  * @return The OSSL key type of the keypair (int)
// // //  */
// // // int CRYPTO_KEYPAIR_get_ossl_type(const CRYPTO_KEYPAIR * pkey);

// // // /*!
// // //  * @brief Returns the OSSL key type of the keypair value
// // //  *
// // //  * This function returns the OSSL key type of the keypair value. The
// // //  * returned value can be used to compare with PKEY_METHOD backed
// // //  * keys (e.g., type == EVP_PKEY_RSA)
// // //  * 
// // //  * @param pkey A pointer to the CRYPTO_KEYPAIR_VALUE data structure
// // //  * @return The OSSL key type of the keypair value (int)
// // //  */
// // // int CRYPTO_KEYPAIR_VALUE_get_ossl_type(const CRYPTO_KEYPAIR_VALUE * pkey);

// /// @brief Returns the ID of the default digest algorithm for a CRYPTO_KEYPAIR
// /// @param key A CRYPTO_KEYPAIR data structure
// /// @return The PKI_ID of the identified algorithm or PKI_ID_UNKNOWN
// int CRYPTO_KEYPAIR_get_default_digest(const CRYPTO_KEYPAIR * key);

// /// @brief Returns the ID of the default digest algorithm for a CRYPTO_KEYPAIR_VALUE 
// /// @param pkey A CRYPTO_KEYPAIR_VALUE data structure
// /// @return The PKI_ID of the identified algorithm or PKI_ID_UKNOWN
// int CRYPTO_KEYPAIR_VALUE_get_default_digest(const CRYPTO_KEYPAIR_VALUE * pkey);

// /*!
//  * @brief Checks if a kepair requires a digest algorithm for signing
//  * @param k The CRYPTO_KEYPAIR data structure
//  * @return PKI_OK if a digest is required, PKI_ERR otherwise
//  */
// int CRYPTO_KEYPAIR_requires_digest(const CRYPTO_KEYPAIR * k);

// /*!
//  * @brief Checks if a kepair requires a digest algorithm for signing
//  * @param k The CRYPTO_KEYPAIR_VALUE data structure
//  * @return PKI_OK if a digest is required, PKI_ERR otherwise
//  */
// int CRYPTO_KEYPAIR_VALUE_requires_digest(const CRYPTO_KEYPAIR_VALUE * pkey);

// /// @brief Returns PKI_OK if the digest algorithm is supported by the Public Key
// /// @param k A pointer to the CRYPTO_KEYPAIR data structure
// /// @param digest A pointer to te PKI_DIGEST_ALG
// /// @return The PKI_OK value if the digest is supported, PKI_ERR otherwise
// int CRYPTO_KEYPAIR_is_digest_supported(const CRYPTO_KEYPAIR * k, const PKI_DIGEST_ALG * digest);

// /// @brief Returns if the passed digest is supported by the Public Key
// /// @param k A pointer to the CRYPTO_KEYPAIR_VALUE data structure
// /// @param digest A pointer to te PKI_DIGEST_ALG
// /// @return The PKI_OK value if the digest is supported, PKI_ERR otherwise
// int CRYPTO_KEYPAIR_VALUE_is_digest_supported(const CRYPTO_KEYPAIR_VALUE * pkey, const PKI_DIGEST_ALG * digest);

// int CRYPTO_KEYPAIR_get_size(const CRYPTO_KEYPAIR *k);

// PKI_MEM *CRYPTO_KEYPAIR_get_pubkey(const CRYPTO_KEYPAIR *kp);

// PKI_MEM *CRYPTO_KEYPAIR_get_privkey(const CRYPTO_KEYPAIR *kp);

// CRYPTO_DIGEST *CRYPTO_KEYPAIR_VALUE_pub_digest(const CRYPTO_KEYPAIR_VALUE * pkey,
//                                               const PKI_DIGEST_ALG         * md );

// CRYPTO_TYPE CRYPTO_KEYPAIR_VALUE_get_scheme(const CRYPTO_KEYPAIR_VALUE *pVal);

// PKI_X509_ALGOR_VALUE * CRYPTO_KEYPAIR_VALUE_get_algor (const CRYPTO_KEYPAIR_VALUE * pVal,
//                                                          const PKI_ID                   digest_id);

// int CRYPTO_KEYPAIR_VALUE_get_size (const  CRYPTO_KEYPAIR_VALUE *pKey );

// CRYPTO_DIGEST *CRYPTO_KEYPAIR_pub_digest (const CRYPTO_KEYPAIR * pkey, 
//                                          const PKI_DIGEST_ALG   * md);

// /* ------------------------ EC Specific ------------------------------ */

// /*!
//  * \brief Returns the PKI_ID of the EC curve of the Key (EC keys only)
//  */
// int CRYPTO_KEYPAIR_get_curve(const CRYPTO_KEYPAIR *kp);

// /* ----------------------- PKCS#8 Format ----------------------------- */

// PKI_MEM *CRYPTO_KEYPAIR_VALUE_get_p8 (const CRYPTO_KEYPAIR_VALUE * pkey );

// PKI_MEM *CRYPTO_KEYPAIR_get_p8(const CRYPTO_KEYPAIR *key );

// CRYPTO_KEYPAIR_VALUE *CRYPTO_KEYPAIR_VALUE_new_p8(const PKI_MEM *buf );

// CRYPTO_KEYPAIR *CRYPTO_KEYPAIR_new_p8(const PKI_MEM *buf );

// /* --------------------- PKEY Encrypt/Decrypt --------------------------- */

// /*! @brief This function encrypts the input data under a keypair and a padding scheme.
//  *
//  * @param pVal is the CRYPTO_KEYPAIR_VALUE that will be used for encryption
//  * @param data is the pointer to the input data
//  * @param data_len is the size of the input data
//  * @param pad is the padding scheme to use (def. OAEP)
//  * @return A pointer to a PKI_MEM structure that contains the encrypted data.
//  */
// PKI_MEM * CRYPTO_KEYPAIR_VALUE_encrypt(const CRYPTO_KEYPAIR_VALUE * pVal, 
//                                          const unsigned char          * const data, 
//                                          size_t                         const data_len,
//                                          int                            const flags);

// /*! @brief This function encrypts the input data under a keypair and a padding scheme.
//  *
//  * @param pVal is the CRYPTO_KEYPAIR that will be used for encryption
//  * @param data is the pointer to the input data
//  * @param data_len is the size of the input data
//  * @param pad is the padding scheme to use (def. OAEP)
//  * @return A pointer to a PKI_MEM structure that contains the encrypted data.
//  */
// PKI_MEM * CRYPTO_KEYPAIR_encrypt(const CRYPTO_KEYPAIR * keypair, 
//                                    const unsigned char    * const data, 
//                                    size_t                   const data_len,
//                                    int                      const flags);

// /*! @brief This function decrypts the input data via a keypair and a padding scheme.
//  *
//  * @param pVal is the CRYPTO_KEYPAIR_VALUE that was used to encrypt the data
//  * @param data is the pointer to the encrypted data
//  * @param data_len is the length of the encrypted data (bytes)
//  * @param padding is the selected padding mode (def. OAEP)
//  * @return a pointer to a PKI_MEM that contains the decrypted data.
//  */ 
// PKI_MEM * CRYPTO_KEYPAIR_VALUE_decrypt(const CRYPTO_KEYPAIR_VALUE * pVal, 
//                                          const unsigned char          * const data, 
//                                          size_t                         const data_len,
//                                          int                            const flags);

// /*! @brief This function decrypts the input data via a keypair and a padding scheme.
//  *
//  * @param pVal is the CRYPTO_KEYPAIR that was used to encrypt the data
//  * @param data is the pointer to the encrypted data
//  * @param data_len is the length of the encrypted data (bytes)
//  * @param padding is the selected padding mode (def. OAEP)
//  * @return a pointer to a PKI_MEM that contains the decrypted data.
//  */ 
// PKI_MEM * CRYPTO_KEYPAIR_decrypt(const CRYPTO_KEYPAIR * keypair, 
//                                    const unsigned char    * const data, 
//                                    size_t                   const data_len,
//                                    int                      const flags);

// /*! \brief Exports a raw public key value into a PKI_MEM 
//  *
//  * This function returns the internal structure of a public key in
//  * its DER representation from a CRYPTO_KEYPAIR data structure.
//  * For example, for RSA keys this function exports the following
//  * data:
//  * 
//  *   rsaKey := SEQUENCE {
//  *      modulus             INTEGER, 
//  *      publicExponent      INTEGER }
//  * 
//  * in DER format in the output buffer. If the @pki_mem parameter
//  * or the deferred pointer (@*pki_mem) are NULL, a new PKI_MEM
//  * structure will be allocated and returned. In case the *pki_mem
//  * is not NULL, the passed PKI_MEM structure will be used (if
//  * any data is present it will be first freed with PKI_Free).
//  * The function returns NULL in case of errors.
//  * 
//  * @param k_val The pointer to the CRYPTO_KEYPAIR to use
//  * @param pki_mem The output structure where to store the data
//  * @retval A pointer to the PKI_MEM with the retrieved data.
// */
// PKI_MEM *CRYPTO_KEYPAIR_get_public_bitstring(const CRYPTO_KEYPAIR  * const k_val, 
// 							  	               PKI_MEM          	  ** pki_mem);

// /*! \brief Exports a raw public key value into a PKI_MEM 
//  *
//  * This function returns the internal structure of a public key in
//  * its DER representation from a CRYPTO_KEYPAIR_VALUE pointer.
//  * For example, for RSA keys this function exports the following
//  * data:
//  * 
//  *   rsaKey := SEQUENCE {
//  *      modulus             INTEGER, 
//  *      publicExponent      INTEGER }
//  * 
//  * in DER format in the output buffer. If the @pki_mem parameter
//  * or the deferred pointer (@*pki_mem) are NULL, a new PKI_MEM
//  * structure will be allocated and returned. In case the *pki_mem
//  * is not NULL, the passed PKI_MEM structure will be used (if
//  * any data is present it will be first freed with PKI_Free).
//  * The function returns NULL in case of errors.
//  * 
//  * @param k_val The pointer to the CRYPTO_KEYPAIR_VALUE to use
//  * @param pki_mem The output structure where to store the data
//  * @retval A pointer to the PKI_MEM with the retrieved data.
// */
// PKI_MEM *CRYPTO_KEYPAIR_VALUE_get_public_bitstring(const CRYPTO_KEYPAIR_VALUE  * const k_val, 
// 							  		                 PKI_MEM          		      ** pki_mem);

#endif
