/* libpki/pki_algor.h */

#ifndef _LIBPKI_OS_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_UTILS_H
#define _LIBPKI_CRYPTO_UTILS_H

/*!
 * @brief Returns an array of random bytes
 * @param buf The buffer to store the random bytes
 * @param num The size of the buffer
 * @return PKI_OK if the operation was successful, PKI_ERR otherwise
 */
int CRYPTO_RAND(unsigned char **buf, size_t size);

/*! \brief Digests the data using the specified algorithm
 *
 * This function digests the data using the specified algorithm and returns the
 * digest in the out parameter. The out_size parameter is used to store the size
 * of the digest. The algorithm parameter is used to specify the algorithm to be
 * used. The data parameter is used to specify the data to be digested. The size
 * parameter is used to specify the size of the data. The salt parameter is used
 * to specify the salt to be used with the data. The salt_size parameter is used
 * to specify the size of the salt. The pepper parameter is used to specify the
 * pepper to be used with the data. The pepper_size parameter is used to specify
 * the size of the pepper.
 * 
 * @param out The digest
 * @param out_size The size of the digest
 * @param algorithm The algorithm to be used
 * @param data The data to be digested
 * @param size The size of the data
 * @param salt The salt to be used or NULL
 * @param salt_size The size of the salt
 * @param pepper The pepper to be used or NULL
 * @param pepper_size The size of the pepper
 * @param hsm The HSM to be used or NULL
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see CRYPTO_HASH
 */
int CRYPTO_DIGEST(unsigned char **out, size_t *out_size, 
                  CRYPTO_TYPE algorithm, const unsigned char *data, size_t size,
                  const unsigned char * salt, size_t salt_size,
                  const unsigned char * pepper, size_t pepper_size, HSM * hsm);

/*! \brief Signs the data using the specified HMAC algorithm and key
 *
 * This function signs the data using the specified HMAC algorithm and key and
 * returns the signature in the out parameter. The out_size parameter is used to
 * store the size of the signature. The hmac_algo parameter is used to specify
 * the HMAC algorithm to be used. The key parameter is used to specify the key to
 * be used with the HMAC algorithm. The key_size parameter is used to specify the
 * size of the key. The data parameter is used to specify the data to be signed.
 * The size parameter is used to specify the size of the data. The hash_algo
 * parameter is used to specify the hash algorithm to be used with the HMAC
 * algorithm. The hsm parameter is used to specify the HSM to be used.
 * 
 * @param out The signature
 * @param out_size The size of the signature
 * @param hmac_algo The HMAC algorithm to be used
 * @param key The key to be used
 * @param key_size The size of the key
 * @param data The data to be signed
 * @param size The size of the data
 * @param hash_algo The hash algorithm to be used
 * @param hsm The HSM to be used
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see CRYPTO_HASH
 * @see CRYPTO_DIGEST
 */
int CRYPTO_HMAC(unsigned char **out, size_t *out_size, 
                  CRYPTO_TYPE hmac_algo, unsigned char *key, size_t key_size,
                  const unsigned char *data, size_t size,
                  CRYPTO_HASH hash_algo, HSM *hsm);

/*! \brief Derives a symmetric key by using the specified algorithm
 *
 * This function derives a symmetric key by using the specified algorithm and
 * returns the key in the out parameter. The out_size parameter is used to store
 * the size of the key. The algorithm parameter is used to specify the algorithm
 * to be used. The label parameter is used to specify the label to be used with
 * the key. The label_size parameter is used to specify the size of the label.
 * The key parameter is used to specify the key to be used with the label. The
 * key_size parameter is used to specify the size of the key. The data parameter
 * is used to specify the data to be used with the key. The data_size parameter
 * is used to specify the size of the data.
 * 
 * @param out The key
 * @param out_size The size of the key
 * @param algorithm The algorithm to be used
 * @param label The label to be used
 * @param label_size The size of the label
 * @param key The key to be used
 * @param key_size The size of the key
 * @param data The data to be used
 * @param data_size The size of the data
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see CRYPTO_HASH
 */
int CRYPTO_KDF(unsigned char    ** out, 
			   size_t            * outlen,
			   unsigned char     * label,
			   size_t              labelen, 
			   unsigned char     * key, 
			   size_t              keylen, 
			   unsigned char     * data, 
			   size_t              datalen,
               const CRYPTO_HASH   hash_alg);

#endif /* _LIBPKI_CRYPTO_UTILS_H */

