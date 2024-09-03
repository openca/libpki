/* pki_keypair.h */

#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_OPERATIONS_H
#define _LIBPKI_CRYPTO_OPERATIONS_H

/*! \brief This function signs the input data using a keypair and a digest algorithm.
 *
 * @param sig is the pointer to the signature
 * @param sig_len is the size of the signature
 * @param data is the pointer to the input data
 * @param data_len is the size of the input data
 * @param digest is the digest algorithm to use
 * @param key is the keypair to use for signing
 * @return PKI_OK if the signature is successful, PKI_ERR otherwise
*/
int CRYPTO_sign(const byte           ** sig, 
                size_t                * sig_len,
                const byte            * data, 
                size_t                  data_len,  
                const CRYPTO_HASH     * digest,
                const CRYPTO_KEYPAIR  * key);

int CRYPTO_verify(const byte           * sig, 
                  size_t                 sig_len,
                  const byte           * data, 
                  size_t                 data_len,
                  const CRYPTO_HASH    * digest,
                  const CRYPTO_KEYPAIR * key);

/*! @brief This function encrypts the input data under a keypair and a padding scheme.
 *
 * @param pVal is the CRYPTO_KEYPAIR_VALUE that will be used for encryption
 * @param data is the pointer to the input data
 * @param data_len is the size of the input data
 * @param pad is the padding scheme to use (def. OAEP)
 * @return A pointer to a PKI_MEM structure that contains the encrypted data.
 */
int CRYPTO_encrypt(const byte          ** enc_data,
                   size_t                 const enc_data_size,
                   const byte           * const data, 
                   size_t                 const data_len,
                   int                    const flags,
                   const CRYPTO_KEYPAIR * keypair);

/*! @brief This function decrypts the input data via a keypair and a padding scheme.
 *
 * This function decrypts the input data via a keypair and a padding scheme.
 * The decrypted data is returned in a 
 *
 * @param pVal is the CRYPTO_KEYPAIR_VALUE that was used to encrypt the data
 * @param data is the pointer to the encrypted data
 * @param data_len is the length of the encrypted data (bytes)
 * @param padding is the selected padding mode (def. OAEP)
 * @return a pointer to a PKI_MEM that contains the decrypted data.
 */
int CRYPTO_decrypt(const byte          ** dec_data,
                   size_t                 const dec_data_size,
                   const byte           * const data, 
                   size_t                 const data_len,
                   int                    const flags,
                   const CRYPTO_KEYPAIR * keypair);

#endif /* _LIBPKI_CRYPTO_OPERATIONS_H */
