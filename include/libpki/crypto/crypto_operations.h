/* pki_keypair.h */

#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_OPERATIONS_H
#define _LIBPKI_CRYPTO_OPERATIONS_H

int CRYPTO_sign(unsigned char        ** sig, 
                size_t                * sig_len,
                const unsigned char   * data, 
                size_t                  data_len,  
                const CRYPTO_HASH     * digest,
                const CRYPTO_KEYPAIR  * key);

int CRYPTO_verify(const unsigned char  * sig, 
                  size_t                 sig_len,
                  const unsigned char  * data, 
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
int CRYPTO_encrypt(const unsigned char ** enc_data,
                   size_t                 const enc_data_size,
                   const unsigned char  * const data, 
                   size_t                 const data_len,
                   int                    const flags,
                   const CRYPTO_KEYPAIR * keypair);


#endif
