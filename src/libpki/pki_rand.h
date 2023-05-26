/* libpki/pki_algor.h */

#ifndef _LIBPKI_PKI_RAND_H
#define _LIBPKI_PKI_RAND_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

/*!
 * @brief Returns an array of random bytes
 * @param buf The buffer to store the random bytes
 * @param num The size of the buffer
 * @return PKI_OK if the operation was successful, PKI_ERR otherwise
 */
int PKI_RAND_get( unsigned char **buf, size_t size);

#endif

