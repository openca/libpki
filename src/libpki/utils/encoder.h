/* PKI Data Encoder */


#ifndef _LIBPKI_PKI_DATA_ENCODER_H
#define _LIBPKI_PKI_DATA_ENCODER_H

#include <sys/types.h>

/* \brief Data Formats
 *
 * Encodes the data from one format to another
 */
int PKI_DATA_encode ( const void *data, const size_t size, 
			const PKI_TYPE data_format, void **out, size_t *out_size, int out_format );

#endif /* _LIBPKI_PKI_DATA_ENCODER_H */
