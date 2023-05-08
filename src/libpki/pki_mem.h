/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/

#ifndef _LIBPKI_PKI_MEM_H
#define _LIBPKI_PKI_MEM_H

#ifndef _LIBPKI_PKI_MEM_TYPES_H
#include <libpki/pki_mem_types.h>
#endif

#ifndef _LIBPKI_PKI_IO_H
#include <libpki/pki_io.h>
#endif

/* Function prototypes */

PKI_MEM *PKI_MEM_new ( size_t size );

/*!  \brief Creates a new PKI_MEM object with a copy of the passed data */
PKI_MEM *PKI_MEM_new_data ( size_t size, const unsigned char *data );
PKI_MEM *PKI_MEM_new_null ( void );
PKI_MEM *PKI_MEM_dup ( PKI_MEM *mem );

PKI_MEM *PKI_MEM_new_func ( void *obj, int (*func)() );
PKI_MEM *PKI_MEM_new_func_bio (void *obj, int (*func)());

int PKI_MEM_free ( PKI_MEM *buf );

int PKI_MEM_grow( PKI_MEM *buf, size_t new_size );
int PKI_MEM_add( PKI_MEM *buf, const unsigned char *data, size_t data_size );
const unsigned char * PKI_MEM_get_data(const PKI_MEM * const buf);
char * PKI_MEM_get_parsed(PKI_MEM *buf);
size_t PKI_MEM_get_size(const PKI_MEM * const buf );

ssize_t PKI_MEM_printf( PKI_MEM * buf );
ssize_t PKI_MEM_fprintf( FILE *file, PKI_MEM *buf );

PKI_MEM *PKI_MEM_new_membio ( PKI_IO *io );
PKI_MEM *PKI_MEM_new_bio ( PKI_IO *io, PKI_MEM **mem );

// Specific Format Encoding / Decoding
PKI_MEM *PKI_MEM_get_url_encoded( PKI_MEM *mem, int skip_newlines);
PKI_MEM *PKI_MEM_get_url_decoded( PKI_MEM *mem);
PKI_MEM *PKI_MEM_get_b64_encoded( PKI_MEM *mem, int addNewLines);
PKI_MEM *PKI_MEM_get_b64_decoded( PKI_MEM *mem, int withNewLines);

// Generic Format Encoding / Decoding
PKI_MEM * PKI_MEM_get_encoded(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);
PKI_MEM * PKI_MEM_get_decoded(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);

/*! 
 * @brief Encodes the contents of a PKI_MEM according to the provided data format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the format to be encoded. Supported
 *    formats are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 encoding, if this
 *    parameter is set to anything but 0, the encoded data will be bound with new lines
 *    every 76 chars. For URL encoding, if this parameter is set to anything but 0, new
 *    line characters (\n and \r) will be skipped (and, thus, NOT encoded).
 * @return PKI_OK if the decoding was successful. In case of errors, the appropriate
 *    error code is returned.
 */
int PKI_MEM_encode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);

/*! 
 * @brief Decodes the contents of a PKI_MEM according to the selected format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the format to be decoded. Supported
 *    formats are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 decoding, if this
 *    parameter is set to anything but 0, the decoded data will be bound with new lines
 *    every 76 chars (Max). For URL encoding, this parameter has no effect.
 * @return PKI_OK if the decoding was successful. In case of errors, the appropriate
 *    error code is returned.
 */
int PKI_MEM_decode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);

/*! @brief Attaches the passed data to the PKI_MEM */
int PKI_MEM_attach(PKI_MEM * mem, unsigned char * data, size_t len);

/*! @brief Detaches the data from the PKI_MEM */
int PKI_MEM_detach(PKI_MEM * mem, unsigned char ** data, size_t * len);

/*! @brief Transfers the data from src to dst */
int PKI_MEM_transfer(PKI_MEM * dst, PKI_MEM * src);

/*! @brief Clears (free) the data from a PKI_MEM */
int PKI_MEM_clear(PKI_MEM * mem);

#endif
