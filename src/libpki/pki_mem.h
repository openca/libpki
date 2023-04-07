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

#ifndef _LIBPKI_PKI_IO_H
#include <libpki/pki_io.h>
#endif

#ifndef _LIBPKI_PKI_MEM_H
#define _LIBPKI_PKI_MEM_H

typedef struct pki_mem_st {
	unsigned char * data;
	// size_t current;
	size_t size;
} PKI_MEM;

/* Function prototypes */

void *PKI_Malloc( size_t size );
void PKI_Free( void *ret );
void PKI_ZFree ( void *pnt, size_t size );
void PKI_ZFree_str ( char *str );

PKI_MEM *PKI_MEM_new ( size_t size );
PKI_MEM *PKI_MEM_new_data ( size_t size, const unsigned char *data );
PKI_MEM *PKI_MEM_new_null ( void );
PKI_MEM *PKI_MEM_dup ( PKI_MEM *mem );

PKI_MEM *PKI_MEM_new_func ( void *obj, int (*func)() );
PKI_MEM *PKI_MEM_new_func_bio (void *obj, int (*func)());

int PKI_MEM_free ( PKI_MEM *buf );

int PKI_MEM_grow( PKI_MEM *buf, size_t new_size );
int PKI_MEM_add( PKI_MEM *buf, const unsigned char *data, size_t data_size );
unsigned char * PKI_MEM_get_data( PKI_MEM *buf );
char * PKI_MEM_get_parsed(PKI_MEM *buf);
size_t PKI_MEM_get_size( PKI_MEM *buf );

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

// Generic (in-place) Format Encoding / Decoding
int PKI_MEM_encode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);
int PKI_MEM_decode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opt);

#endif
