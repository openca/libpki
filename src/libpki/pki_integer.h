/* PKI_INTEGER */

#ifndef _LIBPKI_PKI_INTEGER_H
#define _LIBPKI_PKI_INTEGER_H

PKI_INTEGER *PKI_INTEGER_new_bin ( const unsigned char *data, size_t size );
PKI_INTEGER *PKI_INTEGER_new_char( const char *val );
PKI_INTEGER *PKI_INTEGER_new( long long val );
PKI_INTEGER *PKI_INTEGER_dup( const PKI_INTEGER *a );

void PKI_INTEGER_free_void( void *i );
int PKI_INTEGER_free( PKI_INTEGER *i );
char *PKI_INTEGER_get_parsed ( const PKI_INTEGER *i );

int PKI_INTEGER_cmp ( const PKI_INTEGER *a, const PKI_INTEGER *b );

int PKI_INTEGER_print( const PKI_INTEGER *s );
int PKI_INTEGER_print_fp( FILE *fp, const PKI_INTEGER *s );

#endif

