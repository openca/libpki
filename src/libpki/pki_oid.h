/* OID management for libpki */

#ifndef _LIBPKI_OID_H
#define _LIBPKI_OID_H

PKI_OID *PKI_OID_new( char *oid, char *name, char *descr );
PKI_OID *PKI_OID_new_id ( PKI_ID id );
PKI_OID *PKI_OID_new_text ( char *name );
PKI_OID *PKI_OID_get( char *name );

void PKI_OID_free ( PKI_OID *oid );

PKI_OID *PKI_OID_dup( PKI_OID *a );
int PKI_OID_cmp( PKI_OID *a, PKI_OID *b );

PKI_ID PKI_OID_get_id ( PKI_OID *a );
const char * PKI_OID_get_descr ( PKI_OID *a );
char * PKI_OID_get_str ( PKI_OID *a );

#endif

