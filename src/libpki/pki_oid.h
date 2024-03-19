// Description: Header file for OID handling functions.
#ifndef _LIBPKI_OID_H
#define _LIBPKI_OID_H
# pragma once

// LibPKI Includes
#include <libpki/openssl/data_st.h>
#include <libpki/stack.h>

BEGIN_C_DECLS

// Stack Declarations
DECLARE_LIBPKI_STACK_FN_DUP(PKI_OID)

// ===================
// Function Prototypes
// ===================

PKI_OID *PKI_OID_new( const char *oid, const char *name, const char *descr );
PKI_OID *PKI_OID_new_id ( PKI_ID id );
PKI_OID *PKI_OID_new_text ( const char *name );
PKI_OID *PKI_OID_get( const char *name );

void PKI_OID_free ( PKI_OID *oid );

PKI_OID *PKI_OID_dup( const PKI_OID *a );
int PKI_OID_cmp( const PKI_OID *a, const PKI_OID *b );

PKI_ID PKI_OID_get_id ( const PKI_OID *a );
const char * PKI_OID_get_descr ( const PKI_OID *a );
char * PKI_OID_get_str ( const PKI_OID *a );

END_C_DECLS

#endif // End of _LIBPKI_OID_H

