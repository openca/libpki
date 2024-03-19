/* PKI_ID_INFO data structure definition */

#ifndef _LIBPKI_PKI_ID_INFO_H
#define _LIBPKI_PKI_ID_INFO_H
# pragma once

// LibPKI Includes
#include <libpki/token.h>

// LibPKI Includes
#include <libpki/pki_id_info_st.h>

BEGIN_C_DECLS

// Stack Declarations
DECLARE_OSSL_STACK_FN(PKI_ID_INFO)

						// ====================
						// Functions Prototypes
						// ====================

PKI_ID_INFO *PKI_ID_INFO_new_null( void );

PKI_ID_INFO *PKI_ID_INFO_new( const char *label, PKI_TOKEN *tk );
void PKI_ID_INFO_free ( PKI_ID_INFO *id );

END_C_DECLS

#endif // End of _LIBPKI_PKI_ID_INFO_H
