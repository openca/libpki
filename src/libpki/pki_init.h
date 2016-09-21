/* Library Initialization */

#ifndef __LIBPKI_INIT_H__
#define __LIBPKI_INIT_H__

#ifndef __LIBPKI_BASE_H__
#include <libpki/base.h>
#endif

#ifndef __LIBPKI_STACK_H__
#include <libpki/stack.h>
#endif

#ifndef __LIBPKI_CRYPTO_H__
#include <libpki/crypto.h>
#endif

#ifndef __LIBPKI_OID_H__
#include <libpki/pki_oid.h>
#endif

BEGIN_C_DECLS

#define PKI_STATUS_NOT_INIT      0
#define PKI_STATUS_INIT          1

int PKI_init_all( void );
void PKI_final_all ( void );

int PKI_get_init_status ( void );

int PKI_is_fips_mode();
int PKI_set_fips_mode(int k);

PKI_STACK * PKI_list_all_tokens ( char *dir );
PKI_STACK * PKI_list_all_tokens_dir ( char * dir, PKI_STACK *list );

PKI_TOKEN_STACK *PKI_get_all_tokens ( char *dir );
PKI_TOKEN_STACK *PKI_get_all_tokens_dir ( char *dir, PKI_TOKEN_STACK *list );
PKI_ID_INFO_STACK * PKI_list_all_id ( void );

END_C_DECLS

#endif
