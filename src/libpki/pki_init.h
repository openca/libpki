/* Library Initialization */

#ifndef _LIBPKI_INIT_H
#define _LIBPKI_INIT_H

#ifndef _LIBPKI_STACK_H
#include <libpki/stack.h>
#endif

#if OPENSSL_VERSION_NUMBER > 0x3000000fL
#include <openssl/provider.h>
#endif

// ==================
// Defines and Macros
// ==================

// Definitions for the initialization status
#define PKI_STATUS_NOT_INIT			0
#define PKI_STATUS_INIT				1

// Definitions for the loaded providers by LibPKI
typedef enum {
    PKI_OSSL_PROV_DEFAULT       = 0,
    PKI_OSSL_PROV_OQS,
    PKI_OSSL_PROV_OCS,
    PKI_OSSL_PROV_LEGACY,
} PKI_OSSL_LIBPKI_PROVIDERS;

// Names for the different providers we want to load
#define PKI_OSSL_PROV_DEFAULT_NAME  "default"
#define PKI_OSSL_PROV_OQS_NAME      "oqsprovider"
#define PKI_OSSL_PROV_OCS_NAME      "ocsprovider"
#define PKI_OSSL_PROV_LEGACY_NAME   "legacy"

// ===================
// Function Prototypes
// ===================

int PKI_init_all( void ) __attribute__((constructor));
void PKI_final_all ( void );

int PKI_get_init_status ( void );

int PKI_is_fips_mode();
int PKI_set_fips_mode(int k);

PKI_STACK * PKI_list_all_tokens ( char *dir );
PKI_STACK * PKI_list_all_tokens_dir ( char * dir, PKI_STACK *list );

PKI_TOKEN_STACK *PKI_get_all_tokens ( char *dir );
PKI_TOKEN_STACK *PKI_get_all_tokens_dir ( char *dir, PKI_TOKEN_STACK *list );
PKI_ID_INFO_STACK * PKI_list_all_id ( void );

int PKI_init_providers(void);
int PKI_cleanup_providers(void);

#if OPENSSL_VERSION_NUMBER > 0x3000000fL
OSSL_LIB_CTX * PKI_init_get_ossl_library_ctx();
# else
void * PKI_init_get_ossl_library_ctx();
#endif // End of OPENSSL_VERSION_NUMBER > 0x3000000fL

#endif // End of _LIBPKI_INIT_H
