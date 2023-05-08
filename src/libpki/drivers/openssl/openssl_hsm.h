/* libpki/drivers/openssl/openssl_hsm.h */

#ifndef _LIBPKI_HSM_OPENSSL_H
#define _LIBPKI_HSM_OPENSSL_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_PKI_MEM_TYPES_H
#include <libpki/pki_mem_types.h>
#endif

#ifndef _LIBPKI_CONF_TYPES_H
#include <libpki/pki_config_types.h>
#endif

#ifndef _LIBPKI_HSM_ST_H
#include <libpki/hsm_st.h>
#endif

#ifndef _LIBPKI_INIT_H
#include <libpki/pki_init.h>
#endif

#ifndef _LIBPKI_PKI_X509_H
#include <libpki/pki_x509.h>
#endif

#ifndef _LIBPKI_PKI_KEYPAIR_TYPES_H
#include <libpki/pki_keypair_types.h>
#endif

#ifndef _LIBPKI_PKI_ID_H
#include <libpki/pki_id.h>
#endif

// #ifndef _LIBPKI_OPENSSL_HSM_CB_H
// #include <libpki/drivers/openssl/openssl_hsm_cb.h>
// #endif

// #ifndef _LIBPKI_HEADERS_OPENSSL_PKEY_H
// #include <libpki/drivers/openssl/openssl_hsm_pkey.h>
// #endif

// #ifndef _LIBPKI_ERRORS_H
// #include <libpki/pki_err.h>
// #endif

// #ifndef _LIBPKI_INIT_H
// #include <libpki/pki_init.h>
// #endif

// #ifndef _LIBPKI_PKI_X509_H
// #include <libpki/pki_x509.h>
// #endif

// #ifndef _LIBPKI_LOG_H
// #include <libpki/pki_log.h>
// #endif

// #ifndef _LIBPKI_PKI_ID_H
// #include <libpki/pki_id.h>
// #endif

// #include <openssl/ssl.h>

BEGIN_C_DECLS

						// ====================
						// Functions Prototypes
						// ====================

unsigned long HSM_OPENSSL_get_errno ( void );
char * HSM_OPENSSL_get_errdesc ( unsigned long err, char *str, size_t size );

HSM * HSM_OPENSSL_new( PKI_CONFIG *conf );
const HSM * HSM_OPENSSL_get_default( void );

int HSM_OPENSSL_free ( HSM *driver, PKI_CONFIG *conf );
int HSM_OPENSSL_init ( HSM *driver, PKI_CONFIG *conf );

int HSM_OPENSSL_set_fips_mode(const HSM *driver, int k);
int HSM_OPENSSL_is_fips_mode(const HSM *driver);

/* ---------------------- Sign/Verify functions ----------------------- */

PKI_MEM * HSM_OPENSSL_sign(PKI_MEM          * der,
						   PKI_DIGEST_ALG   * digest,
						   PKI_X509_KEYPAIR * key );

/* ---------------------- OPENSSL Slot Management Functions ---------------- */
HSM_SLOT_INFO * HSM_OPENSSL_SLOT_INFO_get(unsigned long  num, 
										  HSM           * hsm_void);

END_C_DECLS 

#endif
