/* libpki/drivers/openssl/openssl_hsm.h */

#ifndef _LIBPKI_HSM_OPENSSL_H
#define _LIBPKI_HSM_OPENSSL_H

unsigned long HSM_OPENSSL_get_errno ( void );
char * HSM_OPENSSL_get_errdesc ( unsigned long err, char *str, size_t size );

HSM * HSM_OPENSSL_new( PKI_CONFIG *conf );
const HSM * HSM_OPENSSL_get_default( void );

int HSM_OPENSSL_free ( HSM *driver, PKI_CONFIG *conf );
int HSM_OPENSSL_init ( HSM *driver, PKI_CONFIG *conf );

int HSM_OPENSSL_set_fips_mode(const HSM *driver, int k);
int HSM_OPENSSL_is_fips_mode(const HSM *driver);

/* ---------------------- Sign/Verify functions ----------------------- */

/*
 * int HSM_OPENSSL_sign ( PKI_MEM *der, PKI_X509_KEYPAIR *key, 
 * PKI_DIGEST_ALG *al);
 */

PKI_MEM * HSM_OPENSSL_sign ( PKI_MEM *der, PKI_DIGEST_ALG *digest,
					PKI_X509_KEYPAIR *key );

/*
int HSM_OPENSSL_verify ( PKI_X509 *x, PKI_X509_KEYPAIR *key );
*/

/* ---------------------- OPENSSL Slot Management Functions ---------------- */
HSM_SLOT_INFO * HSM_OPENSSL_SLOT_INFO_get ( unsigned long num, HSM *hsm_void);

#endif
