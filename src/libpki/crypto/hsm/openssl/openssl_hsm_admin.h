/* openssl_hsm_admin.h */

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_TYPES_H
#include <libpki/crypto/hsm/openssl/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_ADMIN_H
#define _LIBPKI_CRYPTO_HSM_OPENSSL_ADMIN_H

BEGIN_C_DECLS

int HSM_OPENSSL_is_fips_mode(const HSM *hsm);

int HSM_OPENSSL_login ( HSM *hsm, PKI_CRED *cred );

int HSM_OPENSSL_logout ( HSM *hsm );

unsigned long HSM_OPENSSL_get_errno ( const HSM *hsm );

char *HSM_OPENSSL_get_errdesc ( unsigned long err, const HSM *hsm );

int HSM_OPENSSL_login ( HSM *hsm, PKI_CRED *cred );

int HSM_OPENSSL_logout ( HSM *hsm );

unsigned long HSM_OPENSSL_get_errno ( const HSM *hsm );

char *HSM_OPENSSL_get_errdesc ( unsigned long err, const HSM *hsm );


// /* ------------------- Keypair Functions --------------------- */

// PKI_X509_KEYPAIR *HSM_OPENSSL_X509_KEYPAIR_new( PKI_KEYPARAMS *pk, 
// 		URL *url, PKI_CRED *cred, HSM *driver );
// void HSM_OPENSSL_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey );

// int OPENSSL_HSM_write_bio_PrivateKey (BIO *bp, EVP_PKEY *x, 
// 		const EVP_CIPHER *enc, unsigned char *kstr, int klen, 
// 		pem_password_cb *cb, void *u);

// EVP_PKEY *OPENSSL_HSM_KEYPAIR_dup(EVP_PKEY *kVal);

END_C_DECLS

#endif /* _LIBPKI_CRYPTO_HSM_OPENSSL_ADMIN_H */

