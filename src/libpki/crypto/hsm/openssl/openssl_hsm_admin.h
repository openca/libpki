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

int HSM_OPENSSL_new_driver(void **hsm_driver);

int HSM_OPENSSL_free_driver(void *hsm_driver);

int HSM_OPENSSL_init(void * hsm_driver, const PKI_CONFIG * conf);

int HSM_OPENSSL_set_fips_mode(const void * hsm_driver, int mode);

int HSM_OPENSSL_is_fips_mode(const void * hsm_driver);


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

