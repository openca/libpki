/* PKCS11 Object Management Functions */

#ifndef _LIBPKI_HEADERS_PKCS11_PKEY_H
#define _LIBPKI_HEADERS_PKCS11_PKEY_H

#include <openssl/ecdsa.h>

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	typedef ECDSA_METHOD EC_KEY_METHOD;
#endif

/* ------------------------ Key Management Functions --------------------- */
PKI_X509_KEYPAIR *HSM_PKCS11_KEYPAIR_new( PKI_KEYPARAMS *kp,
				URL *url, PKI_CRED *cred, HSM *driver );

void HSM_PKCS11_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey );

/* ------------------------------ RSA Callback Methods ------------------- */

const RSA_METHOD * HSM_PKCS11_get_rsa_method ( void );

const EC_KEY_METHOD * HSM_PKCS11_get_ecdsa_method ( void );

int HSM_PKCS11_rsa_sign ( int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa );

int HSM_PKCS11_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r);

int HSM_PKCS11_ecdsa_sign ( int type, const unsigned char *dgst, int dlen,
	unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r,
    EC_KEY *eckey );

#endif

