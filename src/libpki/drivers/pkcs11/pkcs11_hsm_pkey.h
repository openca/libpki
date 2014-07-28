/* PKCS11 Object Management Functions */

#ifndef _LIBPKI_HEADERS_PKCS11_PKEY_H
#define _LIBPKI_HEADERS_PKCS11_PKEY_H

/* ------------------------ Key Management Functions --------------------- */
PKI_X509_KEYPAIR *HSM_PKCS11_KEYPAIR_new( PKI_KEYPARAMS *kp,
				URL *url, PKI_CRED *cred, HSM *driver );

void HSM_PKCS11_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey );

/* ------------------------------ RSA Callback Methods ------------------- */

RSA_METHOD *HSM_PKCS11_get_rsa_method ( void );

int HSM_PKCS11_rsa_sign ( int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa );
#endif

