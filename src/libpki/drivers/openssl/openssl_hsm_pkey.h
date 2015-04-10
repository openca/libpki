/* ENGINE Object Management Functions */

#ifndef _LIBPKI_HEADERS_OPENSSL_PKEY_H
#define _LIBPKI_HEADERS_OPENSSL_PKEY_H


/* ------------------- Keypair Functions --------------------- */

PKI_X509_KEYPAIR *HSM_OPENSSL_X509_KEYPAIR_new( PKI_KEYPARAMS *pk, 
		URL *url, PKI_CRED *cred, HSM *hsm );
void HSM_OPENSSL_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey );

int OPENSSL_HSM_write_bio_PrivateKey (BIO *bp, EVP_PKEY *x, 
		const EVP_CIPHER *enc, unsigned char *kstr, int klen, 
		pem_password_cb *cb, void *u);

EVP_PKEY *OPENSSL_HSM_KEYPAIR_dup(EVP_PKEY *kVal);

#endif

