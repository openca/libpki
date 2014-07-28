/* libpki/drivers/openssl/openssl_hsm.h */

#ifndef _LIBPKI_HSM_KMF_H
#define _LIBPKI_HSM_KMF_H

HSM * HSM_KMF_new( void );
int HSM_KMF_free ( HSM *hsm, PKI_CONFIG *conf );
int HSM_KMF_init ( HSM *hsm, PKI_STACK *pre_cmds, 
					PKI_STACK *post_cmds );

int HSM_KMF_CERT_sign ( PKI_X509_CERT *x, PKI_KEYPAIR *key, 
					PKI_DIGEST_ALG *digest, HSM *hsm );

int HSM_KMF_REQ_sign ( PKI_X509_REQ *x, PKI_KEYPAIR *key, 
					PKI_DIGEST_ALG *digest, HSM *hsm );

#endif
