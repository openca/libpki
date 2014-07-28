/* libpki/drivers/kmf/kmf_hsm_sign.h */

#ifndef _LIBPKI_KMF_HSM_SIGN_H
#define _LIBPKI_KMF_HSM_SIGN_H

int HSM_KMF_CERT_sign( PKI_X509_CERT *x, PKI_KEYPAIR *key,
					PKI_DIGEST_ALG *digest, HSM *hsm );
int HSM_KMF_REQ_sign ( PKI_X509_REQ *x, PKI_KEYPAIR *key,
					PKI_DIGEST_ALG *digest, HSM *hsm );
int HSM_KMF_sing ( void *x, PKI_KEYPAIR *key, PKI_DIGEST_ALG *digest, 
					HSM *hsm);

#endif
