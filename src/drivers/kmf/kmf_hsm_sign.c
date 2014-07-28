/* drivers/kmf/kmf_hsm_sign.c */

#include <libpki/pki.h>

int HSM_KMF_CERT_sign ( PKI_X509_CERT *x, PKI_KEYPAIR *key, 
					PKI_DIGEST_ALG *digest, HSM *hsm ) {

	int ret = PKI_ERR;

	if( (!x) || (!key) || (!digest )) return (PKI_ERR);

	/*
	ERR_clear_error();
	ret = X509_sign( (X509 *) x, (EVP_PKEY *) key, (EVP_MD *) digest );
	if( ret == 0 ) {
		fprintf(stdout, "DEBUG::error signing cert!");
		ERR_print_errors_fp(stdout);
	}
	*/

	return ret;
}

int HSM_KMF_REQ_sign ( PKI_X509_REQ *x, PKI_KEYPAIR *key, 
					PKI_DIGEST_ALG *digest, HSM *hsm ) {

	int ret = PKI_ERR;

	if( (!x) || (!key) || (!digest )) return (PKI_ERR);

	/*
	ERR_clear_error();
	ret = X509_REQ_sign( (X509_REQ *) x, (EVP_PKEY *) key, (EVP_MD *) digest );
	if( ret == 0 ) {
		fprintf(stdout, "DEBUG::error signing request!");
		ERR_print_errors_fp(stdout);
	}
	*/

	return ret;
}

int HSM_KMF_sign ( void *x, PKI_KEYPAIR *key, PKI_DIGEST_ALG *digest,
								HSM *hsm ) {
	return (PKI_ERR);
}

