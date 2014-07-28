/* openssl/pki_pkey.c */

#include <libpki/pki.h>

/* ---------------- OpenSSL HSM Keypair get/put --------------------------- */

PKI_STACK * HSM_OPENSSL_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
						PKI_CRED *cred, void *hsm ) {

	PKI_log_debug("HSM_OPENSSL_OBJSK_get_url()::Deprecated");

	return NULL;
}

PKI_X509_KEYPAIR_STACK * HSM_OPENSSL_X509_KEYPAIR_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm) {

	PKI_log_debug("HSM_OPENSSL_X509_KEYPAIR_get_url()::Deprecated");

	return NULL;
}

