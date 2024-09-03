/* KDF utility */

#include <libpki/pki.h>

int PKI_KDF_derive(const EVP_MD   * md,
				   unsigned char  * label,
				   size_t           labelen, 
				   unsigned char  * key, 
				   size_t           keylen, 
				   unsigned char  * data, 
				   size_t           datalen, 
				   unsigned char ** out, 
				   size_t         * outlen) {

	EVP_KDF_CTX * CTX = NULL;
	OSSL_PARAM params[7], *p = params;

	// Missing code
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	
	return 0;
}