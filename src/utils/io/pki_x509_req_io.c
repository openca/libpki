/* PKI_X509_REQ I/O management */

#include <libpki/pki.h>

PKI_X509_REQ *PKI_X509_REQ_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_REQ, format, cred, hsm );
}

PKI_X509_REQ *PKI_X509_REQ_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_REQ, format, cred, hsm );
}

PKI_X509_REQ *PKI_X509_REQ_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format,
					PKI_CRED *cred ) {

	return PKI_X509_get_mem (mem, PKI_DATATYPE_X509_REQ, format, cred, NULL );
}

PKI_X509_REQ_STACK *PKI_X509_REQ_STACK_get (char *url_s, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_REQ, format, cred, hsm );
}


PKI_X509_REQ_STACK *PKI_X509_REQ_STACK_get_url ( URL *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_REQ, format, cred, hsm );
}


PKI_X509_REQ_STACK *PKI_X509_REQ_STACK_get_mem ( PKI_MEM *mem,
					PKI_DATA_FORMAT format, PKI_CRED *cred) {

	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_REQ, format, cred, NULL);
}

/* ---------------------------- X509_REQ put operations ------------------ */

int PKI_X509_REQ_put (PKI_X509_REQ *req, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( req, format, url_s, NULL, cred, hsm );
}

int PKI_X509_REQ_put_url(PKI_X509_REQ *req, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( req, format, url, mime, cred, hsm );
}

PKI_MEM *PKI_X509_REQ_put_mem ( PKI_X509_REQ *r, PKI_DATA_FORMAT format,
				PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put_mem ( r, format, pki_mem, cred );
}


int PKI_X509_REQ_STACK_put ( PKI_X509_REQ_STACK *sk, PKI_DATA_FORMAT format, 
					char *url_s, char *mime,
						PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );
}

int PKI_X509_REQ_STACK_put_url (PKI_X509_REQ_STACK *sk, PKI_DATA_FORMAT format, 
					URL *url, char *mime, PKI_CRED *cred, 
								HSM *hsm ) {

	return PKI_X509_STACK_put_url (sk, format, url, mime, cred, hsm );
}

PKI_MEM *PKI_X509_REQ_STACK_put_mem (PKI_X509_REQ_STACK *sk, 
				PKI_DATA_FORMAT format, 
				PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}
