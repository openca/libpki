/* PKI_X509_PRQP_RESP I/O management */

#include <libpki/pki.h>

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_PRQP_RESP, format, cred, hsm );
}

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_PRQP_RESP, format, cred, hsm );

}

PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get (char *url_s, PKI_DATA_FORMAT format, 
						PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_PRQP_RESP, format, cred, hsm );

}

PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get_url ( URL *url, PKI_DATA_FORMAT format, 
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_PRQP_RESP, format, cred, hsm );

}

/* ---------------------------- RESP put operations ------------------ */

int PKI_X509_PRQP_RESP_put (PKI_X509_PRQP_RESP *resp, PKI_DATA_FORMAT format, char *url_s, 
					char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( resp, format, url_s, mime, cred, hsm );
}

int PKI_X509_PRQP_RESP_put_url(PKI_X509_PRQP_RESP *resp, PKI_DATA_FORMAT format, URL *url, 
					char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( resp, format, url, mime, cred, hsm );

}


int PKI_X509_PRQP_RESP_STACK_put ( PKI_X509_PRQP_RESP_STACK *sk, PKI_DATA_FORMAT format, 
					char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {
	
	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );
}

int PKI_X509_PRQP_RESP_STACK_put_url (PKI_X509_PRQP_RESP_STACK *sk, PKI_DATA_FORMAT format, 
					URL *url, char * mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );
}

/* -------------------------- RESP mem Operations -------------------- */

PKI_X509_PRQP_RESP * PKI_X509_PRQP_RESP_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format, 
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_PRQP_RESP, format, cred, hsm );
}

PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get_mem(PKI_MEM *mem, PKI_DATA_FORMAT format,  
					PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_PRQP_RESP,
						format, cred, hsm );
}

PKI_MEM * PKI_X509_PRQP_RESP_put_mem ( PKI_X509_PRQP_RESP *resp,
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM * hsm ) {

	return PKI_X509_put_mem ( resp, format, pki_mem, cred );
}

PKI_MEM * PKI_X509_PRQP_RESP_STACK_put_mem ( PKI_X509_PRQP_RESP_STACK *sk, PKI_DATA_FORMAT format,
				PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}

