/* PKI_X509_PKCS12 I/O management */

#include <libpki/pki.h>

/* --------------------------- General I/O functions --------------------- */

PKI_X509_PKCS12 *PKI_X509_PKCS12_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_PKCS12, format, cred, hsm );
}

PKI_X509_PKCS12 *PKI_X509_PKCS12_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_PKCS12, format, cred, hsm );
}

PKI_X509_PKCS12 *PKI_X509_PKCS12_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format,
					PKI_CRED *cred ) {

	PKI_X509_PKCS12 *tmp_p12 = NULL;

	tmp_p12 = PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_PKCS12, format, cred, NULL);

	if ( PKI_X509_PKCS12_verify_cred ( tmp_p12, cred ) == PKI_ERR ) {
		PKI_log_debug("Wrong Credentials provided!");
		PKI_X509_PKCS12_free ( tmp_p12 );
		return NULL;
	}

	return tmp_p12;
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get (char *url_s, PKI_DATA_FORMAT format, 
						PKI_CRED *cred, HSM *hsm) {
	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_PKCS12, format, cred, hsm);
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url(url, PKI_DATATYPE_X509_PKCS12, format, cred, hsm);
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_mem ( PKI_MEM *mem, 
							PKI_DATA_FORMAT format, PKI_CRED *cred) {

	PKI_X509_PKCS12_STACK *tmp_sk = NULL;
	PKI_X509_PKCS12_STACK *ret_sk = NULL;
	PKI_X509_PKCS12 *tmp_p12 = NULL;

	/* We need to get the internal format first and then perform some
	   additional operations, i.e. verify the creds if present */

	if(( tmp_sk = PKI_X509_STACK_get_mem ( mem, 
			PKI_DATATYPE_X509_PKCS12, format, cred, NULL)) == NULL ) {
		return NULL;
	}
	
	if((ret_sk = PKI_STACK_X509_PKCS12_new()) == NULL ) {
		return NULL;
	}

	while ((tmp_p12 = PKI_STACK_X509_PKCS12_pop ( tmp_sk )) != NULL ) {
		/* Let's add only the ones that we can decrypt */
		if ( PKI_X509_PKCS12_verify_cred ( tmp_p12, cred ) == PKI_OK ) {
			PKI_STACK_X509_PKCS12_push( ret_sk, tmp_p12 );
		} else {
			PKI_X509_PKCS12_free ( tmp_p12 );
		}
	}

	PKI_STACK_X509_PKCS12_free ( ret_sk );

	return ret_sk;
}

/* ---------------------------- PKCS12 put operations ------------------ */

int PKI_X509_PKCS12_put (PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( p12, format, url_s, mime, cred, hsm );
}

int PKI_X509_PKCS12_put_url(PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( p12, format, url, mime, cred, hsm );
}


int PKI_X509_PKCS12_STACK_put ( PKI_X509_PKCS12_STACK *sk, 
		PKI_DATA_FORMAT format, char *url_s, char *mime, 
			PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );
}

int PKI_X509_PKCS12_STACK_put_url (PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime, 
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );
}


PKI_MEM *PKI_X509_PKCS12_STACK_put_mem ( PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}


/*! \brief Puts a PKI_X509_PKCS12 in a PKI_MEM structure */

PKI_MEM *PKI_X509_PKCS12_put_mem ( PKI_X509_PKCS12 *p12, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put_mem ( p12, format, pki_mem, cred );
}
