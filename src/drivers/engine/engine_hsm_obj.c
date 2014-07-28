/* openssl/pki_pkey.c */

#include <libpki/pki.h>

/* ---------------- OpenSSL HSM Keypair get/put --------------------------- */

/*
PKI_STACK * HSM_ENGINE_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
					PKI_CRED *cred, struct hsm_st *hsm ) {

	void * ret = NULL;

	if( !url ) return ( NULL );

	switch ( type ) {
		case PKI_DATATYPE_X509_KEYPAIR:
			ret = HSM_ENGINE_KEYPAIR_get_url ( url, cred, hsm );
			break;
		default:
			HSM_OPENSSL_OBJSK_get_url ( type, url, cred, hsm );
			ret = NULL;
	}

	return ( ret );
}

*/
/* ------------------------ Internal Retrieve Functions ------------------- */

/*
PKI_X509_KEYPAIR_STACK * HSM_ENGINE_KEYPAIR_get_url ( URL *url, PKI_CRED *cred, 
							HSM *driver ) {
	HSM *hsm = NULL;
	PKI_X509_KEYPAIR_STACK *ret = NULL;
	PKI_X509_KEYPAIR *keypair = NULL;
	PW_CB_DATA cb_data;
	ENGINE *e = NULL;

	if((hsm = (HSM *) driver) == NULL ) {
		PKI_log_debug("ERROR, Memory Allocation", __FILE__, __LINE__);
		return(NULL);
	}

	if( hsm->driver == NULL ) {
		PKI_log_debug("ERROR, No HSM pointer provided (keypair get"
							" in ENGINE HSM)");
		return(NULL);
	}

	e = (ENGINE *) hsm->driver;

	if( cred ) {
		cb_data.password = cred->password;
	} else if ( hsm->cred ) {
		cb_data.password = hsm->cred->password;
	}

	if( url ) {
        	cb_data.prompt_info = url->addr;
	}

	if((ret = PKI_STACK_X509_KEYPAIR_new()) == NULL ) {
		PKI_log_debug("ERROR, can not allocate new memory!");
		return ( NULL );
	}

        if((keypair = (PKI_X509_KEYPAIR *) ENGINE_load_private_key(e, 
				url->addr, NULL, &cb_data)) == NULL ) {
		PKI_log_debug("ERROR, Error loading key (%s) [ENGINE HSM]",
							url->addr );
		if ( ret ) PKI_STACK_X509_KEYPAIR_free ( ret );
		return ( NULL );
	}

	PKI_STACK_X509_KEYPAIR_push ( ret, keypair );

	return ( ret );
}

*/
