/* HSM Object Management Functions */

#include <libpki/pki.h>

extern HSM_CALLBACKS openssl_hsm_callbacks;
extern HSM openssl_hsm;

/* ------------------- Keypair Gen/Free -------------------------------- */

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new( PKI_KEYPARAMS *params, 
			char *label, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR *ret = NULL;
	URL *url = NULL;

	if( hsm && !url && (hsm->type == HSM_TYPE_PKCS11) ) {
		PKI_log_debug("PKI_X509_KEYPAIR_new()::Label is required when "
			"using HSM!");
		return ( NULL );
	}

	if ( label ) {
		if(( url = URL_new(label)) == NULL ) {
			PKI_ERROR(PKI_ERR_URI_PARSE, label);
			return ( NULL );
		}
	};

	ret = HSM_X509_KEYPAIR_new_url ( params, url, cred, hsm );
	
	if( url ) URL_free( url );

	return ( ret );
}

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new_url( PKI_KEYPARAMS *params,
			URL *url, PKI_CRED *cred, HSM *hsm_in ) {

	PKI_X509_KEYPAIR *ret = NULL;
	HSM *hsm = NULL;

	if ( !params ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	};

	if( hsm_in ) {
		hsm = hsm_in;
	} else {
		hsm = (HSM *) HSM_get_default();
		// PKI_log_debug("Getting Default HSM (%p/%p)", hsm, &openssl_hsm );
		/*
		PKI_log_debug("%s:%d::DEBUG => Getting Default HSM (%p/%p)",
				__FILE__, __LINE__, hsm, &openssl_hsm );
		PKI_log_debug("%s:%d::DEBUG => Default HSM (CALLBK %p/%p)",
			hsm->callbacks, &openssl_hsm_callbacks );
		hsm->callbacks = &openssl_hsm_callbacks;
		PKI_log_debug("%s:%d::DEBUG (CB keypair_new_url=>%p)", 
			__FILE__, __LINE__ , hsm->callbacks->keypair_new_url );
		*/
	}
	
	if( hsm && hsm->callbacks && hsm->callbacks->keypair_new_url ) {
		ret = hsm->callbacks->keypair_new_url(params,url,cred,hsm);
	} else {
		PKI_log_err("HSM does not provide key generation");
		// ret = HSM_OPENSSL_KEYPAIR_new( type, bits, url, cred, NULL );
	}

	return ( ret );
}


PKI_MEM *HSM_X509_KEYPAIR_wrap ( PKI_X509_KEYPAIR *key, PKI_CRED *cred) {

	const HSM *hsm = NULL;

	if ( !key || !key->value ) return NULL;

	if ( key->hsm ) {
		hsm = key->hsm;
	} else {
		hsm = HSM_get_default();
	}

	if ( hsm && hsm->callbacks && hsm->callbacks->key_wrap ) {
		return hsm->callbacks->key_wrap ( key, cred );
	}

	return NULL;

/*
	int i = 0;

	PKI_X509 *obj = NULL;
	PKI_MEM_STACK *ret_sk = NULL;
	PKI_MEM *mem = NULL;

	if ( !sk ) return NULL;

	if ((ret_sk = PKI_STACK_MEM_new()) == NULL ) {
		return NULL;
	}

	for ( i = 0; i < PKI_STACK_X509_KEYPAIR_elements ( sk ); i++ ) {
		obj = PKI_STACK_X509_KEYPAIR_get_num ( sk, i );

		if (!obj || !obj->value ) continue;

		if ( obj->hsm ) {
			if( obj->hsm && obj->hsm->callbacks && 
					obj->hsm->callbacks->key_wrap ) { 
				mem = obj->hsm->callbacks->key_wrap ( obj, 
									cred);
				if ( mem == NULL ) break;

				PKI_STACK_MEM_push ( ret_sk, mem );
			}
		}
	}

	return ret_sk;
*/
}

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_unwrap ( PKI_MEM *mem,
				URL *url, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR *ret = NULL;

	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	/* Now Put the stack of objects in the HSM */
	if( hsm && hsm->callbacks && hsm->callbacks->key_unwrap ) { 
		ret = hsm->callbacks->key_unwrap ( mem, url, cred, hsm );
	};

	/* Return value */
	return ret;
}
