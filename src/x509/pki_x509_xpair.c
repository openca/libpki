/* Cross Certificate Pair - src/openssl/pki_x509_xcert.c */

#include <libpki/pki.h>

void PKI_X509_XPAIR_free_void( void *x ) {
	PKI_X509_XPAIR_free((PKI_X509_XPAIR *)x);
}

void PKI_X509_XPAIR_free ( PKI_X509_XPAIR *x ) {
	if (!x) return;

	PKI_X509_free ( x );

	return;
}


/*! \brief Create an empty cross certificate data structure */
PKI_XPAIR *PKI_XPAIR_new_null ( void ) {
	PKI_XPAIR *ret = NULL;

	if((ret = PKI_XPAIR_new()) == NULL ) {
		return ( NULL );
	}

	ret->forward = NULL;
	ret->reverse = NULL;

	return ( ret );
	
}

PKI_X509_XPAIR *PKI_X509_XPAIR_new_null ( void ) {
	PKI_X509_XPAIR *ret = NULL;

	if((ret = PKI_X509_new ( PKI_DATATYPE_X509_XPAIR, NULL )) == NULL ) {
		return NULL;
	}

	if((ret->value = PKI_XPAIR_new()) == NULL ) {
		PKI_X509_free ( ret );
		return NULL;
	}

	return ret;
}


/*! \brief Creates a X-Certificate data structure and set the appropriate
     values for the forward and reverse certificate */

PKI_X509_XPAIR *PKI_X509_XPAIR_new_certs ( PKI_X509_CERT *forward,
						PKI_X509_CERT *reverse ) {

	PKI_X509_XPAIR *ret = NULL;

	if( forward == NULL ) {
		return ( NULL );
	}

	if((ret = PKI_X509_XPAIR_new_null()) == NULL ) {
		return ( NULL );
	}

	if((PKI_X509_XPAIR_set_forward ( ret, forward )) == PKI_ERR ) {
		goto err;
	}

	if((PKI_X509_XPAIR_set_reverse ( ret, reverse )) == PKI_ERR ) {
		goto err;
	}

	return ret;

err:

	if( ret ) {
		PKI_X509_XPAIR_free ( ret );
	}

	return ( NULL );

}

/*! \brief Sets the forward certificate in a Cross Cert data structure */
int PKI_X509_XPAIR_set_forward ( PKI_X509_XPAIR *xp, PKI_X509_CERT *cert ) {

	PKI_XPAIR *xp_val = NULL;
	const PKI_X509_CALLBACKS *cb = NULL;

	if( !xp || !xp->value || !cert || !cert->value ) return ( PKI_ERR );

	xp_val = xp->value;

	cb = PKI_X509_CALLBACKS_get ( PKI_DATATYPE_X509_CERT, NULL );

	if ( xp_val->forward && cb && cb->free ) {
		cb->free ( xp_val->forward );
		// PKI_X509_CERT_free ( xp->forward );
		xp_val->forward = NULL;
	}

	xp_val->forward = PKI_X509_dup_value ( cert );

	return ( PKI_OK );
}

/*! \brief Sets the reverse certificate in a Cross Cert data structure */
int PKI_X509_XPAIR_set_reverse ( PKI_X509_XPAIR *xp, PKI_X509_CERT *cert ) {

	PKI_XPAIR *xp_val = NULL;
	const PKI_X509_CALLBACKS *cb = NULL;

	if( !xp || !xp->value || !cert || !cert->value ) return ( PKI_ERR );

	cb = PKI_X509_CALLBACKS_get ( PKI_DATATYPE_X509_CERT, NULL );

	xp_val = xp->value;
	if ( xp_val->reverse && cb && cb->free ) {
		cb->free ( xp_val->reverse );
		xp_val->reverse = NULL;
	}

	xp_val->reverse = PKI_X509_dup_value ( cert );

	return ( PKI_OK );
}

/*! \brief Returns the forward cert pointer present in a cross cert pair */
PKI_X509_CERT * PKI_X509_XPAIR_get_forward ( PKI_X509_XPAIR *xp ) {

	PKI_XPAIR *xp_val = NULL;
	PKI_X509_CERT *ret = NULL;

	if( !xp || !xp->value ) {
		return NULL;
	}

	xp_val = xp->value;
	if( !xp_val->forward ) {
		return ( NULL );
	}

	if((ret = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
				xp_val->forward, NULL )) == NULL ) {
		// ret = PKI_X509_dup ( xp_val->forward );
		// ret->value = xp_val->forward;
		PKI_log_debug( "Can not duplicate forward cert!");
		return NULL;
	}

	return ret;
}

/*! \brief Returns the reverse cert pointer present in a cross cert pair */
PKI_X509_CERT * PKI_X509_XPAIR_get_reverse ( PKI_X509_XPAIR *xp ) {

	PKI_XPAIR *xp_val = NULL;
	PKI_X509_CERT *ret = NULL;

	if( !xp || !xp->value ) return ( NULL );

	xp_val = xp->value;
	if( !xp_val->reverse ) return ( NULL );

	if((ret = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
			xp_val->reverse, NULL )) != NULL ) {
		PKI_log_debug( "Can not duplicate reverse cert!");
	}

	return ret;
}

