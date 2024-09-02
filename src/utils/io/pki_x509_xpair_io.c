/* PKI_X509 I/O management */

#include <libpki/pki.h>


/*! \brief Retrieve a Cross Cert Pair from a URL
 *
 * Downloads a XPAIR from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509_XPAIR in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_XPAIR_STACK_get() function
 * to retrieve a PKI_X509_XPAIR_STACK * object.
 */

PKI_X509_XPAIR *PKI_X509_XPAIR_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_XPAIR, format, cred, hsm );
}

/*! \brief Retrieve a cross certificate pair from a URL pointer.
 *
 * Downloads a XPAIR from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509_XPAIR in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_XPAIR_STACK_get_url() function
 * to retrieve a PKI_X509_XPAIR_STACK * object.
 *
 */

PKI_X509_XPAIR *PKI_X509_XPAIR_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_XPAIR, format, cred, hsm );
}

/*! \brief Retrieve a stack of cross cert pair from a URL (char *).
 *
 * Downloads a stack of certificates from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_XPAIR_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_XPAIR_get_url() function instead.
 *
 */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get ( char *url_s, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_XPAIR, format, cred, hsm);
}

/*! \brief Retrieve a stack of cross cert pair from a URL (URL *) pointer.
 *
 * Downloads a stack of XPAIR from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_XPAIR_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_XPAIR_get_url() function instead.
 *
 */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_url ( URL *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_XPAIR, format, cred, hsm );
}

/* --------------------------- X509_XPAIR put (write) ----------------------- */

int PKI_X509_XPAIR_put ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put ( x, format, url_s, mime, cred, hsm );
}

PKI_MEM *PKI_X509_XPAIR_put_mem ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_mem ( x, format, pki_mem, cred );
}

int PKI_X509_XPAIR_STACK_put (PKI_X509_XPAIR_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );
}


int PKI_X509_XPAIR_STACK_put_url (PKI_X509_XPAIR_STACK *sk, 
				PKI_DATA_FORMAT format, URL *url, 
				char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );
}

/* -------------------------- X509_XPAIR mem Operations -------------------- */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_mem(PKI_MEM *mem, 
							PKI_DATA_FORMAT format, PKI_CRED *cred) { 
	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_XPAIR, 
							format, cred, NULL );
}

PKI_MEM * PKI_X509_XPAIR_STACK_put_mem ( PKI_X509_XPAIR_STACK *sk, 
							PKI_DATA_FORMAT format, PKI_MEM **pki_mem,
							PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}

int PKI_XPAIR_print( BIO *bio, PKI_XPAIR *xp_val ) {

	PKI_X509_CERT *x_tmp = NULL;

	if ( !bio || !xp_val ) return ( PKI_ERR );

	BIO_printf(bio, "\nCross Certificate Pair:\n");

	BIO_printf(bio, "  Forward Certificate:\n" );
	if (( x_tmp = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
					xp_val->forward, NULL )) != NULL ) {

		BIO_printf(bio, "    Serial=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SERIAL ));
		BIO_printf(bio, "    Subject=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SUBJECT ));
		BIO_printf(bio, "    Issuer=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_ISSUER ));
		x_tmp->cb->to_pem ( (PKI_IO *) bio, (void *) xp_val->forward );
		PKI_X509_free ( x_tmp );
	} else {
		BIO_printf(bio, "     No forward certificate present.\n\n");
	}

	BIO_printf(bio, "  Reverse Certificate:\n" );
	if (( x_tmp = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT,
					xp_val->reverse, NULL )) != NULL ) {
		BIO_printf(bio, "    Serial=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SERIAL ));
		BIO_printf(bio, "    Subject=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SUBJECT ));
		BIO_printf(bio, "    Issuer=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_ISSUER ));
		x_tmp->cb->to_pem ( (PKI_IO *) bio, (void *) xp_val->reverse );
		PKI_X509_free ( x_tmp );
	} else {
		BIO_printf(bio, "     No reverse certificate present.\n\n");
	}

	return ( PKI_OK );
}
