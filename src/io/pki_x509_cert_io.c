/* PKI_X509 I/O management */

#include <libpki/pki.h>

/*! \brief Retrieve a certificate from a URL
 *
 * Downloads a certificate from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509_CERT in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CERT_STACK_get() function
 * to retrieve a PKI_X509_CERT_STACK * object.
 *
 */

PKI_X509_CERT *PKI_X509_CERT_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_CERT, format, cred, hsm );
}

/*! \brief Retrieve a certificate from a URL pointer.
 *
 * Downloads a certificate from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509_CERT in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CERT_STACK_get_url() function
 * to retrieve a PKI_X509_CERT_STACK * object.
 *
 */

PKI_X509_CERT *PKI_X509_CERT_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_CERT, format, cred, hsm );

}

PKI_X509_CERT *PKI_X509_CERT_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format,
					PKI_CRED *cred ) {

	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_CERT, format, cred, NULL );

}

/*! \brief Retrieve a stack of certificates from a URL (char *).
 *
 * Downloads a stack of certificates from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_CERT_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CERT_get_url() function instead.
 *
 */

PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get ( char *url_s, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_CERT, format, cred, hsm );
}

/*! \brief Retrieve a stack of certificates from a URL (URL *) pointer.
 *
 * Downloads a stack of certificates from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_CERT_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CERT_get_url() function instead.
 *
 */

PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_CERT, format, cred, hsm);
}

PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_mem(PKI_MEM *mem, 
					PKI_DATA_FORMAT format, PKI_CRED *cred) {

	return PKI_X509_STACK_get_mem (mem, PKI_DATATYPE_X509_CERT, format, cred, NULL);
}

/* --------------------------- X509_CERT put (write) ----------------------- */

int PKI_X509_CERT_put ( PKI_X509_CERT *x, PKI_DATA_FORMAT format,
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put ( x, format, url_s, mime, cred, hsm );
}

int PKI_X509_CERT_put_url ( PKI_X509_CERT *x, PKI_DATA_FORMAT format,
		URL *url, char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put_url (x, format, url, mime, cred, hsm );
}

PKI_MEM *PKI_X509_CERT_put_mem ( PKI_X509_CERT *x, PKI_DATA_FORMAT format,
		PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put_mem ( x, format, pki_mem, cred );
}

int PKI_X509_CERT_STACK_put (PKI_X509_CERT_STACK *sk, PKI_DATA_FORMAT format, 
		char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );
}

int PKI_X509_CERT_STACK_put_url (PKI_X509_CERT_STACK *sk,
			PKI_DATA_FORMAT format, URL *url, char *mime,
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );
}

/* -------------------------- X509_CERT mem Operations -------------------- */

PKI_MEM *PKI_X509_CERT_STACK_put_mem ( PKI_X509_CERT_STACK *sk,
		PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}

