/* PKI_X509 I/O management */

#include <libpki/pki.h>

/*! \brief Retrieve a CRL from a URL
 *
 * Downloads a CRL from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509_CRL in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CRL_STACK_get() function
 * to retrieve a PKI_X509_CERT_STACK * object.
 *
 */

PKI_X509_CRL *PKI_X509_CRL_get ( char *url_s, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_CRL, format, cred, hsm );
}

/*! \brief Retrieve a CRL from a URL pointer.
 *
 * Downloads a CRL from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509_CRL * in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CRL_get_url() function
 * to retrieve a PKI_X509_CRL_STACK * object.
 *
 */

PKI_X509_CRL *PKI_X509_CRL_get_url ( URL *url, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_CRL, format, cred, hsm );
}

PKI_X509_CRL * PKI_X509_CRL_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format, 
						PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_CRL, format, cred, NULL );
}

/*! \brief Retrieve a stack of CRLs from a URL (char *).
 *
 * Downloads a stack of CRLs from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_CRL_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CRL_get_url() function instead.
 *
 */

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get (char *url_s, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_CRL, format, cred, hsm );
}

/*! \brief Retrieve a stack of CRLs from a URL (URL *) pointer.
 *
 * Downloads a stack of CRLs from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_CRL_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CRL_get_url() function instead.
 *
 */

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_url ( URL *url, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_CRL, format, cred, hsm );
}

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_mem( PKI_MEM *mem, PKI_DATA_FORMAT format,
						PKI_CRED *cred ) {

	return PKI_X509_STACK_get_mem (mem, PKI_DATATYPE_X509_CRL, format, cred, NULL );
}

int PKI_X509_CRL_put ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format, char *url_s,
				PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put ( crl, format, url_s, NULL, cred, hsm );
}

int PKI_X509_CRL_put_url ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format,
				URL *url, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_url ( crl, format, url, NULL, cred, hsm );
}

PKI_MEM *PKI_X509_CRL_put_mem ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format,
				PKI_MEM **mem, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_mem ( crl, format, mem, cred );
}

int PKI_X509_CRL_STACK_put ( PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format,
			char *url_s, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_STACK_put ( sk, format, url_s, NULL, cred, hsm );
}

int PKI_X509_CRL_STACK_put_url ( PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format,
			URL *url, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_STACK_put_url ( sk, format, url, NULL, cred, hsm );
}

PKI_MEM *PKI_X509_CRL_STACK_put_mem (PKI_X509_CRL_STACK *sk, 
	PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}
