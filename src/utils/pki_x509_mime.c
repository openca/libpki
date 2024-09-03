/* PKI_X509 mime types management */

#include <libpki/pki.h>

const char *PKI_X509_get_mimetype ( PKI_DATATYPE type ) {

	const char *ret = NULL;

	switch ( type ) {
		case PKI_DATATYPE_X509_CERT:
			ret = PKI_MIMETYPE_X509_CERT;
			break;
		case PKI_DATATYPE_X509_CRL:
			ret = PKI_MIMETYPE_X509_CRL;
			break;
		case PKI_DATATYPE_X509_REQ:
			ret = PKI_MIMETYPE_X509_REQ;
			break;
		default:
			ret = PKI_MIMETYPE_UNKNOWN;
			break;
	}

	return ret;
}
