/* PKI_X509 I/O management */

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

#ifndef _LIBPKI_PKI_URL_H
# include <libpki/net/url.h>
#endif

#ifndef _LIBPKI_PKI_CRED_H
# include <libpki/pki_cred.h>
#endif

#ifndef _LIBPKI_PKI_X509_IO_H
#define  _LIBPKI_PKI_X509_IO_H

/* ---------------------------- X509 get (read) ----------------------- */

PKI_X509 *PKI_X509_get ( char *url_s, PKI_DATATYPE type, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

void *PKI_get_value ( char *url_s, PKI_DATATYPE type,
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509 *PKI_X509_get_url ( URL *url, PKI_DATATYPE type, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509_STACK *PKI_X509_STACK_get ( char *url_s, PKI_DATATYPE type, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509_STACK *PKI_X509_STACK_get_url ( URL *url, PKI_DATATYPE type,
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

/* --------------------------- X509 put (write) ----------------------- */

int PKI_X509_put ( PKI_X509 *x, PKI_DATA_FORMAT format, char *url_string, 
			const char *mime, PKI_CRED *cred, HSM *hsm );

int PKI_X509_put_value ( void *x, PKI_DATATYPE type, PKI_DATA_FORMAT format,
		char *url_string, const char *mime, PKI_CRED *cred, HSM *hsm );

int PKI_X509_put_url ( PKI_X509 *x, PKI_DATA_FORMAT format, URL *url, 
			const char *mime, PKI_CRED *cred, HSM *hsm );

int PKI_X509_STACK_put (PKI_X509_STACK *sk, PKI_DATA_FORMAT format, 
		char *url_string, const char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_STACK_put_url (PKI_X509_STACK *sk, PKI_DATA_FORMAT format, 
		URL *url, const char *mime, PKI_CRED *cred, HSM *hsm);

#endif

