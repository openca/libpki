/* PKI_X509 I/O management */

#ifndef _LIBPKI_X509_CERT_IO_H
#define _LIBPKI_X509_CERT_IO_H

/* --------------------- X509 CERT get (load) functions ------------------- */
PKI_X509_CERT *PKI_X509_CERT_get ( char *url_s, PKI_CRED *cred, HSM *hsm );
PKI_X509_CERT *PKI_X509_CERT_get_url ( URL *url, PKI_CRED *cred, HSM *hsm );
PKI_X509_CERT *PKI_X509_CERT_get_mem ( PKI_MEM *mem, PKI_CRED *cred );

PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get ( char *url_s, PKI_CRED *cred,
								HSM *hsm );
PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_url ( URL *url , PKI_CRED *cred,
								HSM *hsm);
PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_mem (PKI_MEM *mem, PKI_CRED *cred);

/* -------------------- X509 CERT put (write) functions ------------------- */
int PKI_X509_CERT_put ( PKI_X509_CERT *x, PKI_DATA_FORMAT format, 
			char *url_string, char *mime, PKI_CRED *cred, HSM *hsm);
int PKI_X509_CERT_put_url ( PKI_X509_CERT *x, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm );
PKI_MEM *PKI_X509_CERT_put_mem ( PKI_X509_CERT *x, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

int PKI_X509_CERT_STACK_put (PKI_X509_CERT_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_CERT_STACK_put_url (PKI_X509_CERT_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
					PKI_CRED *cred, HSM *hsm );
PKI_MEM *PKI_X509_CERT_STACK_put_mem ( PKI_X509_CERT_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **mem,
					PKI_CRED *cred, HSM *hsm );

#endif
