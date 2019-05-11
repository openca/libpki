/* PKI_X509_CRL I/O management */

#ifndef _LIBPKI_X509_CRL_IO_H
#define _LIBPKI_X509_CRL_IO_H

PKI_X509_CRL *PKI_X509_CRL_get ( char *url_s, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm );
PKI_X509_CRL *PKI_X509_CRL_get_url ( URL *url, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm );
PKI_X509_CRL *PKI_X509_CRL_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm );

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get ( char *url_s, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_url ( URL *url,
					 	PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_mem( PKI_MEM *mem,
						PKI_DATA_FORMAT format, PKI_CRED *cred );

int PKI_X509_CRL_put ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format, char *url_s,
						PKI_CRED *cred, HSM *hsm );
int PKI_X509_CRL_put_url ( PKI_X509_CRL *crl, PKI_DATA_FORMAT, URL *url_s,
						PKI_CRED *cred, HSM *hsm );

PKI_MEM *PKI_X509_CRL_put_mem ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format,
						PKI_MEM **mem, PKI_CRED *cred, HSM *hsm );

int PKI_X509_CRL_STACK_put (PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format, 
						char *url_s, PKI_CRED *cred, HSM *hsm );
int PKI_X509_CRL_STACK_put_url (PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format, 
						URL *pki_mem, PKI_CRED *cred, HSM *hsm );

PKI_MEM *PKI_X509_CRL_STACK_put_mem (PKI_X509_CRL_STACK *sk, 
						PKI_DATA_FORMAT format, PKI_MEM **pki_mem,
						PKI_CRED *cred, HSM *hsm );

#endif
