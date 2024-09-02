/* PKI_X509_OCSP_RESP I/O management */

#ifndef _LIBPKI_X509_OCSP_RESP_IO_H
#define _LIBPKI_X509_OCSP_RESP_IO_H

#define PKI_X509_OCSP_RESP_BEGIN_ARMOUR	"-----BEGIN OCSP RESPONSE-----"
#define PKI_X509_OCSP_RESP_END_ARMOUR	"-----END OCSP RESPONSE-----"

/* ------------------- OCSP_REQ get Operations --------------------------- */
PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get ( char *url_s, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get_mem ( PKI_MEM *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred );

PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get ( char *url_s, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get_url ( URL *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get_mem ( PKI_MEM *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred );

/* ------------------- OCSP_REQ put Operations --------------------------- */
int PKI_X509_OCSP_RESP_put (PKI_X509_OCSP_RESP *r, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);
int PKI_X509_OCSP_RESP_put_url(PKI_X509_OCSP_RESP *r, PKI_DATA_FORMAT format,
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm);
PKI_MEM *PKI_X509_OCSP_RESP_put_mem ( PKI_X509_OCSP_RESP *r, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem,
				PKI_CRED *cred, HSM *hsm );

int PKI_X509_OCSP_RESP_STACK_put ( PKI_X509_OCSP_RESP_STACK *sk, 
			PKI_DATA_FORMAT format, char *url_s, char *mime,
				PKI_CRED *cred, HSM *hsm);
int PKI_X509_OCSP_RESP_STACK_put_url (PKI_X509_OCSP_RESP_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
				PKI_CRED *cred, HSM *hsm );
PKI_MEM *PKI_X509_OCSP_RESP_STACK_put_mem ( PKI_X509_OCSP_RESP_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem,
				PKI_CRED *cred, HSM *hsm );

#endif

