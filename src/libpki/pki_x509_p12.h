/* PKI_TOKEN write/load object management */


#ifndef _LIBPKI_X509_PKCS12_TOKEN_H
#define _LIBPKI_X509_PKCS12_TOKEN_H

PKI_X509_PKCS12 *PKI_X509_PKCS12_new_null( void );

void PKI_X509_PKCS12_free ( PKI_X509_PKCS12*p12 );
void PKI_X509_PKCS12_free_void ( void *p12 );

/* Retrieve data from a P12 */
int PKI_X509_PKCS12_verify_cred ( PKI_X509_PKCS12 *p12, PKI_CRED *cred );
PKI_X509_KEYPAIR *PKI_X509_PKCS12_get_keypair (PKI_X509_PKCS12*p12, PKI_CRED *cred );
PKI_X509_CERT *PKI_X509_PKCS12_get_cert ( PKI_X509_PKCS12*p12, PKI_CRED *cred );
PKI_X509_CERT *PKI_X509_PKCS12_get_cacert (PKI_X509_PKCS12*p12, PKI_CRED *cred);
PKI_X509_CERT_STACK *PKI_X509_PKCS12_get_otherCerts ( PKI_X509_PKCS12*p12, 
							PKI_CRED *cred);

/* Write a token to a URL */
int PKI_X509_PKCS12_TOKEN_export ( PKI_TOKEN *tk, URL *url, int format, HSM *hsm );

/* PKCS12 generation tools */
PKI_X509_PKCS12* PKI_X509_PKCS12_new ( PKI_X509_PKCS12_DATA *p12_data, PKI_CRED *cred );

PKI_X509_PKCS12_DATA *PKI_X509_PKCS12_DATA_new ( void );
void PKI_X509_PKCS12_DATA_free ( PKI_X509_PKCS12_DATA *p12_data );
int PKI_X509_PKCS12_DATA_add_keypair ( PKI_X509_PKCS12_DATA *data, PKI_X509_KEYPAIR *keypair, 
							PKI_CRED *cred );
int PKI_X509_PKCS12_DATA_add_certs (PKI_X509_PKCS12_DATA *data, PKI_X509_CERT *cert,
		PKI_X509_CERT *cacert, PKI_X509_CERT_STACK *trusted, 
			PKI_CRED *cred );
int PKI_X509_PKCS12_DATA_add_other_certs ( PKI_X509_PKCS12_DATA *data, 
				PKI_X509_CERT_STACK *sk, PKI_CRED *cred );

/* -------------------------- PKCS12 PEM I/O operations ---------------- */

PKI_X509_PKCS12_VALUE *PEM_read_bio_PKCS12( PKI_IO *bp );
int PEM_write_bio_PKCS12( PKI_IO *bp, PKI_X509_PKCS12_VALUE *o );

#endif
