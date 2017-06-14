/* PKI_TOKEN write/load object management */


#ifndef _LIBPKI_X509_PKCS12_TOKEN_H
#define _LIBPKI_X509_PKCS12_TOKEN_H

PKI_X509_PKCS12 *PKI_X509_PKCS12_new_null( void );

void PKI_X509_PKCS12_free ( PKI_X509_PKCS12*p12 );
void PKI_X509_PKCS12_free_void ( void *p12 );

/* Retrieve data from a P12 */
int PKI_X509_PKCS12_verify_cred(const PKI_X509_PKCS12 * const p12,
				const PKI_CRED * const cred );

PKI_X509_KEYPAIR *PKI_X509_PKCS12_get_keypair(
				const PKI_X509_PKCS12 * const p12,
	       			const PKI_CRED * const cred );

PKI_X509_CERT *PKI_X509_PKCS12_get_cert(
				const PKI_X509_PKCS12 * const p12,
				const PKI_CRED *cred );

PKI_X509_CERT *PKI_X509_PKCS12_get_cacert(
				const PKI_X509_PKCS12 * const p12,
				const PKI_CRED *cred);

PKI_X509_CERT_STACK *PKI_X509_PKCS12_get_otherCerts(
				const PKI_X509_PKCS12 * const p12, 
				const PKI_CRED * const cred);

/* Write a token to a URL */
int PKI_X509_PKCS12_TOKEN_export(const PKI_TOKEN * const tk,
				 const URL * const url,
				 int format,
				 HSM *hsm );

/* PKCS12 generation tools */
PKI_X509_PKCS12* PKI_X509_PKCS12_new(
				const PKI_X509_PKCS12_DATA * const p12_data,
				const PKI_CRED * const cred );

PKI_X509_PKCS12_DATA *PKI_X509_PKCS12_DATA_new ( void );

void PKI_X509_PKCS12_DATA_free ( PKI_X509_PKCS12_DATA *p12_data );

int PKI_X509_PKCS12_DATA_add_keypair(
				PKI_X509_PKCS12_DATA *data,
				const PKI_X509_KEYPAIR * const keypair, 
				const PKI_CRED * const cred );

int PKI_X509_PKCS12_DATA_add_certs(
				PKI_X509_PKCS12_DATA *data,
				const PKI_X509_CERT * const cert,
				const PKI_X509_CERT * const cacert,
				const PKI_X509_CERT_STACK * const trusted, 
				const PKI_CRED * const cred );

int PKI_X509_PKCS12_DATA_add_other_certs(
				PKI_X509_PKCS12_DATA *data, 
				const PKI_X509_CERT_STACK * const sk,
				const PKI_CRED * const cred );

/* -------------------------- PKCS12 PEM I/O operations ---------------- */

PKI_X509_PKCS12_VALUE *PEM_read_bio_PKCS12(PKI_IO *bp);
int PEM_write_bio_PKCS12(PKI_IO *bp, const PKI_X509_PKCS12_VALUE *o );

#endif
