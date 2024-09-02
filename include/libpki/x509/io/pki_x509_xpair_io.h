/* PKI_X509_XPAIR I/O management */

#ifndef _LIBPKI_X509_XPAIR_H
# include <libpki/pki_x509_xpair.h>
#endif

#ifndef _LIBPKI_X509_XPAIR_IO_H
#define _LIBPKI_X509_XPAIR_IO_H

// #define PKI_X509_XPAIR_BEGIN_ARMOUR "-----BEGIN CROSS CERTIFICATE PAIR-----"
// #define PKI_X509_XPAIR_END_ARMOUR "-----END CROSS CERTIFICATE PAIR-----"
#define PEM_STRING_X509_XPAIR "CROSS CERTIFICATE PAIR"

/* --------------------- X509 CERT get (load) functions ------------------- */
PKI_X509_XPAIR *PKI_X509_XPAIR_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm );
PKI_X509_XPAIR *PKI_X509_XPAIR_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm );
PKI_X509_XPAIR *PKI_X509_XPAIR_get_mem( PKI_MEM *mem, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm);

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get ( char *url_s,
					PKI_DATA_FORMAT format, PKI_CRED *cred,	HSM *hsm );
PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_url ( URL *url,
					PKI_DATA_FORMAT format, PKI_CRED *cred,	HSM *hsm);

/* -------------------- X509 CERT put (write) functions ------------------- */
int PKI_X509_XPAIR_put ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_XPAIR_put_url ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT, URL *url,
			char *mime, PKI_CRED *cred, HSM *hsm );
PKI_MEM *PKI_X509_XPAIR_put_mem ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );
int PKI_X509_XPAIR_STACK_put (PKI_X509_XPAIR_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_string, char *mime, PKI_CRED *cred, HSM *hsm);
int PKI_X509_XPAIR_STACK_put_url (PKI_X509_XPAIR_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
					PKI_CRED *cred, HSM *hsm );

/* ---------------------- X509_XPAIR mem Operations ------------------------ */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_mem(PKI_MEM *mem, 
					PKI_DATA_FORMAT format, PKI_CRED *cred);

PKI_MEM * PKI_X509_XPAIR_STACK_put_mem ( PKI_X509_XPAIR_STACK *sk, 
	PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

int PKI_XPAIR_print( BIO *bio, PKI_XPAIR *xp );


#endif
