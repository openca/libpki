/* src/libpki/pki_x509_xpair.h */

#ifndef _LIBPKI_X509_XPAIR_ASN1_H
# include <libpki/pki_x509_xpair_asn1.h>
#endif

#ifndef _LIBPKI_X509_XPAIR_H
#define _LIBPKI_X509_XPAIR_H

DECLARE_ASN1_FUNCTIONS(PKI_XPAIR)

/* New  functions */
PKI_XPAIR *PKI_XPAIR_new_null ( void );

void PKI_XPAIR_free ( PKI_XPAIR *x );

void PKI_X509_XPAIR_free_void ( void *x );
void PKI_X509_XPAIR_free ( PKI_X509_XPAIR *x );

PKI_X509_XPAIR *PKI_X509_XPAIR_new_null ( void );
PKI_X509_XPAIR *PKI_X509_XPAIR_new_certs ( PKI_X509_CERT *forward,
						PKI_X509_CERT *reverse );

/* Set functions */
int PKI_X509_XPAIR_set_forward ( PKI_X509_XPAIR *xp, PKI_X509_CERT *cert );
int PKI_X509_XPAIR_set_reverse ( PKI_X509_XPAIR *xp, PKI_X509_CERT *cert );

/* Get functions */
PKI_X509_CERT *PKI_X509_XPAIR_get_forward ( PKI_X509_XPAIR *xp );
PKI_X509_CERT *PKI_X509_XPAIR_get_reverse ( PKI_X509_XPAIR *xp );

#endif
