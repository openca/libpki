/* pki_x509_name.h */

#ifndef _LIBPKI_X509_NAME_H
#define _LIBPKI_X509_NAME_H

PKI_X509_NAME *PKI_X509_NAME_new_null ( void );
PKI_X509_NAME *PKI_X509_NAME_new ( char *name );
PKI_X509_NAME *PKI_X509_NAME_add ( PKI_X509_NAME *name, const char *entry );
PKI_X509_NAME *PKI_X509_NAME_dup ( PKI_X509_NAME *name );

int PKI_X509_NAME_cmp ( PKI_X509_NAME *a, PKI_X509_NAME *b );

int PKI_X509_NAME_free( PKI_X509_NAME *name );

char *PKI_X509_NAME_get_parsed ( PKI_X509_NAME *name );

PKI_X509_NAME_RDN **PKI_X509_NAME_get_list ( PKI_X509_NAME *name,
				PKI_X509_NAME_TYPE filter );

void PKI_X509_NAME_list_free ( PKI_X509_NAME_RDN **list );

PKI_DIGEST * PKI_X509_NAME_get_digest ( PKI_X509_NAME *name, PKI_DIGEST_ALG *alg );

char *PKI_X509_NAME_RDN_value ( PKI_X509_NAME_RDN *rdn );
PKI_X509_NAME_TYPE PKI_X509_NAME_RDN_type_id ( PKI_X509_NAME_RDN *rdn );
const char *PKI_X509_NAME_RDN_type_text ( PKI_X509_NAME_RDN *rdn );
const char *PKI_X509_NAME_RDN_type_descr ( PKI_X509_NAME_RDN *rdn );

#endif
