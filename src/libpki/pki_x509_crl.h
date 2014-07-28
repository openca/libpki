/* PKI_X509_CRL object management */

#ifndef _LIBPKI_PKI_X509_CRL_H
#define _LIBPKI_PKI_X509_CRL_H

/* PKI_X509_CRL_ENTRY */
PKI_X509_CRL_ENTRY * PKI_X509_CRL_ENTRY_new ( PKI_X509_CERT *cert,
		PKI_X509_CRL_REASON reason, PKI_TIME *revDate, 
			PKI_X509_PROFILE *profile);
PKI_X509_CRL_ENTRY * PKI_X509_CRL_ENTRY_new_serial ( char *serial, 
		PKI_X509_CRL_REASON reason, PKI_TIME *revDate, 
			PKI_X509_PROFILE *profile );
int PKI_X509_CRL_ENTRY_free ( PKI_X509_CRL_ENTRY *entry );

/* PKI CRL lookup functions */
PKI_X509_CRL_ENTRY * PKI_X509_CRL_lookup( PKI_X509_CRL *x, PKI_INTEGER *s );
PKI_X509_CRL_ENTRY * PKI_X509_CRL_lookup_serial(PKI_X509_CRL *x, char *serial);
PKI_X509_CRL_ENTRY * PKI_X509_CRL_lookup_cert(PKI_X509_CRL *x, 
							PKI_X509_CERT *cert );
PKI_X509_CRL_ENTRY * PKI_X509_CRL_lookup_long(PKI_X509_CRL *x, long long s );

/* PKI CRL Reason Codes */
int PKI_X509_CRL_REASON_CODE_num ( void );
int PKI_X509_CRL_REASON_CODE_get ( const char * st );
const char *PKI_X509_CRL_REASON_CODE_get_parsed ( int reason );
const char *PKI_X509_CRL_REASON_CODE_get_descr ( int reason );

/* PKI CRL */
PKI_X509_CRL *PKI_X509_CRL_new_null ( void );
void PKI_X509_CRL_free_void( void *x );

PKI_X509_CRL *PKI_X509_CRL_new ( PKI_X509_KEYPAIR *pkey, PKI_X509_CERT *cert,
	char * crlNum_s, unsigned long validity, PKI_X509_CRL_ENTRY_STACK *sk,
                        PKI_X509_PROFILE *profile, PKI_CONFIG *oids, HSM *hsm);

int PKI_X509_CRL_free ( PKI_X509_CRL * x );
int PKI_X509_CRL_add_extension(PKI_X509_CRL *x, PKI_X509_EXTENSION *ext);

void * PKI_X509_CRL_get_data ( PKI_X509_CRL *x, PKI_X509_DATA type );
char * PKI_X509_CRL_get_parsed( PKI_X509_CRL *x, PKI_X509_DATA type );

#endif
