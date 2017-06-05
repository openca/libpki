/* token.h */

#ifndef _LIBPKI_TOKEN_HEADERS_H
#define _LIBPKI_TOKEN_HEADERS_H

#include <libpki/token_st.h>

/* Memory related functions */
PKI_TOKEN *PKI_TOKEN_new_null( void );
PKI_TOKEN *PKI_TOKEN_new( char *confDir, char *name );
PKI_TOKEN *PKI_TOKEN_new_p12 ( char *url, char *config_dir, PKI_CRED *cred );

int PKI_TOKEN_free( PKI_TOKEN *tk );
void PKI_TOKEN_free_void ( void *tk );

/* Token Initialization */
int PKI_TOKEN_set_config_dir ( PKI_TOKEN *tk, char *dir );
char * PKI_TOKEN_get_config_dir ( PKI_TOKEN *tk );
int PKI_TOKEN_login( PKI_TOKEN *tk );
int PKI_TOKEN_init (PKI_TOKEN *tk, char *conf_url, char *name);
PKI_OID *PKI_TOKEN_OID_new ( PKI_TOKEN *tk, char *oid_s );
int PKI_TOKEN_check ( PKI_TOKEN *tk );

/* Configuration options */
PKI_ALGOR *PKI_TOKEN_get_algor( PKI_TOKEN *tk );
int PKI_TOKEN_get_algor_id( PKI_TOKEN *tk );
int PKI_TOKEN_set_algor( PKI_TOKEN *tk, PKI_ALGOR_ID algor );
int PKI_TOKEN_set_algor_by_name( PKI_TOKEN *tk, const char *algName );
int PKI_TOKEN_X509_REQ_profile_set( PKI_TOKEN *tk, PKI_X509_PROFILE *req_prof );
int PKI_TOKEN_X509_CERT_profile_set( PKI_TOKEN *tk, PKI_X509_PROFILE *cert_prof );

/* Token Credential Callback functions */
PKI_CRED *PKI_TOKEN_cred_cb_stdin ( char * prompt );
PKI_CRED *PKI_TOKEN_cred_cb_env ( char * env );
int PKI_TOKEN_cred_set_cb ( PKI_TOKEN *tk, PKI_CRED * (*cb)(char *), 
					char *prompt);
/* Basic functions: add data to the TOKEN structure */
int PKI_TOKEN_set_cert ( PKI_TOKEN *tk, PKI_X509_CERT *x );
int PKI_TOKEN_set_cacert ( PKI_TOKEN *tk, PKI_X509_CERT *x );
int PKI_TOKEN_set_keypair ( PKI_TOKEN *tk, PKI_X509_KEYPAIR *pkey );
int PKI_TOKEN_set_otherCerts ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *stack );
int PKI_TOKEN_set_trustedCerts ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *stack );
int PKI_TOKEN_set_crls ( PKI_TOKEN *tk, PKI_X509_CRL_STACK *stack );
int PKI_TOKEN_set_cred ( PKI_TOKEN *tk, PKI_CRED *cred );
int PKI_TOKEN_set_req( PKI_TOKEN *tk, PKI_X509_REQ *req );

/* Load data from URL pointers */
int PKI_TOKEN_load_cert( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_req ( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_cacert( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_keypair( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_otherCerts( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_trustedCerts( PKI_TOKEN *tk, char *url_string );
int PKI_TOKEN_load_crls( PKI_TOKEN *tk, char *url_string );

/* Retrieve pointers to PKI_TOKEN data */
PKI_X509_KEYPAIR *PKI_TOKEN_get_keypair ( PKI_TOKEN *tk );
PKI_X509_CERT *PKI_TOKEN_get_cert ( PKI_TOKEN *tk );
PKI_X509_CERT *PKI_TOKEN_get_cacert ( PKI_TOKEN *tk );
PKI_X509_CERT_STACK * PKI_TOKEN_get_otherCerts ( PKI_TOKEN *tk);
PKI_X509_CERT_STACK * PKI_TOKEN_get_trustedCerts ( PKI_TOKEN *tk);
PKI_X509_CRL_STACK * PKI_TOKEN_get_crls ( PKI_TOKEN *tk );
PKI_CRED *PKI_TOKEN_get_cred ( PKI_TOKEN *tk );
char * PKI_TOKEN_get_name ( PKI_TOKEN *tk );

PKI_X509_PKCS12 *PKI_TOKEN_get_p12 ( PKI_TOKEN *tk, PKI_CRED *cred );

/* Save data to URL pointers */
int PKI_TOKEN_export_p12 ( PKI_TOKEN *tk, PKI_DATA_FORMAT format, 
						char *url_s, PKI_CRED *cred );
int PKI_TOKEN_export_cert ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format );
int PKI_TOKEN_export_req ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format );
int PKI_TOKEN_export_keypair ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format );
int PKI_TOKEN_export_keypair_url( PKI_TOKEN *tk, URL *url, PKI_DATA_FORMAT format );
int PKI_TOKEN_export_otherCerts ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format );
int PKI_TOKEN_export_trustedCerts (PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format);

/* Import data into the token (add) */
int PKI_TOKEN_import_cert ( PKI_TOKEN *tk, PKI_X509_CERT *cert, 
				PKI_DATATYPE type, char *url_s);
int PKI_TOKEN_import_cert_stack ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *sk, 
				  PKI_DATATYPE type, char *url_s );

/* Delete an object from the token (del) */
int PKI_TOKEN_del_url ( PKI_TOKEN *tk, URL *url, PKI_DATATYPE datatype );

/* TOKEN operations */
int PKI_TOKEN_new_keypair ( PKI_TOKEN *tk, int bits, char *label );
int PKI_TOKEN_new_keypair_ex ( PKI_TOKEN *tk, PKI_KEYPARAMS *kp, char *label, char * profile_s);
int PKI_TOKEN_new_keypair_url ( PKI_TOKEN *tk, int bits, URL *label );
int PKI_TOKEN_new_keypair_url_ex ( PKI_TOKEN *tk, PKI_KEYPARAMS *kp, URL *label, char *profile_s );
int PKI_TOKEN_import_keypair ( PKI_TOKEN *tk, PKI_X509_KEYPAIR *key, char * url_s );
int PKI_TOKEN_new_req(PKI_TOKEN *tk, char *subject, char *profile_s );
int PKI_TOKEN_self_sign (PKI_TOKEN *tk, char *subject, char *serial,
				unsigned long validity, char *profile_s );
PKI_X509_CERT* PKI_TOKEN_issue_cert(PKI_TOKEN *tk, char *subject, char *serial,
		unsigned long validity, PKI_X509_REQ *req, char *profile_s);
PKI_X509_CRL * PKI_TOKEN_issue_crl ( PKI_TOKEN *tk, char *serial,
	unsigned long validity, PKI_X509_CRL_ENTRY_STACK *sk, char *profile_s );
PKI_TOKEN *PKI_TOKEN_issue_proxy (PKI_TOKEN *tk, char *subject, 
		char *serial, unsigned long validity, 
			char *profile_s, PKI_TOKEN *px_tk );

/* TOKEN profile ops */
int PKI_TOKEN_load_profiles ( PKI_TOKEN *tk, char *urlStr );
int PKI_TOKEN_add_profile( PKI_TOKEN *tk, PKI_X509_PROFILE *profile );
PKI_X509_PROFILE *PKI_TOKEN_search_profile( PKI_TOKEN *tk, char *profile_s );

/* TOKEN Slot */
int PKI_TOKEN_use_slot ( PKI_TOKEN *tk, long num );
int PKI_TOKEN_print_info ( PKI_TOKEN *tk );

#endif

