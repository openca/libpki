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

/// @brief Login into the token (triggers keypair loading)
/// @param tk [in,out] The token to login into (PKI_TOKEN *)
/// @return PKI_OK if successful or an error code otherwise (PKI_ERR_)
int PKI_TOKEN_login(PKI_TOKEN * const tk);

// Sets the login status for the token
int PKI_TOKEN_set_login_success(PKI_TOKEN * const tk);
int PKI_TOKEN_is_logged_in(const PKI_TOKEN * const tk);
int PKI_TOKEN_status_clear_errors(PKI_TOKEN * const tk);
int PKI_TOKEN_status_set(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status);
int PKI_TOKEN_status_del_error(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status);
int PKI_TOKEN_status_add_error(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status);
PKI_TOKEN_STATUS PKI_TOKEN_status_get(const PKI_TOKEN * const tk);

int PKI_TOKEN_init (PKI_TOKEN *tk, char *conf_url, char *name);
PKI_OID *PKI_TOKEN_OID_new ( PKI_TOKEN *tk, char *oid_s );
int PKI_TOKEN_check ( PKI_TOKEN *tk );

/* Configuration options */
PKI_X509_ALGOR_VALUE *PKI_TOKEN_get_algor( PKI_TOKEN *tk );
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

/// @brief Generate a new CRL from a stack of revoked entries
/// @details Generates a new signed CRL from a stack of revoked entries. If a profile
///    passed, it is used to set the right extensions in the CRL. To generate a
///    new revoked entry the PKI_X509_CRL_ENTRY_new() function has to be used.
/// @param tk is the signing token (PKI_TOKEN)
/// @param serial is the text representation of the crl number (char *)
/// @param thisUpdate offset from 'now', in seconds, for thisUpdate date (long long) 
/// @param nextUpdate offset from 'now', in seconds, for nextUpdate date (long long)
/// @param sk is the stack of revoked entries (PKI_STACK_X509_CRL_ENTRY *)
/// @param exts is the stack of extensions for the CRL (PKI_STACK_X509_EXTENSION *)
/// @param profile_s is the name of the profile for CRL extensions (char *)
/// @return The newly issued (and signed) CRL (PKI_X509_CRL *)
PKI_X509_CRL * PKI_TOKEN_issue_crl (const PKI_TOKEN 			   * tk,           /* signing token */
									const char 					   * const serial, /* crlNumber */ 
									const long long 				 thisUpdate    /* offset */,
									const long long 				 nextUpdate    /* offset */, 
									const PKI_X509_CRL_ENTRY_STACK * const sk,     /* stack of rev */
									const PKI_X509_EXTENSION_STACK * const exts,   /* stack of crl exts */
									const char 					   * profile_s );

PKI_TOKEN *PKI_TOKEN_issue_proxy (PKI_TOKEN *tk, char *subject, 
		char *serial, unsigned long validity, 
			char *profile_s, PKI_TOKEN *px_tk );

/* TOKEN profile ops */
int PKI_TOKEN_load_profiles(PKI_TOKEN *tk, char *urlStr);
int PKI_TOKEN_clear_profiles(PKI_TOKEN * tk);
int PKI_TOKEN_add_profile( PKI_TOKEN *tk, PKI_X509_PROFILE *profile );

/// @brief Returns a named profile from the loaded ones
/// @param tk is the token where the profiles have been loaded (PKI_TOKEN *)
/// @param profile_s is the name of the requested profile (char *)
/// @return the searched profile or NULL if none was found (PKI_X509_PROFILE *)
PKI_X509_PROFILE *PKI_TOKEN_search_profile(const PKI_TOKEN * const tk,
										   const char 	   * const profile_s);

/* TOKEN Slot */
int PKI_TOKEN_use_slot(PKI_TOKEN *tk, long num);
int PKI_TOKEN_print_info(PKI_TOKEN *tk);

#endif

