/* pki_x509.h */

#ifndef _LIBPKI_X509_CERT_HEADER_H
#define _LIBPKI_X509_CERT_HEADER_H

/* Memory functions */
PKI_X509_CERT *PKI_X509_CERT_new_null( void );

void PKI_X509_CERT_free ( PKI_X509_CERT *x );

PKI_X509_CERT * PKI_X509_CERT_new ( PKI_X509_CERT *ca_cert, 
	PKI_X509_KEYPAIR *pkey, PKI_X509_REQ *req, char *subj_s, char *serial,
	uint64_t validity, PKI_X509_PROFILE *conf, PKI_ALGOR * algor,
	PKI_CONFIG *oids, HSM *hsm );
PKI_X509_CERT *PKI_X509_CERT_dup ( PKI_X509_CERT *x );

/* Signature Specific Functions */
int PKI_X509_CERT_sign ( PKI_X509_CERT *x, PKI_X509_KEYPAIR *k,
				PKI_DIGEST_ALG *alg );
int PKI_X509_CERT_sign_tk ( PKI_X509_CERT *cert, PKI_TOKEN *tk,
		PKI_DIGEST_ALG *alg);

/* Get/Set data in a certificate */
void * PKI_X509_CERT_get_data ( PKI_X509_CERT *x, PKI_X509_DATA type );
int PKI_X509_CERT_set_data ( PKI_X509_CERT *x, int type, void *data );

/* Print and Get Parsed Data */
int PKI_X509_CERT_get_keysize ( PKI_X509_CERT *x );
char * PKI_X509_CERT_get_parsed( PKI_X509_CERT *x, PKI_X509_DATA type );
int PKI_X509_CERT_print_parsed( PKI_X509_CERT *x, 
				PKI_X509_DATA type, int fd );

/* Key Check function */
int PKI_X509_CERT_check_pubkey(PKI_X509_CERT *x, PKI_X509_KEYPAIR *k);

/* Exts functions */
int PKI_X509_CERT_add_extension ( PKI_X509_CERT *x, PKI_X509_EXTENSION *ext );
int PKI_X509_CERT_add_extension_stack (PKI_X509_CERT *x, 
				PKI_X509_EXTENSION_STACK *ext);

/* Fingerprint functions */
PKI_DIGEST *PKI_X509_CERT_fingerprint ( PKI_X509_CERT *x, PKI_DIGEST_ALG *alg );
PKI_DIGEST *PKI_X509_CERT_fingerprint_by_name( PKI_X509_CERT *x, char *alg );

/* Key Hash functions */
PKI_DIGEST *PKI_X509_CERT_key_hash ( PKI_X509_CERT *x, PKI_DIGEST_ALG *alg );
PKI_DIGEST *PKI_X509_CERT_key_hash_by_name ( PKI_X509_CERT *x, char *alg );

/* Get Certificate type - look for PKI_X509_CERT_TYPE */
PKI_X509_CERT_TYPE PKI_X509_CERT_get_type ( PKI_X509_CERT *x );

/* Retrieve Extensions from the Certificate */
PKI_STACK *PKI_X509_CERT_get_cdp ( PKI_X509_CERT *cert );

int PKI_X509_CERT_is_selfsigned ( PKI_X509_CERT *x );
int PKI_X509_CERT_is_ca ( PKI_X509_CERT *x );
int PKI_X509_CERT_is_proxy ( PKI_X509_CERT *x );
int PKI_X509_CERT_check_domain ( PKI_X509_CERT *x, char *domain );
char ** PKI_X509_CERT_get_email ( PKI_X509_CERT *x );

// PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_num ( PKI_X509_CERT  *x, 
// 							int num );

PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_id ( PKI_X509_CERT  *x, 
							PKI_ID id );
PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_name ( PKI_X509_CERT *x,
							char * name );
PKI_X509_EXTENSION *PKI_X509_CERT_get_extension_by_oid ( PKI_X509_CERT  *x,
                                                                PKI_OID *id );

#endif
