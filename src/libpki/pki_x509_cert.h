/* pki_x509.h */

#ifndef _LIBPKI_X509_CERT_HEADER_H
#define _LIBPKI_X509_CERT_HEADER_H
# pragma once

// LibPKI Includes
#include <libpki/pki_x509.h>
#include <libpki/pki_x509_extension.h>

// Stack Declarations
DECLARE_LIBPKI_STACK_FN_DUP(PKI_X509_CERT)

						// ====================
						// Functions Prototypes
						// ====================

/* Memory functions */
PKI_X509_CERT *PKI_X509_CERT_new_null( void );

void PKI_X509_CERT_free ( PKI_X509_CERT *x );

PKI_X509_CERT * PKI_X509_CERT_new (const PKI_X509_CERT *ca_cert, 
				   const PKI_X509_KEYPAIR *pkey, 
				   const PKI_X509_REQ *req, 
				   const char *subj_s, 
				   const char *serial,
				   uint64_t validity, 
				   const PKI_X509_PROFILE *conf, 
				   const PKI_X509_ALGOR_VALUE * algor,
				   const PKI_CONFIG *oids,
				   HSM *hsm );

PKI_X509_CERT *PKI_X509_CERT_dup (const PKI_X509_CERT *x );

/* Signature Specific Functions */
int PKI_X509_CERT_sign ( PKI_X509_CERT *x, PKI_X509_KEYPAIR *k,
				PKI_DIGEST_ALG *alg );
int PKI_X509_CERT_sign_tk ( PKI_X509_CERT *cert, PKI_TOKEN *tk,
		PKI_DIGEST_ALG *alg);

/* Get/Set data in a certificate */

/*! \brief Returns a pointer to a specified data field in a certificate */
const void * PKI_X509_CERT_get_data(const PKI_X509_CERT *x, PKI_X509_DATA type);

int PKI_X509_CERT_set_data(PKI_X509_CERT *x, int type, void *data);

/* Special case for TBS encoded data */
PKI_MEM * PKI_X509_CERT_get_der_tbs(const PKI_X509_CERT *x );

/* Print and Get Parsed Data */
int PKI_X509_CERT_get_keysize (const PKI_X509_CERT *x );

char * PKI_X509_CERT_get_parsed(const PKI_X509_CERT *x, 
				PKI_X509_DATA type );

int PKI_X509_CERT_print_parsed(const PKI_X509_CERT *x, 
				PKI_X509_DATA type,
				int fd );

/* Key Check function */
int PKI_X509_CERT_check_pubkey(const PKI_X509_CERT *x, 
		 	       const PKI_X509_KEYPAIR *k);

/* Exts functions */
int PKI_X509_CERT_add_extension( PKI_X509_CERT *x, 
				 const PKI_X509_EXTENSION *ext );
int PKI_X509_CERT_add_extension_stack (PKI_X509_CERT *x, 
				       const PKI_X509_EXTENSION_STACK *ext);

/* Fingerprint functions */
PKI_DIGEST *PKI_X509_CERT_fingerprint(const PKI_X509_CERT *x,
				      const PKI_DIGEST_ALG *alg );
PKI_DIGEST *PKI_X509_CERT_fingerprint_by_name(const PKI_X509_CERT *x,
					      const char *alg );

/* Key Hash functions */
PKI_DIGEST *PKI_X509_CERT_key_hash(const PKI_X509_CERT *x, 
				   const PKI_DIGEST_ALG *alg );
PKI_DIGEST *PKI_X509_CERT_key_hash_by_name(const PKI_X509_CERT *x, 
					   const char *alg );

/* Get Certificate type - look for PKI_X509_CERT_TYPE */
PKI_X509_CERT_TYPE PKI_X509_CERT_get_type(const PKI_X509_CERT *x );

/* Retrieve Extensions from the Certificate */
PKI_STACK *PKI_X509_CERT_get_cdp(const PKI_X509_CERT *cert );

int PKI_X509_CERT_is_selfsigned(const PKI_X509_CERT *x );
int PKI_X509_CERT_is_ca(const PKI_X509_CERT *x );
int PKI_X509_CERT_is_proxy(const PKI_X509_CERT *x );
int PKI_X509_CERT_check_domain(const PKI_X509_CERT *x,
			       const char *domain );

/* Retrieves the e-mail address from the Subject or SubjectAltName */
PKI_STACK * PKI_X509_CERT_get_email(const PKI_X509_CERT *x );

// PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_num ( PKI_X509_CERT  *x, 
// 							int num );

PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_id(const PKI_X509_CERT  *x, 
						       PKI_ID id );
PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_name(const PKI_X509_CERT *x,
							 const char * name );
PKI_X509_EXTENSION *PKI_X509_CERT_get_extension_by_oid (const PKI_X509_CERT  *x,
                                                        const PKI_OID *id );

#endif
