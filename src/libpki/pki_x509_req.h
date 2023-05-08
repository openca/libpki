/* PKI_X509_REQ driver specific object management */

#ifndef _LIBPKI_PKI_X509_REQ_H
#define _LIBPKI_PKI_X509_REQ_H

// ================
// OpenSSL Includes
// ================

#ifndef HEADER_X509_H
#include <openssl/x509.h>
#endif

#ifndef HEADER_X509V3_H
#include <openssl/x509v3.h>
#endif

// ===============
// LibPKI Includes
// ===============

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_ERR_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_X509_ATTRIBUTE_H_
#include <libpki/pki_x509_attribute.h>
#endif

#ifndef _LIBPKI_PKI_X509_TYPES_H
#include <libpki/pki_x509_types.h>
#endif

#ifndef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

// ====================
// Function Definitions
// ====================

/* Create/Destroy REQ objects */
PKI_X509_REQ * PKI_X509_REQ_new_null ( void );

PKI_X509_REQ *PKI_X509_REQ_new(const PKI_X509_KEYPAIR *pkey, 
			       const char *subj_s,
			       const PKI_X509_PROFILE *req_cnf, 
			       const PKI_CONFIG *oids, 
			       const PKI_DIGEST_ALG *digest,
			       HSM *hsm );

void PKI_X509_REQ_free( PKI_X509_REQ *x );
void PKI_X509_REQ_free_void( void *x );

/* Manage extensions */
int PKI_X509_REQ_add_extension(PKI_X509_REQ *x, PKI_X509_EXTENSION *ext);
int PKI_X509_REQ_add_extension_stack(PKI_X509_REQ *x, 
					PKI_X509_EXTENSION_STACK *ext);

/* Attributes */
int PKI_X509_REQ_add_attribute ( PKI_X509_REQ *req, PKI_X509_ATTRIBUTE *attr );
int PKI_X509_REQ_delete_attribute ( PKI_X509_REQ *req, PKI_ID id );
int PKI_X509_REQ_delete_attribute_by_num ( PKI_X509_REQ *req, int num );
int PKI_X509_REQ_delete_attribute_by_name ( PKI_X509_REQ *req, char *name );
int PKI_X509_REQ_clear_attributes ( PKI_X509_REQ *req );
int PKI_X509_REQ_get_attributes_num (const PKI_X509_REQ *req );

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute(const PKI_X509_REQ *req,
						     PKI_ID type );

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_num(
					const PKI_X509_REQ *req, int num);

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_name(
					const PKI_X509_REQ *req, 
					const char * name );

/* Retrieve Data from a REQ object */
int PKI_X509_REQ_get_keysize ( const PKI_X509_REQ *x );

const void * PKI_X509_REQ_get_data ( const PKI_X509_REQ *req, 
				     PKI_X509_DATA type );

const char * PKI_X509_REQ_get_parsed(const PKI_X509_REQ *req,
				     PKI_X509_DATA type);

int PKI_X509_REQ_print_parsed(const PKI_X509_REQ *req, 
			      PKI_X509_DATA type, 
			      int fd );

/* Retrieve Extensions from the Request */
int PKI_X509_REQ_get_extension_by_num(const PKI_X509_REQ *req, int num );

int PKI_X509_REQ_get_extension_by_oid(const PKI_X509_REQ *req, 
				      const PKI_OID *id );

int PKI_X509_REQ_get_extension_by_name(const PKI_X509_REQ *req, 
				       const char * name );

#endif /* _LIBPKI_PKI_X509_REQ_H */
