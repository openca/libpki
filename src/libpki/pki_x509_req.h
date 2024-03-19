/* PKI_X509_REQ driver specific object management */

#ifndef _LIBPKI_PKI_X509_REQ_H
#define _LIBPKI_PKI_X509_REQ_H
# pragma once

// LibPKI Includes
#include <libpki/pki_x509_data_st.h>
#include <libpki/profile.h>

BEGIN_C_DECLS

// Stack Declarations
DECLARE_LIBPKI_STACK_FN(PKI_X509_REQ)

						// ====================
						// Functions Prototypes
						// ====================

/* Create/Destroy REQ objects */
PKI_X509_REQ * PKI_X509_REQ_new_null ( void );

/*!
 * \brief Create a new PKI_X509_REQ object
 *
 * This function creates a new PKI_X509_REQ object.  The function takes
 * as input a PKI_X509_KEYPAIR object, a subject string, a PKI_X509_PROFILE
 * object, a PKI_CONFIG object, a PKI_DIGEST_ALG object, and an HSM object.
 * The function returns a pointer to the new PKI_X509_REQ object. All
 * parameters are optional except for the pkey, and the function will use
 * default values if they are not provided.
 *
 * \param pkey is a pointer to a PKI_X509_KEYPAIR object
 * \param subj_s is a pointer to a string containing the subject
 * \param req_cnf is a pointer to a PKI_X509_PROFILE object
 * \param oids is a pointer to a PKI_CONFIG object
 * \param digest is a pointer to a PKI_DIGEST_ALG object
 * \param hsm is a pointer to an HSM object
 * \return a pointer to the new PKI_X509_REQ object
*/
PKI_X509_REQ *PKI_X509_REQ_new(const PKI_X509_KEYPAIR * pkey, 
			       			   const char 			  * subj_s,
			       			   const PKI_X509_PROFILE * req_cnf, 
			       			   const PKI_CONFIG 	  * oids, 
			       			   const PKI_DIGEST_ALG   * digest,
			       			   HSM 					  * hsm);

PKI_X509_REQ *PKI_X509_REQ_dup(const PKI_X509_REQ *req);

void PKI_X509_REQ_free( PKI_X509_REQ *x );
void PKI_X509_REQ_free_void( void *x );

/* Manage extensions */
int PKI_X509_REQ_add_extension(PKI_X509_REQ *x, PKI_X509_EXTENSION *ext);
int PKI_X509_REQ_add_extension_stack(PKI_X509_REQ *x, 
					PKI_X509_EXTENSION_STACK *ext);

/* Attributes */
int PKI_X509_REQ_add_attribute ( PKI_X509_REQ *req, PKI_X509_ATTRIBUTE_VALUE *attr );
int PKI_X509_REQ_delete_attribute ( PKI_X509_REQ *req, PKI_ID id );
int PKI_X509_REQ_delete_attribute_by_num ( PKI_X509_REQ *req, int num );
int PKI_X509_REQ_delete_attribute_by_name ( PKI_X509_REQ *req, char *name );
int PKI_X509_REQ_clear_attributes ( PKI_X509_REQ *req );
int PKI_X509_REQ_get_attributes_num (const PKI_X509_REQ *req );

const PKI_X509_ATTRIBUTE_VALUE *PKI_X509_REQ_get_attribute(const PKI_X509_REQ *req,
						     PKI_ID type );

const PKI_X509_ATTRIBUTE_VALUE *PKI_X509_REQ_get_attribute_by_num(
					const PKI_X509_REQ *req, int num);

const PKI_X509_ATTRIBUTE_VALUE *PKI_X509_REQ_get_attribute_by_name(
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

END_C_DECLS

#endif // End of _LIBPKI_PKI_X509_REQ_H
