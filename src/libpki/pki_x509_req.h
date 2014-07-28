/* PKI_X509_REQ driver specific object management */

#ifndef _LIBPKI_PKI_X509_REQ_H
#define _LIBPKI_PKI_X509_REQ_H

/* Create/Destroy REQ objects */
PKI_X509_REQ * PKI_X509_REQ_new_null ( void );

PKI_X509_REQ *PKI_X509_REQ_new ( PKI_X509_KEYPAIR *pkey, char *subj_s,
			PKI_X509_PROFILE *req_cnf, PKI_CONFIG *oids, 
				PKI_DIGEST_ALG *digest, HSM *hsm );

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
int PKI_X509_REQ_get_attributes_num ( PKI_X509_REQ *req );

PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute ( PKI_X509_REQ *req, PKI_ID type );
PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_num( PKI_X509_REQ *req, int num);
PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_name ( PKI_X509_REQ *req, 
						char * name );

/* Retrieve Data from a REQ object */
int PKI_X509_REQ_get_keysize ( PKI_X509_REQ *x );
void * PKI_X509_REQ_get_data ( PKI_X509_REQ *req, PKI_X509_DATA type );
const char * PKI_X509_REQ_get_parsed( PKI_X509_REQ *req,PKI_X509_DATA type);
int PKI_X509_REQ_print_parsed ( PKI_X509_REQ *req, 
					PKI_X509_DATA type, int fd );

/* Retrieve Extensions from the Request */
int PKI_X509_REQ_get_extension_by_num ( PKI_X509_REQ *req, int num );
int PKI_X509_REQ_get_extension_by_oid ( PKI_X509_REQ *req, PKI_OID *id );
int PKI_X509_REQ_get_extension_by_name ( PKI_X509_REQ *req, char * name );

#endif /* _LIBPKI_PKI_X509_REQ_H */
