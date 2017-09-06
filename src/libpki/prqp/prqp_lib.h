/* PKI Resource Query Protocol (PRQP) - Main Lib file
 * (c) 2006-2010 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 *
 */
                                                                                
#ifndef _LIBPKI_X509_PRQP_LIB_H
#define _LIBPKI_X509_PRQP_LIB_H

int CERT_IDENTIFIER_cmp ( CERT_IDENTIFIER *a, CERT_IDENTIFIER *b);

void *PKI_X509_PRQP_REQ_new_null( void );
void PKI_X509_PRQP_REQ_free_void( void *x );
void PKI_X509_PRQP_REQ_free ( PKI_X509_PRQP_REQ *x );

void *PKI_X509_PRQP_RESP_new_null( void );
void PKI_X509_PRQP_RESP_free_void( void *x );
void PKI_X509_PRQP_RESP_free ( PKI_X509_PRQP_RESP *x );

/* Service Objects conversion functions */
int PRQP_init_all_services ( void );

/* Certificate Identifier */
CERT_IDENTIFIER * PKI_PRQP_CERTID_new_cert(
		const PKI_X509_CERT  * caCert, 
		const PKI_X509_CERT  * issuerCert,
		const PKI_X509_CERT  * issuedCert,
		const char           * subject_s,
		const char           * serial_s,
		const PKI_DIGEST_ALG * dgst );

CERT_IDENTIFIER *PKI_PRQP_CERTID_new(
                const PKI_X509_NAME  * caName,
		const PKI_X509_NAME  * caIssuerName,
                const PKI_INTEGER    * serial,
		const PKI_STRING     * caCertHash,
		const PKI_STRING     * caKeyHash,
                const PKI_STRING     * caKeyId,
		const PKI_STRING     * issKeyId,
		const PKI_DIGEST_ALG *dgst);

/* General Signature Function for req or resp */
int PKI_X509_PRQP_sign( PKI_X509 *obj, PKI_X509_KEYPAIR *k,
                        PKI_X509_CERT *x, PKI_DIGEST_ALG *dgst,
                                        PKI_X509_CERT_STACK * certs );
int PKI_X509_PRQP_sign_tk ( PKI_X509 *obj, PKI_TOKEN *tk, PKI_DIGEST_ALG *dgst );

// ***************** REQUEST *******************

PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_new_cert(PKI_X509_CERT *x, PKI_X509_CERT *issuer, 
		PKI_X509_CERT *issued, char *issuer_s, char *serial_s, PKI_DIGEST_ALG *md );

PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_new_url( char * cert_s, char *issuer_cert_s, 
	char *issued_cert_s, char *issuer_s, char *serial_s, PKI_DIGEST_ALG *md ); 

PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_new_file( char * file, PKI_DATA_FORMAT format);

PKI_X509_PRQP_REQ * PKI_X509_PRQP_REQ_new_certs_res( PKI_X509_CERT *caCert, 
		PKI_X509_CERT *caIssuerCert, PKI_X509_CERT *issuedCert, PKI_STACK *sk_srv );

PKI_INTEGER *PKI_X509_PRQP_NONCE_new (int size);

/* Helper functions to add services to requests */
int PKI_X509_PRQP_REQ_add_service_stack ( PKI_X509_PRQP_REQ *p, PKI_STACK *sk_services );
int PKI_X509_PRQP_REQ_add_service ( PKI_X509_PRQP_REQ *p, char *ss );

int PKI_X509_PRQP_REQ_is_signed( PKI_X509_PRQP_REQ *r );
int PKI_X509_PRQP_REQ_verify ( PKI_X509_PRQP_REQ *r );

void * PKI_X509_PRQP_REQ_get_data ( PKI_X509_PRQP_REQ *r, PKI_X509_DATA type );

// ***************** RESPONSE ******************

int PKI_X509_PRQP_RESP_version_set ( PKI_X509_PRQP_RESP *resp, int ver );

int PKI_X509_PRQP_RESP_nonce_dup ( PKI_X509_PRQP_RESP *resp, PKI_X509_PRQP_REQ *req );
int PKI_X509_PRQP_RESP_pkistatus_set ( PKI_X509_PRQP_RESP *resp, long v, char *info );
int PKI_X509_PRQP_RESP_add_referrals ( PKI_X509_PRQP_RESP *r, PKI_STACK *referrals);
int PKI_X509_PRQP_RESP_add_service ( PKI_X509_PRQP_RESP *r, PKI_OID * resId, char * url, 
			long long version, char *comment, PKI_OID *oid );
int PKI_X509_PRQP_RESP_add_service_stack ( PKI_X509_PRQP_RESP *r, PKI_OID *resId, 
			PKI_STACK *url_stack, long long version, char *comment,
			PKI_OID *oid );

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_new_req ( PKI_X509_PRQP_RESP **resp_pnt,
			PKI_X509_PRQP_REQ *req, int status, long secs );
PKI_STACK * PKI_X509_PRQP_RESP_url_sk ( PKI_X509_PRQP_RESP *r );

int PKI_X509_PRQP_RESP_is_signed( PKI_X509_PRQP_RESP *r );
int PKI_X509_PRQP_RESP_verify ( PKI_X509_PRQP_RESP *r );

void * PKI_X509_PRQP_RESP_get_data ( PKI_X509_PRQP_RESP *r, PKI_X509_DATA type );
PKI_OID *PRQP_RESOURCE_RESPONSE_TOKEN_get_oid ( RESOURCE_RESPONSE_TOKEN *rrt );
PKI_STACK *PRQP_RESOURCE_RESPONSE_TOKEN_get_services( RESOURCE_RESPONSE_TOKEN *rrt );
int PKI_X509_PRQP_RESP_get_status ( PKI_X509_PRQP_RESP *r );

// ******************** Print facilities *******************

int PKI_X509_PRQP_REQ_print ( PKI_X509_PRQP_REQ *req );
int PKI_X509_PRQP_REQ_print_fp ( FILE *fp, PKI_X509_PRQP_REQ *req);
int PKI_X509_PRQP_REQ_VALUE_print_bio ( PKI_X509_PRQP_REQ_VALUE *req, BIO *bio);

int PKI_X509_PRQP_RESP_print ( PKI_X509_PRQP_RESP *resp );
int PKI_X509_PRQP_RESP_print_fp ( FILE *fp, PKI_X509_PRQP_RESP *resp );
int PKI_X509_PRQP_RESP_VALUE_print_bio ( PKI_X509_PRQP_RESP_VALUE *resp, BIO *bio );


#endif
