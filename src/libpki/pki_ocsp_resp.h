/* PKI_X509_OCSP_RESP object management */

#ifndef _LIBPKI_X509_OCSP_RESP_H
#define _LIBPKI_X509_OCSP_RESP_H

/* Macros for PKI_MEM conversion */
#define PKI_X509_OCSP_RESP_mem_der(a) \
        PKI_MEM_new_func( (void *) a, i2d_OCSP_RESP_bio )
#define PKI_X509_OCSP_RESP_mem_pem(a) \
        PKI_MEM_new_func( (void *) a, PEM_write_bio_OCSP_RESP )

/* ---------------------------- Memory Management ----------------------- */

PKI_OCSP_RESP *PKI_OCSP_RESP_new ( void );
void PKI_OCSP_RESP_free( PKI_OCSP_RESP *x );

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new_null( void );
PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new ( void );

void PKI_X509_OCSP_RESP_free_void( void *x );
void PKI_X509_OCSP_RESP_free( PKI_X509_OCSP_RESP *x );

/* ---------------------------- Response Manipulation ------------------- */

int PKI_X509_OCSP_RESP_set_status ( PKI_X509_OCSP_RESP *x, 
																		PKI_X509_OCSP_RESP_STATUS status );

int PKI_X509_OCSP_RESP_add ( PKI_X509_OCSP_RESP *r, 
														PKI_OCSP_CERTID *cid, PKI_OCSP_CERTSTATUS status,
														const PKI_TIME *revokeTime, 
														const PKI_TIME *thisUpdate,
														const PKI_TIME *nextUpdate, 
														PKI_X509_CRL_REASON reason,
														PKI_X509_EXTENSION *invalidityDate );

int PKI_X509_OCSP_RESP_copy_nonce (PKI_X509_OCSP_RESP *r, 
						PKI_X509_OCSP_REQ *req);

int PKI_X509_OCSP_RESP_set_extendedRevoke(PKI_X509_OCSP_RESP * resp);

int PKI_X509_OCSP_resp_bytes_encode ( PKI_X509_OCSP_RESP * resp);

/* ------------------------------ Signature ----------------------------- */

int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP *r, PKI_X509_KEYPAIR *pkey,
					PKI_DIGEST_ALG *md );

int PKI_X509_OCSP_RESP_sign ( PKI_X509_OCSP_RESP *r, PKI_X509_KEYPAIR *keypair,
		PKI_X509_CERT *cert, PKI_X509_CERT *issuer, 
		PKI_X509_CERT_STACK * otherCerts, PKI_DIGEST_ALG *digest,
		PKI_X509_OCSP_RESPID_TYPE respidType);

int PKI_X509_OCSP_RESP_sign_tk ( PKI_X509_OCSP_RESP *r, PKI_TOKEN *tk, 
				 PKI_DIGEST_ALG *digest, PKI_X509_OCSP_RESPID_TYPE respidType);

/* ------------------------------ Data Parsing --------------------------- */

const void * PKI_X509_OCSP_RESP_get_data ( PKI_X509_OCSP_RESP *r, PKI_X509_DATA type );
char * PKI_X509_OCSP_RESP_get_parsed ( PKI_X509_OCSP_RESP *r, PKI_X509_DATA type );

int PKI_X509_OCSP_RESP_print_parsed ( PKI_X509_OCSP_RESP *r, 
				PKI_X509_DATA type, int fd );

/* ----------------------------- Basic I/O ------------------------------- */

PKI_OCSP_RESP *PEM_read_bio_PKI_OCSP_RESP( PKI_IO *bp, void *a,
						void *b, void *c );
int PEM_write_bio_PKI_OCSP_RESP( PKI_IO *bp, PKI_OCSP_RESP *o );

PKI_OCSP_RESP *d2i_PKI_OCSP_RESP_bio ( PKI_IO *bp, PKI_OCSP_RESP **p );

int i2d_PKI_OCSP_RESP_bio(PKI_IO *bp, PKI_OCSP_RESP *o );

#endif
