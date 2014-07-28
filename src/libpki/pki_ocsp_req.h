/* PKI_X509_OCSP_REQ object management */

#ifndef _LIBPKI_X509_OCSP_REQ_H
#define _LIBPKI_X509_OCSP_REQ_H

/* Macros for PKI_MEM conversion */
#define PKI_X509_OCSP_REQ_mem_der(a) \
        PKI_MEM_new_func( (void *) a, i2d_OCSP_REQ_bio )
#define PKI_X509_OCSP_REQ_mem_pem(a) \
        PKI_MEM_new_func( (void *) a, PEM_write_bio_OCSP_REQ )

/* --------------------------------- Memory Allocation ------------------ */
PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_new ( void );
void PKI_X509_OCSP_REQ_free_void( void *x );
void PKI_X509_OCSP_REQ_free( PKI_X509_OCSP_REQ *x );

/* --------------------------------- Request Generation ----------------- */
int PKI_X509_OCSP_REQ_add_nonce ( PKI_X509_OCSP_REQ *req, size_t size );

int PKI_X509_OCSP_REQ_add_serial ( PKI_X509_OCSP_REQ *req, PKI_INTEGER *serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest );
int PKI_X509_OCSP_REQ_add_cert ( PKI_X509_OCSP_REQ *req, PKI_X509_CERT *cert, 
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest );
int PKI_X509_OCSP_REQ_add_txt ( PKI_X509_OCSP_REQ *req, char *serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest );
int PKI_X509_OCSP_REQ_add_longlong ( PKI_X509_OCSP_REQ *req, long long serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest );

/* --------------------------------- Signature -------------------------- */
int PKI_X509_OCSP_REQ_DATA_sign (PKI_X509_OCSP_REQ *req,
                        PKI_X509_KEYPAIR *k, PKI_DIGEST_ALG *md );

int PKI_X509_OCSP_REQ_sign ( PKI_X509_OCSP_REQ *req, PKI_X509_KEYPAIR *keypair,
		PKI_X509_CERT *cert, PKI_X509_CERT *issuer, 
		PKI_X509_CERT_STACK * otherCerts, PKI_DIGEST_ALG *digest );

int PKI_X509_OCSP_REQ_sign_tk ( PKI_X509_OCSP_REQ *req, PKI_TOKEN *tk );

/* --------------------------------- Parsing ---------------------------- */
int PKI_X509_OCSP_REQ_elements ( PKI_X509_OCSP_REQ *req );

PKI_OCSP_CERTID * PKI_X509_OCSP_REQ_get_cid ( PKI_X509_OCSP_REQ *req, int num);
PKI_INTEGER * PKI_X509_OCSP_REQ_get_serial ( PKI_X509_OCSP_REQ *req, int num);

void * PKI_X509_OCSP_REQ_get_data ( PKI_X509_OCSP_REQ *req, PKI_X509_DATA type );
char * PKI_X509_OCSP_REQ_get_parsed ( PKI_X509_OCSP_REQ *req, PKI_X509_DATA type );

int PKI_X509_OCSP_REQ_print_parsed ( PKI_X509_OCSP_REQ *req, 
				PKI_X509_DATA type, int fd );

/* --------------------------------- Tools ------------------------------ */

int PKI_OCSP_nonce_check ( PKI_X509_OCSP_REQ *req, PKI_X509_OCSP_RESP *resp );

/* ------------------------------- Basic I/O ---------------------------- */

PKI_X509_OCSP_REQ_VALUE *PEM_read_bio_OCSP_REQ( PKI_IO *bp, void *,
						void *, void * );
int PEM_write_bio_OCSP_REQ( PKI_IO *bp, PKI_X509_OCSP_REQ_VALUE *o );
int i2d_OCSP_REQ_bio ( PKI_IO *bio, PKI_X509_OCSP_REQ_VALUE *val );
PKI_X509_OCSP_REQ_VALUE * d2i_OCSP_REQ_bio ( PKI_IO *bio, 
					PKI_X509_OCSP_REQ_VALUE *buf );

#endif

