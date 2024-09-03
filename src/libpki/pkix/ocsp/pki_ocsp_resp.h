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

// int PKI_X509_OCSP_RESP_set_keytype_by_key(PKI_X509_OCSP_RESP     * x, 
// 										  const PKI_X509_KEYPAIR * const key);

// int PKI_X509_OCSP_RESP_set_keytype_by_cert(PKI_X509_OCSP_RESP  * x,
// 										   const PKI_X509_CERT * const cert);

// int PKI_X509_OCSP_RESP_set_nametype_by_cert(PKI_X509_OCSP_RESP * x,
// 											const PKI_X509     * const cert);

// int PKI_X509_OCSP_RESP_set_nametype_by_name(PKI_X509_OCSP_RESP  * x, 
// 											const PKI_X509_NAME * const name);

// int PKI_X509_OCSP_RESP_set_createdAt(PKI_X509_OCSP_RESP * x, int offset);

/* ---------------------------- Response Manipulation ------------------- */

/*!
 * @brief Sets the status of the OCSP response
 * @param x The OCSP response to which the status should be set
 * @param status The status to set
 * @return PKI_OK if the status was set successfully, PKI_ERR otherwise
 */
int PKI_X509_OCSP_RESP_set_status (PKI_X509_OCSP_RESP *x, 
								   PKI_X509_OCSP_RESP_STATUS status );

/*!
 * @brief Adds a single response to the OCSP response
 * @param r The OCSP response to which the response should be added
 * @param cid The certificate ID of the certificate to which the response
 * @param status The status of the certificate
 * @param revokeTime The time at which the certificate was revoked
 * @param thisUpdate The time at which the source of the revocation information was updated
 * @param nextUpdate The time at which the revocation information will be updated again
 * @param reason The reason code for the revocation
 * @param invalidityDate The date at which the certificate was invalidated
 * @return PKI_OK if the response was added successfully, PKI_ERR otherwise
 */
int PKI_X509_OCSP_RESP_add (PKI_X509_OCSP_RESP 	* r, 
							PKI_OCSP_CERTID 	* cid, 
							PKI_OCSP_CERTSTATUS   status,
							const PKI_TIME 		* revokeTime, 
							const PKI_TIME 		* thisUpdate,
							const PKI_TIME 		* nextUpdate, 
							PKI_X509_CRL_REASON   reason,
							PKI_X509_EXTENSION 	* invalidityDate);

/*! 
 * \brief Copies the NONCE from a PKI_OCSP_RESP into the response
 */
int PKI_X509_OCSP_RESP_copy_nonce (PKI_X509_OCSP_RESP *r, 
						PKI_X509_OCSP_REQ *req);

int PKI_X509_OCSP_RESP_set_extendedRevoke(PKI_X509_OCSP_RESP * resp);

int PKI_X509_OCSP_RESP_bytes_encode ( PKI_X509_OCSP_RESP * resp);

/* ------------------------------ Signature ----------------------------- */

// int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP *r, PKI_X509_KEYPAIR *pkey,
// 					PKI_DIGEST_ALG *md );

/*! 
 * \brief Signs a PKI_X509_OCSP_RESP
 *
 * For a simpler API use PKI_X509_OCSP_RESP_sign_tk 
 */

int PKI_X509_OCSP_RESP_sign ( PKI_X509_OCSP_RESP *r, PKI_X509_KEYPAIR *keypair,
		PKI_X509_CERT *cert, PKI_X509_CERT *issuer, 
		PKI_X509_CERT_STACK * otherCerts, PKI_DIGEST_ALG *digest,
		PKI_X509_OCSP_RESPID_TYPE respidType);

/*! 
 * \brief Signs a PKI_X509_OCSP_RESP object by using a token
 */
int PKI_X509_OCSP_RESP_sign_tk ( PKI_X509_OCSP_RESP *r, PKI_TOKEN *tk, 
				 PKI_DIGEST_ALG *digest, PKI_X509_OCSP_RESPID_TYPE respidType);

/* ------------------------------ Data Parsing --------------------------- */

/*! 
 * \brief Returns a pointer to the data present in the OCSP request
 */
const void * PKI_X509_OCSP_RESP_get_data ( PKI_X509_OCSP_RESP *r, PKI_X509_DATA type );

/*! 
 * \brief Returns a char * representation of the data present in the
 *         OCSP request
 */
char * PKI_X509_OCSP_RESP_get_parsed ( PKI_X509_OCSP_RESP *r, PKI_X509_DATA type );

/*! 
 * \brief Prints the requested data from the OCSP request to the file
 *         descriptor passed as an argument
 */
int PKI_X509_OCSP_RESP_print_parsed ( PKI_X509_OCSP_RESP *r, 
				PKI_X509_DATA type, int fd );

/* ----------------------------- Basic I/O ------------------------------- */

/* 
 *! \brief PEM <-> INTERNAL Macros --- fix for errors in OpenSSL
 */

PKI_X509_OCSP_RESP_VALUE *PEM_read_bio_PKI_X509_OCSP_RESP_VALUE( PKI_IO *bp, void *a,
						void *b, void *c );
int PEM_write_bio_PKI_X509_OCSP_RESP_VALUE( PKI_IO *bp, PKI_X509_OCSP_RESP_VALUE *o );

PKI_OCSP_RESP *d2i_PKI_X509_OCSP_RESP_VALUE_bio ( PKI_IO *bp, PKI_X509_OCSP_RESP_VALUE **p );

int i2d_PKI_X509_OCSP_RESP_VALUE_bio(PKI_IO *bp, PKI_X509_OCSP_RESP_VALUE *o );

#endif
