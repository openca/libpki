/* libpki KEYPAIR I/O */

#ifndef _LIBPKI_X509_KEYPAIR_IO_HEADER_H
#define _LIBPKI_X509_KEYPAIR_IO_HEADER_H

/* ------------------ Key retrieve (load) functions ----------------------- */

/* Load a PKI_X509_KEYPAIR from a provided URL string */
PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get ( char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm );
PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm );
PKI_X509_KEYPAIR_STACK *PKI_X509_KEYPAIR_STACK_get (char *url_s,PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm);
PKI_X509_KEYPAIR_STACK *PKI_X509_KEYPAIR_STACK_get_url ( URL *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

/* ------------------ Keypair put (save) functions ----------------------- */

int PKI_X509_KEYPAIR_put (PKI_X509_KEYPAIR *x, PKI_DATA_FORMAT format, char *url_string,
						PKI_CRED *cred, HSM *hsm);
int PKI_X509_KEYPAIR_put_url( PKI_X509_KEYPAIR *x, PKI_DATA_FORMAT format, URL *url, 
						PKI_CRED *cred, HSM *hsm);

/* ------------------------- File I/O ------------------------------------ */
/* These functions should be generalized with a write to mem and then sent */
/* to the URL_put_data_url () function that will take care of send/save    */
/* the data according to the URL */
int PKI_X509_KEYPAIR_put_file( PKI_X509_KEYPAIR *key, PKI_DATA_FORMAT format, URL *url,
							PKI_CRED *cred );

/* -------------------------- Mem I/O ------------------------------------ */
/* These are needed for the URL_put_data_url() functionality - not for HSM */

/*! \brief Returns a PKI_X509_KEYPAIR from a PKI_MEM buffer */
PKI_X509_KEYPAIR * PKI_X509_KEYPAIR_get_mem(const PKI_MEM         * const mem,
											const PKI_DATA_FORMAT   format,
											const PKI_CRED        * const cred );

/*! \brief Reads a PKI_X509_KEYPAIR_VALUE from a PKI_MEM buffer */
PKI_X509_KEYPAIR_VALUE * PKI_X509_KEYPAIR_VALUE_get_mem(const PKI_MEM         * const mem, 
												        const PKI_DATA_FORMAT   format,
												        const PKI_CRED        * const cred );

/*! \brief Writes a PKI_X509_KEYPAIR to a PKI_MEM buffer */
PKI_MEM * PKI_X509_KEYPAIR_put_mem(const PKI_X509_KEYPAIR *  const key,
								   const PKI_DATA_FORMAT     format, 
								   PKI_MEM                ** const pki_mem,
								   const PKI_CRED          * cred,
								   const HSM               * hsm);

/*! \brief Writes a PKI_X509_KEYPAIR_VALUE to a PKI_MEM buffer */
PKI_MEM * PKI_X509_KEYPAIR_VALUE_put_mem(const PKI_X509_KEYPAIR_VALUE  * const key,
								   		 const PKI_DATA_FORMAT           format, 
								   		 PKI_MEM                      ** const pki_mem,
								   		 const PKI_CRED                * cred,
								   		 const HSM                     * hsm);

#endif
