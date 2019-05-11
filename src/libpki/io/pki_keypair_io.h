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

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get_mem( PKI_MEM *mem,
					PKI_DATA_FORMAT format, PKI_CRED *cred );

PKI_MEM *PKI_X509_KEYPAIR_put_mem ( PKI_X509_KEYPAIR *key, PKI_DATA_FORMAT format, 
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

#endif
