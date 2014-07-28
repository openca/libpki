/* ENGINE Object Management Functions */

#ifndef _LIBPKI_HEADERS_KMF_PKEY_H
#define _LIBPKI_HEADERS_KMF_PKEY_H

PKI_KEYPAIR *HSM_KMF_KEYPAIR_new( int type, int bits, HSM *hsm, 
							PKI_CRED *cred );
int HSM_KMF_KEYPAIR_free ( PKI_KEYPAIR *pkey );
int PKI_KMF_KEYPAIR_write_file( PKI_KEYPAIR *key, int format, 
						char *file, HSM *hsm );

#endif

