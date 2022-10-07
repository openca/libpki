/* HSM Object Management Functions */

#ifndef _LIBPKI_HSM_MAIN_KEYPAIR_H
#define _LIBPKI_HSM_MAIN_KEYPAIR_H

#ifndef _LIBPKI_X509_KEYPAIR_HEADER_H
#include <libpki/pki_keypair.h>
#endif

/* -------------------- Key Management Functions --------------------- */

/* Generate a new Keypair */
PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new( PKI_KEYPARAMS *params, char *label,
                                        PKI_CRED *cred, HSM *hsm );

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new_url( PKI_KEYPARAMS *params, URL *url,
                                        PKI_CRED *cred, HSM *driver );

/* Free the memory associated to a keypair */
/*
int PKI_X509_KEYPAIR_free( PKI_X509_KEYPAIR *key, HSM *hsm );
void PKI_X509_KEYPAIR_free_void ( void *key );
*/

/* --------------------------- Wrap/Unwrap ---------------------------- */

PKI_MEM *HSM_X509_KEYPAIR_wrap ( PKI_X509_KEYPAIR *key, PKI_CRED *cred );

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_unwrap ( PKI_MEM *mem,
				URL *url, PKI_CRED *cred, HSM *hsm );
#endif
