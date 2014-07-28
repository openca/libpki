/* engine/engine_hsm_pkey.c */

#ifndef _LIBPKI_ENGINE_PKEY_H
#define _LIBPKI_ENGINE_PKEY_H

/* -------------------- Key Management Functions ----------------------- */

/* New keypair */
PKI_X509_KEYPAIR *HSM_ENGINE_X509_KEYPAIR_new( PKI_KEYPARAMS *pk,
				URL *url, PKI_CRED *cred, HSM *driver );

/* Key Free function */
void HSM_ENGINE_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey );

#endif
