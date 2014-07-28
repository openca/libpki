/* ENGINE HSM Support
 * ==================
 *
 *   Small Note: This code has been written by Massimiliano Pala sitting
 *   on a Bench in Princeton's campus... if there is someone to blame...
 *   blame Princeton!!!!
 *
 */

#ifndef _LIBPKI_ENGINE_H
#define _LIBPKI_ENGINE_H

unsigned long HSM_ENGINE_get_errno ( void );
char * HSM_ENGINE_get_errdesc ( unsigned long err, char *str, size_t size );

HSM *HSM_ENGINE_new ( PKI_CONFIG *conf );
int HSM_ENGINE_free ( HSM *driver, PKI_CONFIG *conf );
int HSM_ENGINE_init( HSM *driver, PKI_CONFIG *conf );

/* ---------------------- Sign/Verify functions ----------------------- */

/* General Signing function */
/*
int HSM_ENGINE_sign (PKI_OBJTYPE type, 
				void *x, 
				void *it_pp, 
				PKI_ALGOR *alg,
				PKI_STRING *bit,
				PKI_X509_KEYPAIR *key, 
				PKI_DIGEST_ALG *digest, 
				void *driver );
*/

/* ---------------------- ENGINE Slot Management Functions ---------------- */
HSM_SLOT_INFO * HSM_ENGINE_SLOT_INFO_get ( unsigned long num, HSM *hsm );

#endif

