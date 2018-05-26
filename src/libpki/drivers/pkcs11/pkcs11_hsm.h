/* libpki/drivers/pkcs11/pkcs11_hsm.h */

#ifndef _LIBPKI_HSM_PKCS11_H
#define _LIBPKI_HSM_PKCS11_H

typedef struct pkcs11_handler {

	/* Pointer to the Shared Object (lib) */
	void *sh_lib;

	/* Info for the current HSM and Library */
	HSM_INFO hsm_info;

	/* Available Mechanisms (Algoritms) */
	CK_MECHANISM_TYPE_PTR mech_list;

	/* Number of available Mechanisms (Algorithms) */
	unsigned long mech_num;

	/* Current Algorithm */
	CK_MECHANISM_TYPE mech_curr;

	/* Callbacks - Easier to reference for PKCS11 drivers */
	CK_FUNCTION_LIST_PTR callbacks;

	/* Session Handler - Four Different handlers */
	CK_SESSION_HANDLE session;
	/*
	CK_SESSION_HANDLE encrypt;
	CK_SESSION_HANDLE decrypt;
	CK_SESSION_HANDLE sign;
	CK_SESSION_HANDLE info;
	*/

	/* Loging status */
	int logged_in;

	/* Current Slot ID */
	CK_SLOT_ID slot_id;

	/* Current Slot & Token (in slot_info.token) Info */
	HSM_SLOT_INFO slot_info;

	/* PKCS11 Operations Mutex */
	pthread_mutex_t pkcs11_mutex;
	pthread_cond_t pkcs11_cond;

} PKCS11_HANDLER;

HSM * HSM_PKCS11_new( PKI_CONFIG *conf );
int HSM_PKCS11_free ( HSM *driver, PKI_CONFIG *conf );

int HSM_PKCS11_login ( HSM *driver, PKI_CRED *cred );
int HSM_PKCS11_logout ( HSM *driver );

int HSM_PKCS11_init ( HSM *driver, PKI_CONFIG *conf );
int HSM_PKCS11_sign_algor_set (HSM *hsm, PKI_ALGOR *algor);

int HSM_PKCS11_set_fips_mode ( const HSM *driver, int k);
int HSM_PKCS11_is_fips_mode( const HSM *driver );

/*
PKI_MEM * HSM_PKCS11_sign (PKI_MEM *der, PKI_X509_KEYPAIR *key,
                                                PKI_DIGEST_ALG *digest);
int HSM_PKCS11_sign (PKI_OBJTYPE type, 
				void *x, 
				void *it_pp, 
				PKI_ALGOR *alg,
				PKI_STRING *bit,
				PKI_X509_KEYPAIR *key, 
				PKI_DIGEST_ALG *digest, 
				HSM *driver );
*/

int HSM_PKCS11_verify ( PKI_OBJTYPE type, void *x, 
					PKI_X509_KEYPAIR *key, HSM *hsm );

unsigned long HSM_PKCS11_SLOT_num(HSM * hsm);
HSM_SLOT_INFO * HSM_PKCS11_SLOT_INFO_get ( unsigned long num, HSM *hsm );
void HSM_PKCS11_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm );
int HSM_PKCS11_SLOT_select ( unsigned long num, PKI_CRED *cred, HSM *hsm);
int HSM_PKCS11_SLOT_clear (unsigned long slot_id, PKI_CRED *cred, HSM *driver);

#endif
