/* HSM Object Management Functions */

#ifndef _LIBPKI_HSM_MAIN_H
#define _LIBPKI_HSM_MAIN_H
# pragma once

// LibPKI Includes
#include <libpki/hsm_st.h>
#include <libpki/pki_x509_data_st.h>
#include <libpki/pki_mem.h>

BEGIN_C_DECLS

/* Added MACRO to ease usage of the general signature function PKI_sign() */
/*
#define PKI_OBJ_sign( t,x,k,d ) PKI_sign (t,x,NULL,NULL,NULL,k,d)

#define PKI_ITEM_sign(t,x,i,a,b,k,d,h) \
		PKI_sign(t,x,(void *) ASN1_ITEM_rptr(i),a,b,k,d)
#define PKI_verify(it,alg,sig,data,key) \
		PKI_verify_signature((void*)ASN1_ITEM_rptr(it),alg,sig,data,key)
*/

						// ====================
						// Functions Prototypes
						// ====================

/* ----------------------- HSM Management ---------------------------- */

unsigned long HSM_get_errno ( const HSM *hsm );
char *HSM_get_errdesc ( unsigned long err, const HSM *hsm );

const HSM *HSM_get_default( void );

HSM *HSM_new(const char * const dir, const char * const name );
HSM *HSM_new_fips(const char * const dir, const char * const name);
int HSM_free ( HSM *hsm );

int HSM_init( HSM *hsm );
int HSM_init_fips (HSM *hsm);

int HSM_set_fips_mode(const HSM *hsm, int k);
int HSM_is_fips_mode(const HSM *hsm);

/*
 * HSM *HSM_new_init ( char *driver, char *name, PKI_STACK *pre_cmds,
							PKI_STACK *post_cmds );
*/


/* -------------------- Login/Logout functions ----------------------- */

int HSM_login ( HSM *hsm, PKI_CRED *cred );
int HSM_logout ( HSM *hsm );
int HSM_set_sign_algor (PKI_X509_ALGOR_VALUE *alg, HSM *hsm );

/* ------------------ Signing Functions Prototypes ------------------- */

int PKI_X509_sign (PKI_X509 *x, 
		   const PKI_DIGEST_ALG *alg,
		   const PKI_X509_KEYPAIR *key );

PKI_MEM *PKI_sign (const PKI_MEM *der,
		   const PKI_DIGEST_ALG *alg,
		   const PKI_X509_KEYPAIR *key );

int PKI_X509_verify(const PKI_X509 *x, 
		    const PKI_X509_KEYPAIR *key );

int PKI_X509_verify_cert(const PKI_X509 *x,
			 const PKI_X509_CERT *cert );

int PKI_verify_signature(const PKI_MEM  			* data,
				 		 const PKI_MEM              * sig,
						 const PKI_X509_ALGOR_VALUE * alg,
						 const ASN1_ITEM            * it,
						 const PKI_X509_KEYPAIR     * key );

/* ------------------- PKI Object Retrieval ( Get ) ----------------------- */

PKI_X509_STACK *HSM_X509_STACK_get_url(const PKI_DATATYPE	   type,
									   const URL 		  	 * const url,
									   const PKI_DATA_FORMAT   format,
									   const PKI_CRED 	   	 * cred,
									   HSM 			   		 * hsm);

/* --------------------- PKI Object Import ( Put ) ------------------------ */

int HSM_X509_STACK_put_url ( PKI_X509_STACK *sk, URL *url,
                    PKI_CRED *cred, HSM *hsm );

int HSM_MEM_STACK_put_url ( PKI_MEM_STACK *sk, URL *url, PKI_DATATYPE type,
                    PKI_CRED *cred, HSM *hsm );

/* --------------------- PKI Object Delete ( Del ) ------------------------ */

int HSM_X509_STACK_del ( PKI_X509_STACK *sk );

int HSM_X509_del_url ( PKI_DATATYPE type, URL *url, PKI_CRED *cred, HSM *hsm );

const PKI_X509_CALLBACKS * HSM_X509_get_cb ( PKI_DATATYPE type, HSM *hsm );

END_C_DECLS

#endif // End of _LIBPKI_HSM_MAIN_H
