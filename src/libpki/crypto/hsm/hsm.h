/* HSM API */

#ifndef _LIBPKI_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_H
#define _LIBPKI_CRYPTO_HSM_H

/* ----------------------- HSM Management ---------------------------- */

HSM *HSM_new(const char * const dir, const char * const name );

HSM *HSM_new_fips(const char * const dir, const char * const name);

const HSM *HSM_get_default( void );

int HSM_free ( HSM *hsm );

int HSM_init( HSM *hsm );

int HSM_init_fips (HSM *hsm);

int HSM_set_fips_mode(const HSM *hsm, int k);

int HSM_is_fips_mode(const HSM *hsm);

/* ---------------------- Slot Management Functions ----------------------- */

unsigned long HSM_SLOT_num ( HSM *hsm );
int HSM_SLOT_select(unsigned long num, PKI_CRED *cred, HSM *hsm );
int HSM_SLOT_clear(unsigned long num, PKI_CRED *cred, HSM *hsm );

HSM_SLOT_INFO * HSM_SLOT_INFO_get ( unsigned long num, HSM *hsm );
int HSM_SLOT_INFO_print( unsigned long num, PKI_CRED *cred, HSM *hsm );
void HSM_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm );

int HSM_SLOT_wrap(byte ** out, size_t * out_size, PKI_CRED *cred, void * driver_raw_key, HSM *hsm);
int HSM_SLOT_unwrap(void * driver_raw_key, byte * in, size_t * in_size, PKI_CRED *cred, HSM *hsm);

int HSM_SLOT_keypair_del(void * driver_raw_key, HSM *hsm );
int HSM_SLOT_keypair_new(CRYPTO_KEYPARAMS * params, HSM *hsm);

int HSM_SLOT_objects_del(byte * label, PKI_CRED *cred, HSM *hsm);
int HSM_SLOT_objects_get(PKI_STACK ** sk, PKI_TYPE type, byte * label, PKI_TYPE format, HSM *hsm);

/* -------------------- Login/Logout functions ----------------------- */

int HSM_login ( HSM *hsm, PKI_CRED *cred );
int HSM_logout ( HSM *hsm );

unsigned long HSM_get_errno ( const HSM *hsm );

char *HSM_get_errdesc ( unsigned long err, const HSM *hsm );

/* ------------------ Signing Functions Prototypes ------------------- */

int HSM_sign(const unsigned char   * data, 
             size_t                  data_sz, 
             unsigned char        ** sig, 
             size_t                * sig_sz,
			 void  				   * driver_key,
			 HSM                   * hsm);

int HSM_verify(const unsigned char  * data, 
               size_t                 data_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_derive(const unsigned char  * out, 
               size_t                 out_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_encrypt(const unsigned char * data, 
               size_t                 data_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_decrypt(const unsigned char  * data, 
               size_t                 data_len, 
               const unsigned char  * sig, 
               size_t                 sig_len,
			   void  			    * driver_key,
			   HSM                  * hsm);


// // int PKI_X509_sign (PKI_X509 *x, 
// // 		   const PKI_DIGEST_ALG *alg,
// // 		   const PKI_X509_KEYPAIR *key );

// // PKI_MEM *PKI_sign (const PKI_MEM *der,
// // 		   const PKI_DIGEST_ALG *alg,
// // 		   const PKI_X509_KEYPAIR *key );

// // int PKI_X509_verify(const PKI_X509 *x, 
// // 		    const PKI_X509_KEYPAIR *key );

// // int PKI_X509_verify_cert(const PKI_X509 *x,
// // 			 const PKI_X509_CERT *cert );

// // int PKI_verify_signature(const PKI_MEM  			* data,
// // 				 		 const PKI_MEM              * sig,
// // 						 const PKI_X509_ALGOR_VALUE * alg,
// // 						 const ASN1_ITEM            * it,
// // 						 const PKI_X509_KEYPAIR     * key );

// // // /* ------------------- PKI Object Retrieval ( Get ) ----------------------- */

// // // PKI_X509_STACK *HSM_X509_STACK_get_url ( PKI_DATATYPE type, URL *url,
// // // 					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

// // // /* --------------------- PKI Object Import ( Put ) ------------------------ */

// // // int HSM_X509_STACK_put_url ( PKI_X509_STACK *sk, URL *url,
// // //                     PKI_CRED *cred, HSM *hsm );

// // // int HSM_MEM_STACK_put_url ( PKI_MEM_STACK *sk, URL *url, PKI_DATATYPE type,
// // //                     PKI_CRED *cred, HSM *hsm );

// // // /* --------------------- PKI Object Delete ( Del ) ------------------------ */

// // // int HSM_X509_STACK_del ( PKI_X509_STACK *sk );

// // // int HSM_X509_del_url ( PKI_DATATYPE type, URL *url, PKI_CRED *cred, HSM *hsm );

// // // const PKI_X509_CALLBACKS * HSM_X509_get_cb ( PKI_DATATYPE type, HSM *hsm );

// #endif
// /* HSM Object Management Functions */

// /* ----------------------- HSM Management ---------------------------- */

// unsigned long HSM_get_errno ( const HSM *hsm );
// char *HSM_get_errdesc ( unsigned long err, const HSM *hsm );

// const HSM *HSM_get_default( void );

// int HSM_free ( HSM *hsm );

// HSM *HSM_new(const char * const dir, const char * const name );
// HSM *HSM_new_fips(const char * const dir, const char * const name);

// int HSM_init( HSM *hsm );
// int HSM_init_fips (HSM *hsm);

// int HSM_is_fips_mode(const HSM *hsm);
// int HSM_set_fips_mode(const HSM *hsm, int k);

// /* -------------------- Login/Logout functions ----------------------- */

// int HSM_login ( HSM *hsm, PKI_CRED *cred );
// int HSM_logout ( HSM *hsm );
// int HSM_set_sign_algor (PKI_X509_ALGOR_VALUE *alg, HSM *hsm );

// /* ------------------ Signing Functions Prototypes ------------------- */

// int PKI_X509_sign (PKI_X509 *x, 
// 		   const PKI_DIGEST_ALG *alg,
// 		   const PKI_X509_KEYPAIR *key );

// PKI_MEM *PKI_sign (const PKI_MEM *der,
// 		   const PKI_DIGEST_ALG *alg,
// 		   const PKI_X509_KEYPAIR *key );

// int PKI_X509_verify(const PKI_X509 *x, 
// 		    const PKI_X509_KEYPAIR *key );

// int PKI_X509_verify_cert(const PKI_X509 *x,
// 			 const PKI_X509_CERT *cert );

// int PKI_verify_signature(const PKI_MEM  			* data,
// 				 		 const PKI_MEM              * sig,
// 						 const PKI_X509_ALGOR_VALUE * alg,
// 						 const ASN1_ITEM            * it,
// 						 const PKI_X509_KEYPAIR     * key );

// /* ------------------- PKI Object Retrieval ( Get ) ----------------------- */

// PKI_X509_STACK *HSM_X509_STACK_get_url ( PKI_DATATYPE type, URL *url,
// 					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

// /* --------------------- PKI Object Import ( Put ) ------------------------ */

// int HSM_X509_STACK_put_url ( PKI_X509_STACK *sk, URL *url,
//                     PKI_CRED *cred, HSM *hsm );

// int HSM_MEM_STACK_put_url ( PKI_MEM_STACK *sk, URL *url, PKI_DATATYPE type,
//                     PKI_CRED *cred, HSM *hsm );

// /* --------------------- PKI Object Delete ( Del ) ------------------------ */

// int HSM_X509_STACK_del ( PKI_X509_STACK *sk );

// int HSM_X509_del_url ( PKI_DATATYPE type, URL *url, PKI_CRED *cred, HSM *hsm );

// const PKI_X509_CALLBACKS * HSM_X509_get_cb ( PKI_DATATYPE type, HSM *hsm );

// /* ---------------------- Slot Management Functions ----------------------- */

// unsigned long HSM_SLOT_num ( HSM *hsm );
// int HSM_SLOT_select ( unsigned long num, PKI_CRED *cred, HSM *hsm );
// int HSM_SLOT_clear ( unsigned long num, PKI_CRED *cred, HSM *hsm );

// HSM_SLOT_INFO * HSM_SLOT_INFO_get ( unsigned long num, HSM *hsm );
// int HSM_SLOT_INFO_print( unsigned long num, PKI_CRED *cred, HSM *hsm );
// void HSM_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm );

// /* -------------------- Key Management Functions --------------------- */

// /* Generate a new Keypair */
// PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new( PKI_KEYPARAMS *params, char *label,
//                                         PKI_CRED *cred, HSM *hsm );

// PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new_url( PKI_KEYPARAMS *params, URL *url,
//                                         PKI_CRED *cred, HSM *driver );

// /* --------------------------- Wrap/Unwrap ---------------------------- */

// PKI_MEM *HSM_X509_KEYPAIR_wrap ( PKI_X509_KEYPAIR *key, PKI_CRED *cred );

// PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_unwrap ( PKI_MEM *mem,
// 				URL *url, PKI_CRED *cred, HSM *hsm );

#endif /* _LIBPKI_CRYPTO_HSM_H */
