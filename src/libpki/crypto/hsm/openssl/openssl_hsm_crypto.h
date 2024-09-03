/* libpki/crypto/hsm/openssl/openssl_hsm.h */

#ifndef _LIBPKI_CRYPTO_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_H
#define _LIBPKI_CRYPTO_HSM_OPENSSL_H

BEGIN_C_DECLS

const HSM_CRYPTO_CALLBACKS c_openssl_hsm_crypto_cb = {
	// ---- Error Handling Functions ---- //
	HSM_OPENSSL_get_errno, // get_errno
	HSM_OPENSSL_get_errdesc, // get_errdesc
	// ---- Key Management Functions ---- //
	NULL, // keypair_gen
	NULL, // keypair_free
	NULL, // keypair_get
	// ---- General Crypto Functions ---- //
	NULL, // sign
	NULL, // verify
	NULL, // encrypt
	NULL, // decrypt
	NULL  // derive
};

// typedef struct hsm_crypto_cb_st {
  
//   /* ------------- HSM Management functions --------------- */

//   /* Get Error number */
//   unsigned long (*get_errno)(const void * driver);

//   /* Get Error Description */
//   char * (*get_errdesc)(unsigned long err, char *str, size_t size, const void * driver);

//   /* ------------- Key Management functions --------------- */

//   /* Create (new) Keypair */
//   int (*keypair_gen)(void ** out, const CRYPTO_KEYPARAMS * params, const char * label, void * driver);

//   /* Free memory associated with a keypair */
//   void (*keypair_free)(void * key, void * driver);

//   /* Retrieve the keypair data */
//   int (*keypair_get)(byte ** pub, size_t * pub_size, byte ** priv, size_t * priv_size,
//               void * key, void * driver);

//   /* ------------- Crypto functions --------------- */

//   /* \brief General Sign Function */
  
//   int (*sign)(byte ** sig, size_t * sig_sz, const byte * data, size_t data_sz,
// 					    const void * hsm_key,	const void * hsm_driver);
  
//   /* \brief General Verify Function */
//   int (*verify)(const byte * sig, size_t sig_sz, const byte * data, size_t data_sz,
//                 const void * hsm_key, const void * hsm_driver);

//   /* \brief General Encrypt Function */
//   int (*encrypt)(byte ** out, size_t * out_sz, const byte * data, size_t data_sz,
//                 const void * hsm_key, const void * hsm_driver);
  
//   /* \brief General Decrypt Function */
//   int (*decrypt)(byte ** out, size_t out_sz, const byte * data, size_t data_sz, 
//                 const void * hsm_key, const void * hsm_driver);
  
//   /* \brief General Derive Function */
//   int (*derive)(void ** hsm_key, const void * key_share_a, const void * key_share_b,
//                 const char *digest_alg, const void * driver);
  
// } HSM_CRYPTO_CALLBACKS;

						// ====================
						// Functions Prototypes
						// ====================

unsigned long HSM_OPENSSL_get_errno(const void * driver);

char * HSM_OPENSSL_get_errdesc(unsigned long   err,
							   char          * str,
							   size_t          str_sz,
							   const void    * driver);

int HSM_OPENSSL_keygen(void                   ** hsm_key, 
					   const CRYPTO_KEYPARAMS  * params,
					   const char              * label,
					   void                    * hsm_driver);

int HSM_OPENSSL_keyfree(void * hsm_key, void * hsm_driver);

int HSM_OPENSSL_sign(byte       ** sig,
					 size_t      * sig_sz,
					 const byte  * data,
					 size_t        data_sz,
				     const void  * hsm_key,
					 const void  * hsm_driver);

int HSM_OPENSSL_verify(const byte * sig,
					   size_t       sig_sz,
					   const byte * data,
					   size_t       data_sz,
                 	   const void * hsm_key,
					   const void * hsm_driver);

int HSM_OPENSSL_encrypt(byte       ** out, 
						size_t      * out_sz,
						const byte  * data,
						size_t        data_sz,
                		const void  * hsm_key,
						const void  * hsm_driver);

int HSM_OPENSSL_decrypt(byte       ** out,
						size_t        out_sz,
						const byte  * data,
						size_t        data_sz, 
                 		const void  * hsm_key,
						const void  * hsm_driver);

// int HSM_OPENSSL_derive(const unsigned char  * out, 
//                size_t                 out_sz, 
//                const unsigned char  * sig, 
//                size_t                 sig_sz,
// 			   const void           * driver_key,
// 			   const void           * hsm);

END_C_DECLS 

#endif
