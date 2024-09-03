/* openssl/pki_pkey.c */

#include <libpki/crypto/hsm/openssl/openssl_hsm_store.h>

const HSM_STORE_CALLBACKS c_openssl_hsm_crypto_cb = {
	NULL, // store_num
	NULL, // store_info_get
	NULL, // store_info_free
	NULL, // select_slot
	NULL, // clear_slot
	NULL, // get_objects
	NULL, // add_objects
	NULL, // del_objects
	NULL, // key_wrap
	NULL  // key_unwrap
};

// typedef struct hsm_store_cb_st {
  
//   /* ----------------- Store Management functions ----------------- */
  
//   /* Get the number of available Slots */
//   unsigned long  (*store_num)(struct hsm_st *);

//   /* Get Slot info */
//   HSM_STORE_INFO   * (*store_info_get)(unsigned long, struct hsm_st *);

//   /* Free memory associated with an HSM_STORE_INFO structure */
//   void (*store_info_free) (HSM_STORE_INFO *, struct hsm_st *);

//   /* Set the current slot */
//   int (*select_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

//   /* Clear the current slot from any object present */
//   int (*clear_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

//   /* -------------- Object Management functions -------------------- */

//   int (*get_objects)(PKI_STACK ** sk, PKI_TYPE type, byte * label, PKI_TYPE format, 
//             void *driver);

//   int (*add_objects)(const PKI_STACK * sk, PKI_TYPE type, byte * label, PKI_TYPE format,
//             void *driver);

//   int (*del_objects)(PKI_TYPE type, byte * label, void *driver);

//   /* Key Wrapping function */
//   int (*key_wrap)(byte ** out, size_t *out_len, const char * label, size_t label_sz, char * wrappingkey_label, size_t wrappingkey_label_sz, void * driver);

//   /* Key Unwrapping function */
//   int (*key_unwrap)(CRYPTO_KEYPAIR ** key, const byte * data, size_t data_sz, const byte * label, size_t label_size,
//             const char * wrappingkey_label, size_t wrappingkey_label_sz, void * driver);

// } HSM_STORE_CALLBACKS;


