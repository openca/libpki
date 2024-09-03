/* openssl/pki_pkey.c */

#include <libpki/crypto/hsm/openssl/openssl_hsm_store.h>

const HSM_STORE_CALLBACKS c_openssl_hsm_store_cb = {
	NULL, // store_num
	HSM_OPENSSL_STORE_INFO_get, // store_info_get
	free, // store_info_free
	NULL, // select_slot
	NULL, // clear_slot
	NULL, // get_objects
	NULL, // add_objects
	NULL, // del_objects
	NULL, // key_wrap
	NULL  // key_unwrap
};

HSM_STORE_INFO openssl_slot_info = {

	/* Device Manufacturer ID */
	"OpenSSL",

	/* Device Description */
	"Software interface",

	/* Hardware Version */
	1,
	0,

	/* Firmware Version */
	1,
	0,

	/* Initialized */
	1,

	/* Present */
	1,

	/* Removable */
	0,

	/* Hardware */
	0,

	/* Token Info */
	{
		/* Token Label */
		"Unknown Label\x0                ",
		/* ManufacturerID */
		"Unknown\x0                      ",
		/* Model */
		"Unknown\x0        ",
		/* Serial Number */
		"0\x0              ",
		/* Max Sessions */
		65535,
		/* Current Sessions */
		0,
		/* Max Pin Len */
		0,
		/* Min Pin Len */
		0,
		/* Memory Pub Total */
		0,
		/* Memory Pub Free */
		0,
		/* Memory Priv Total */
		0,
		/* Memory Priv Free */
		0,
		/* HW Version Major */
		1,
		/* HW Version Minor */
		0,
		/* FW Version Major */
		1,
		/* FW Version Minor */
		0,
		/* HAS Random Number Generator (RNG) */
		1,
		/* HAS clock */
		0,
		/* Login is Required */
		0,
		/* utcTime */
		""
	}
};

/* ---------------------- OPENSSL Slot Management Functions ---------------- */

HSM_STORE_INFO * HSM_OPENSSL_STORE_INFO_get (unsigned long num, HSM *hsm) {

	HSM_STORE_INFO *ret = NULL;

	ret = (HSM_STORE_INFO *) PKI_Malloc ( sizeof (HSM_STORE_INFO));
	memcpy( ret, &openssl_slot_info, sizeof( HSM_STORE_INFO ));

	return (ret);
}

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


