/* hsm/types.h */

/* Configuration options:
 *
 */


#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_TYPES_H
#define _LIBPKI_CRYPTO_HSM_TYPES_H

BEGIN_C_DECLS

#ifndef typedef byte
typedef unsigned char byte;
#endif

// Forward declaration for the HSM structure
typedef struct pki_config_st PKI_CONFIG;
typedef struct pki_cred_st PKI_CRED;
typedef struct pki_mem_st PKI_MEM;

typedef struct crypto_keyparams_st CRYPTO_KEYPARAMS;
typedef struct crypto_keypair_st CRYPTO_KEYPAIR;

/* \brief HSM Manufacturer ID Size */
#define HSM_MANUFACTURER_ID_SIZE   32

/* \brief HSM Description Size */
#define HSM_DESCRIPTION_SIZE       32

/* \brief HSM Slot Description Size */
#define HSM_STORE_DESCRIPTION_SIZE  64

/* \brief HSM Label Size */
#define HSM_LABEL_SIZE             32

/* \brief HSM Model Size */
#define HSM_MODEL_SIZE             16

/* \brief HSM Serial Number Size */
#define HSM_SERIAL_NUMBER_SIZE     16

/* \brief HSM UTC Time Size */
#define HSM_UTC_TIME_SIZE          16

/* \brief HSM Types */
typedef enum {
  HSM_TYPE_OTHER    = 0,
  HSM_TYPE_SOFTWARE,
  HSM_TYPE_PKCS11
} HSM_TYPE;

/* \brief HSM Key Pair Handlers' Indexes */
typedef enum hsm_keypair_handler_idx {
  KEYPAIR_DRIVER_HANDLER_IDX  = 0,
  KEYPAIR_PRIVKEY_HANDLER_IDX,
  KEYPAIR_PUBKEY_HANDLER_IDX
} HSM_KEYPAIR_HANDLER;

/* \brief HSM Info Data Structure */
typedef struct hsm_info_st {
  
  /* \brief HSM Version Major Number */
  unsigned short version_major;

  /* \brief HSM Version Minor Number */
  unsigned short version_minor;

  /* \brief HSM Manufacturer ID */
  char manufacturerID[HSM_MANUFACTURER_ID_SIZE];

  /* \brief HSM Description */
  char description[HSM_DESCRIPTION_SIZE];

  /* \brief HSM Library Version Major Number */
  unsigned short lib_version_major;

  /* \brief HSM Library Version Minor Number */
  unsigned short lib_version_minor;

  /* \brief HSM Fips Mode of Operation */
  int fips_mode;

} HSM_INFO;

/* \brief HSM Token Info Data Structure */
typedef struct hsm_token_info_st {

  /* \brief Token Label */
  char label[HSM_LABEL_SIZE];

  /* \brief Token Manufacturer ID */
  char manufacturerID[HSM_DESCRIPTION_SIZE];

  /* \brief Token Model */
  char model[HSM_MODEL_SIZE];

  /* \brief Serial Number */
  char serialNumber[HSM_SERIAL_NUMBER_SIZE];

  /* \brief Max Supported Sessions */
  unsigned long max_sessions;

  /* \brief Current Number of Sessions */
  unsigned long curr_sessions;

  /* \brief Maximum Pin Length */
  unsigned long max_pin_len;

  /* \brief Minimum Supported Pin Length */
  unsigned long min_pin_len;

  /* \brief Public Memory Total Size */
  unsigned long memory_pub_tot;

  /* \brief Available Public Memory Size */
  unsigned long memory_pub_free;

  /* \brief Private Memory Total Size */
  unsigned long memory_priv_tot;

  /* \brief Available Private Memory Size */
  unsigned long memory_priv_free;

  /* \brief Hardware Version Major Number */
  unsigned short hw_version_major;

  /* \brief Hardware Version Minor Number */
  unsigned short hw_version_minor;

  /* \brief Firmware Version Major Number */
  unsigned short fw_version_major;

  /* \brief Firmware Version Minor Number */
  unsigned short fw_version_minor;

  /* \brief Requires Login */
  unsigned short login_required;

  /* \brief Provides Random Number Generation */
  unsigned short has_rng;

  /* \brief Provides Clock Time */
  unsigned short has_clock;

  /* \brief Token UTC Time */
  char utcTime[HSM_UTC_TIME_SIZE];

} HSM_TOKEN_INFO;

/* \brief HSM Slot Info Data Structure */
typedef struct HSM_STORE_info_st {

  /* \brief Device Manufacturer ID */
  char manufacturerID[HSM_MANUFACTURER_ID_SIZE];

  /* \brief Device Description */
  char description[HSM_STORE_DESCRIPTION_SIZE];

  /* \brief Hardware Version */
  unsigned short hw_version_major;
  unsigned short hw_version_minor;

  /* \brief Firmware Version */
  unsigned short fw_version_major;
  unsigned short fw_version_minor;

  /* \brief Is the Slot Initialized? */
  unsigned short initialized;

  /* \brief Does the Slot have a valid token? */
  unsigned short present;

  /* \brief Is the Slot removable? */
  unsigned short removable;

  /* \brief Is the Slot a hardware Slot? */
  unsigned short hardware;

  /* \brief Info for the current inserted token */
  HSM_TOKEN_INFO token_info;

} HSM_STORE_INFO;

typedef struct hsm_admin_cb_st {
  
  /* ------------- HSM Management functions --------------- */

  /* HSM driver new function */
  int (*new) (void ** driver, const PKI_CONFIG * config);

  /* HSM initialization function */
  int (*init) (void * driver, const PKI_CONFIG * config);

  /* HSM driver free function */
  int (*free) (void * driver);

  /* HSM login */
  int (*login)(void * driver, PKI_CRED *cred);

  /* HSM logout */
  int (*logout)(void * driver);

  /* HSM set algor function */
  int (*sign_algor) (void * driver, unsigned char * oid);

  /* HSM set fips mode */
  int (*set_fips_mode) (const void * driver, int enabled);

  /* HSM gets fips operation mode */
  int (*is_fips_mode) (const void * driver);

} HSM_ADMIN_CALLBACKS;

typedef struct hsm_store_cb_st {
  
  /* ----------------- Store Management functions ----------------- */
  
  /* Get the number of available Slots */
  unsigned long  (*store_num)(struct hsm_st *);

  /* Get Slot info */
  HSM_STORE_INFO   * (*store_info_get)(unsigned long, struct hsm_st *);

  /* Free memory associated with an HSM_STORE_INFO structure */
  void (*store_info_free) (HSM_STORE_INFO *, struct hsm_st *);

  /* Set the current slot */
  int (*select_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

  /* Clear the current slot from any object present */
  int (*clear_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

  /* -------------- Object Management functions -------------------- */

  int (*get_objects)(PKI_STACK ** sk, PKI_TYPE type, byte * label, PKI_TYPE format, 
            void *driver);

  int (*add_objects)(const PKI_STACK * sk, PKI_TYPE type, byte * label, PKI_TYPE format,
            void *driver);

  int (*del_objects)(PKI_TYPE type, byte * label, void *driver);

  /* Key Wrapping function */
  int (*key_wrap)(byte ** out, size_t *out_len, const char * label, size_t label_sz, char * wrappingkey_label, size_t wrappingkey_label_sz, void * driver);

  /* Key Unwrapping function */
  int (*key_unwrap)(CRYPTO_KEYPAIR ** key, const byte * data, size_t data_sz, const byte * label, size_t label_size,
            const char * wrappingkey_label, size_t wrappingkey_label_sz, void * driver);

} HSM_STORE_CALLBACKS;

typedef struct hsm_crypto_cb_st {
  
  /* ------------- HSM Management functions --------------- */

  /* Get Error number */
  unsigned long (*get_errno)(const void * driver);

  /* Get Error Description */
  char * (*get_errdesc)(unsigned long err, char *str, size_t size, const void * driver);

  /* ------------- Key Management functions --------------- */

  /* Create (new) Keypair */
  int (*keypair_gen)(void ** out, const CRYPTO_KEYPARAMS * params, const char * label, void * driver);

  /* Free memory associated with a keypair */
  void (*keypair_free)(void * key, void * driver);

  /* Retrieve the keypair data */
  int (*keypair_get)(byte ** pub, size_t * pub_size, byte ** priv, size_t * priv_size,
              void * key, void * driver);

  /* ------------- Crypto functions --------------- */

  /* \brief General Sign Function */
  
  int (*sign)(byte ** sig, size_t * sig_sz, const byte * data, size_t data_sz,
					    const void * hsm_key,	const void * hsm_driver);
  
  /* \brief General Verify Function */
  int (*verify)(const byte * sig, size_t sig_sz, const byte * data, size_t data_sz,
                const void * hsm_key, const void * hsm_driver);

  /* \brief General Encrypt Function */
  int (*encrypt)(byte ** out, size_t * out_sz, const byte * data, size_t data_sz,
                const void * hsm_key, const void * hsm_driver);
  
  /* \brief General Decrypt Function */
  int (*decrypt)(byte ** out, size_t out_sz, const byte * data, size_t data_sz, 
                const void * hsm_key, const void * hsm_driver);
  
  /* \brief General Derive Function */
  int (*derive)(void ** hsm_key, const void * key_share_a, const void * key_share_b,
                const char *digest_alg, const void * driver);
  
} HSM_CRYPTO_CALLBACKS;

/* Structure for HSM definition */
typedef struct hsm_st {

  /* Version of the token */
  int version;
  
  /* ID of the driver - this is used to identify the driver
     to be used, e.g., 'id://LunaCA' for loading the ENGINE
     LunaCA extension */
  char * id_label;

  /* Description of the HSM */
  char *description;

  /* Manufacturer */
  char *manufacturer;

  /* Pointer to the HSM config file and parsed structure*/
  PKI_CONFIG *config;

  /* One of PKI_HSM_TYPE value */
  HSM_TYPE type;

  /* Pointer to the internal structure for drivers */
  void *driver;
 
  /* Pointer to internal session handler */
  void *session;

  /* Credential for the HSM - usually used for the SO */
  PKI_CRED *cred;

  /* Is Logged In */
  uint8_t isLoggedIn;

  /* Is Cred Set */
  uint8_t isCredSet;

  /* Login Requirements */
  const uint8_t isLoginRequired;

  /* HSM Callbacks */
  const HSM_ADMIN_CALLBACKS *admin_callbacks;
  const HSM_STORE_CALLBACKS *store_callbacks;
  const HSM_CRYPTO_CALLBACKS *crypto_callbacks;

} HSM;

END_C_DECLS

#endif

