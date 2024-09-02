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

#ifndef HSM_TYPES_H
#define HSM_TYPES_H

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
#define HSM_SLOT_DESCRIPTION_SIZE  64

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
typedef struct hsm_slot_info_st {

  /* \brief Device Manufacturer ID */
  char manufacturerID[HSM_MANUFACTURER_ID_SIZE];

  /* \brief Device Description */
  char description[HSM_SLOT_DESCRIPTION_SIZE];

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

} HSM_SLOT_INFO;

typedef struct callbacks_st {
  
  /* ------------- HSM Management functions --------------- */

  /* Get Error number */
  unsigned long (*get_errno)( void );

  /* Get Error Description */
  char * (*get_errdesc)( unsigned long err, char *str, size_t size );

  /* HSM initialization function */
  int (*init) (struct hsm_st *driver, PKI_CONFIG *);

  /* HSM free function */
  int (*free) (struct hsm_st *driver, PKI_CONFIG *);

  /* HSM login */
  int (*login)(struct hsm_st *driver, PKI_CRED *cred);

  /* HSM logout */
  int (*logout)(struct hsm_st *driver);

  /* HSM set algor function */
  int (*sign_algor) (struct hsm_st *driver, unsigned char * oid);

  /* HSM set fips mode */
  int (*set_fips_mode) (const struct hsm_st *driver, int k);

  /* HSM gets fips operation mode */
  int (*is_fips_mode) (const struct hsm_st *driver);

  /* ----------------- Slot Management functions ----------------- */
  
  /* Get the number of available Slots */
  unsigned long  (*slot_num)(struct hsm_st *);

  /* Get Slot info */
  HSM_SLOT_INFO   * (*slot_info_get)(unsigned long, struct hsm_st *);

  /* Free memory associated with an HSM_SLOT_INFO structure */
  void (*slot_info_free) (HSM_SLOT_INFO *, struct hsm_st *);

  /* Set the current slot */
  int (*select_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

  /* Clear the current slot from any object present */
  int (*clear_slot)(unsigned long, PKI_CRED *cred, struct hsm_st *);

  /* -------------- Object Management functions -------------------- */

  int (*get_objects)(PKI_STACK ** sk, PKI_TYPE type, byte * label, PKI_TYPE format, 
            const PKI_CRED *cred, void *driver);

  int (*add_objects)(const PKI_STACK * sk, PKI_TYPE type, byte * label, PKI_TYPE format,
            const PKI_CRED * cred, void *driver);

  int (*del_objects)(PKI_TYPE type, byte * label, const PKI_CRED * cred, void *driver);

  /* ------------- Crypto functions --------------- */

  /* \brief General Sign Function */
  int (*sign)(unsigned char * data, size_t size, unsigned char * sig,
              size_t * sig_size, const char *digest_alg, CRYPTO_KEYPAIR *key);

  /* \brief General Verify Function */
  int (*verify)(unsigned char * data, size_t size, unsigned char * sig, size_t sig_size,
                const char *digest_alg, CRYPTO_KEYPAIR *key);

  /* ------------- Key Management functions --------------- */

  /* Create (new) Keypair */
  int (*keypair_new)(unsigned char * pub, size_t *pub_size, unsigned char * priv, size_t priv_size,
              const CRYPTO_KEYPARAMS * params, const char * label, void * driver);

  /* Free memory associated with a keypair */
  void    (*keypair_free)(CRYPTO_KEYPAIR *);

  /* Key Wrapping function */
  int (*key_wrap)(unsigned char * out, size_t *out_len, CRYPTO_KEYPAIR * key, const PKI_CRED * cred);

  /* Key Unwrapping function */
  int (*key_unwrap)(byte * wrapped_key, size_t wrapped_key_len, byte * label,
            const PKI_CRED *, void * driver);

} HSM_CALLBACKS;

/* Structure for HSM definition */
typedef struct hsm_st {

  /* ID of the driver - this is used to identify the driver
     to be used, e.g., 'id://LunaCA' for loading the ENGINE
     LunaCA extension */
  char * id_label;

  /* Version of the token */
  int version;

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
  const HSM_CALLBACKS *callbacks;

} HSM;

END_C_DECLS

#endif

