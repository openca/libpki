
#ifndef _LIBPKI_URL_H
# include <libpki/net/url.h>
#endif

#ifndef _LIBPKI_PKI_CONFIG_H
# include <libpki/pki_config.h>
#endif

#ifndef _LIBPKI_PKI_X509_DATATYPES_ST_H
# include <libpki/pki_x509_data_st.h>
#endif

#ifndef _LIBPKI_HSM_ST_H
#define _LIBPKI_HSM_ST_H

#define MANUFACTURER_ID_SIZE   32
#define DESCRIPTION_SIZE       32
#define SLOT_DESCRIPTION_SIZE  64
#define LABEL_SIZE             32
#define MODEL_SIZE             16
#define SERIAL_NUMBER_SIZE     16
#define UTC_TIME_SIZE          16

typedef enum {
  HSM_TYPE_OTHER    = 0,
  HSM_TYPE_SOFTWARE,
  HSM_TYPE_ENGINE,
  HSM_TYPE_KMF,
  HSM_TYPE_PKCS11
} PKI_HSM_TYPE;

typedef enum {
  PKI_OBJTYPE_UNKNOWN   = 0,
  PKI_OBJTYPE_X509_KEYPAIR,
  PKI_OBJTYPE_X509_CERT,
  PKI_OBJTYPE_X509_REQ,
  PKI_OBJTYPE_X509_CRL,
  PKI_OBJTYPE_PKCS7,
  PKI_OBJTYPE_PKCS12,
  PKI_OBJTYPE_PKI_MSG,
  PKI_OBJTYPE_SCEP_MSG,
  PKI_OBJTYPE_CMS_MSG,
  PKI_OBJTYPE_PKI_PRQP_REQ,
  PKI_OBJTYPE_PKI_PRQP_RESP
} PKI_OBJTYPE;

typedef enum {
  KEYPAIR_DRIVER_HANDLER_IDX  = 0,
  KEYPAIR_PRIVKEY_HANDLER_IDX,
  KEYPAIR_PUBKEY_HANDLER_IDX
} KEYPAIR_HSM_HANDLER;

/* HSM_INFO Data Structure */
typedef struct hsm_info_st {

  /* HSM Version */
  unsigned short version_major;
  unsigned short version_minor;

  /* HSM Manufacturer ID */
  char manufacturerID[MANUFACTURER_ID_SIZE];

  /* HSM Description */
  char description[DESCRIPTION_SIZE];

  /* HSM Library Version */
  unsigned short lib_version_major;
  unsigned short lib_version_minor;

  /* HSM Supported Modes */
  int fips_mode;

} HSM_INFO;

typedef struct hsm_token_info_st {

  /* Token Label */
  char label[LABEL_SIZE];

  /* Token Manifacturer ID */
  char manufacturerID[DESCRIPTION_SIZE];

  /* Token Model */
  char model[MODEL_SIZE];

  /* Serial Number */
  char serialNumber[SERIAL_NUMBER_SIZE];

  /* Max Supported Sessions */
  unsigned long max_sessions;

  /* Current Number of Sessions */
  unsigned long curr_sessions;

  /* Maximum Pin Length */
  unsigned long max_pin_len;

  /* Minimum Supported Pin Length */
  unsigned long min_pin_len;

  /* Public Memory Total Size */
  unsigned long memory_pub_tot;

  /* Available Public Memory Size */
  unsigned long memory_pub_free;

  /* Private Memory Total Size */
  unsigned long memory_priv_tot;

  /* Available Private Memory Size */
  unsigned long memory_priv_free;

  /* Hardware Version Major Number */
  unsigned short hw_version_major;

  /* Hardware Version Minor Number */
  unsigned short hw_version_minor;

  /* Firmware Version Major Number */
  unsigned short fw_version_major;

  /* Firmware Version Minor Number */
  unsigned short fw_version_minor;

  /* Requires Login */
  unsigned short login_required;

  /* Provides Random Number Generation */
  unsigned short has_rng;

  /* Provides Clock Time */
  unsigned short has_clock;

  /* Token UTC Time */
  char utcTime[UTC_TIME_SIZE];

} HSM_TOKEN_INFO;

/* HSM_SLOT_INFO Data Structure */
typedef struct hsm_slot_info_st {

  /* Device Manufacturer ID */
  char manufacturerID[MANUFACTURER_ID_SIZE];

  /* Device Description */
  char description[SLOT_DESCRIPTION_SIZE];

  /* Hardware Version */
  unsigned short hw_version_major;
  unsigned short hw_version_minor;

  /* Firmware Version */
  unsigned short fw_version_major;
  unsigned short fw_version_minor;

  /* Is the Slot Initialized ? */
  unsigned short initialized;

  /* Does the Slot have a valid token ? */
  unsigned short present;

  /* Is the Slot removable ? */
  unsigned short removable;

  /* Is the Slot an hardware Slot ? */
  unsigned short hardware;

  /* Info for the current inserted token */
  HSM_TOKEN_INFO token_info;

} HSM_SLOT_INFO;

/* Forward Declarations */
struct hsm_st;
// typedef struct hsm_st HSM;

struct pki_mem_st;
// typedef struct pki_mem_st PKI_MEM;

#ifndef _LIBPKI_PKI_X509_DATA_ST_H

  /* Forward Declaration for PKI_X509 structure */
  struct pki_x509_st;
//  typedef struct pki_x509_st PKI_X509;

  /* Forward Definition for PKI_X509_CERT */
  #define PKI_X509_CERT PKI_X509

  /* Forward Declaration of URL structure */
  struct url_data_st;
//  typedef struct url_data_st URL;

  /* Forward Declaration of PKI_STACK and PKI_X509_STACK */
  struct pki_stack_st;
//  typedef struct pki_stack_st PKI_STACK;
//  typedef PKI_STACK PKI_X509_STACK;

  /* Forward Declaration of PKI_X509_CALLBACKS structure */
  struct pki_x509_callbacks_st;
//  typedef struct pki_x509_callbacks_st PKI_X509_CALLBACKS;

  /* Forward Declaration of PKI_X509_PROFILE structure */
  struct _xmlDoc;
//  typedef struct xmlDoc PKI_X509_PROFILE;

#endif

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
  int (*sign_algor) (struct hsm_st *driver, PKI_X509_ALGOR_VALUE *algor);

  /* HSM set fips mode */
  int (*set_fips_mode) (const struct hsm_st *driver, int k);

  /* HSM gets fips operation mode */
  int (*is_fips_mode) (const struct hsm_st *driver);

  /* ------------- Signing functions --------------- */
  /* General Signing function */
  PKI_MEM * (*sign) (const PKI_MEM *, const PKI_DIGEST_ALG *, PKI_X509_KEYPAIR *);

  /* ASN.1 Signing function */
  PKI_MEM * (*sign_asn1) (const PKI_X509 *, const PKI_DIGEST_ALG *, PKI_X509_KEYPAIR *);

  /* General Verify Function */
  int (*verify)(const PKI_MEM *, const PKI_MEM *, PKI_X509_ALGOR_VALUE *, PKI_X509_KEYPAIR * );

  /* ASN.1 Verify Function */
  int (*verify_asn1)(const PKI_X509 *, const PKI_X509_KEYPAIR *);

  /* ------------- Key Management functions --------------- */

  /* Create (new) Keypair */
  PKI_X509_KEYPAIR * (*keypair_new_url)( PKI_KEYPARAMS *, URL *, PKI_CRED *, 
              struct hsm_st *);

  /* Free memory associated with a keypair */
  void    (*keypair_free)(PKI_X509_KEYPAIR *);

  /* Key Wrapping function */
  PKI_MEM *  (*key_wrap)(PKI_X509_KEYPAIR *, PKI_CRED *);

  /* Key Unwrapping function */
  PKI_X509_KEYPAIR *(*key_unwrap)( PKI_MEM *, URL *url,
            PKI_CRED *, struct hsm_st *);

  /* -------------- Object Management functions -------------------- */

  /* Retrieve (get) stack of objects */
  PKI_X509_STACK * (*x509_sk_get_url)( PKI_DATATYPE, URL *, 
            PKI_DATA_FORMAT, PKI_CRED *, struct hsm_st *);
  /* Import (add) stack of objects */
  int (*x509_sk_add_url)(PKI_X509_STACK *, URL *, 
            PKI_CRED *, struct hsm_st *);
  /* Erase (del) stack of objects */
  int (*x509_del_url)( PKI_DATATYPE, URL *, PKI_CRED *, struct hsm_st *);

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

  /* Get X509 callbacks */
  const PKI_X509_CALLBACKS * (*x509_get_cb)(PKI_DATATYPE type );

} HSM_CALLBACKS;

/* Structure for HSM definition */
typedef struct hsm_st {

  /* Version of the token */
  int version;

  /* Description of the HSM */
  char *description;

  /* Manufacturer */
  char *manufacturer;

  /* Pointer to the HSM config file and parsed structure*/
  PKI_CONFIG *config;

  /* One of PKI_HSM_TYPE value */
  PKI_HSM_TYPE type;

  /* ID of the driver - this is used to identify the driver
     to be used, e.g., 'id://LunaCA' for loading the ENGINE
     LunaCA extension */
  URL *id;

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

/* End of _LIBPKI_HSM_ST_H */
#endif
