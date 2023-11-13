/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_TYPES_H
#define _LIBPKI_COMPOSITE_TYPES_H

#ifndef _LIBPKI_COMPOSITE_ASN1_H
#include <libpki/openssl/composite/composite_asn1.h>
#endif

BEGIN_C_DECLS

// ========================
// Composite Crypto Support
// ========================

// Basic CTRL values for COMPOSITE support
# define EVP_PKEY_CTRL_COMPOSITE_PUSH    0x201
# define EVP_PKEY_CTRL_COMPOSITE_POP     0x202
# define EVP_PKEY_CTRL_COMPOSITE_ADD     0x203
# define EVP_PKEY_CTRL_COMPOSITE_DEL     0x204
# define EVP_PKEY_CTRL_COMPOSITE_CLEAR   0x205

// ==============================
// Declarations & Data Structures
// ==============================

DEFINE_STACK_OF(EVP_PKEY);
  // Provides the Definition for the stack of keys

/*! \brief Stack of Composite Key Components (EVP_PKEY) */
typedef STACK_OF(EVP_PKEY) COMPOSITE_KEY_STACK;

// /*!
//  * @brief Composite Parameters to capture the OID and Key
//  *        individual parameters
//  */
// typedef struct Composite_Component_Param_st {
//   X509_ALGOR *algorithm;
//   ASN1_BOOLEAN * canSkipUnknown;
// } COMPONENT_PARAM;

// DECLARE_STACK_OF(COMPONENT_PARAM);

// typedef STACK_OF(COMPONENT_PARAM) COMPONENT_PARAMS;

typedef struct CompositeKey_Component_st {
  EVP_PKEY * pkey;
  COMPONENT_PARAMS_STACK * params;
} KEY_COMPONENT;

DEFINE_STACK_OF(KEY_COMPONENT);

typedef STACK_OF(KEY_COMPONENT) KEY_COMPONENTS;

// typedef struct CompositeKey_Params_st {
//   ASN1_INTEGER * KOFN;
//   COMPONENT_PARAMS * components_params;
// } COMPOSITE_KEY_PARAMS;

/*!
 * \brief Structure to hold the stack of key components
 *        and validation param (K of N)
 */
typedef struct CompositeKey_st {
  int algorithm;
  COMPOSITE_KEY_PARAMS * params;
  KEY_COMPONENTS * components;
} COMPOSITE_KEY;

/*!
 * \brief Structure to hold the stack of key components
 *        and validation param (K of N)
 */
typedef struct _libpki_composite_key_st {
  int algorithm;
  COMPOSITE_KEY_STACK * components;
  COMPOSITE_KEY_PARAMS * params;
} COMPOSITE_KEY_OLD;

/*!
 * @brief Defines a stack of MDs
 * @note  This is used to define the MDs used for
 *        signature calculation
 */
DEFINE_STACK_OF_CONST(EVP_MD);
typedef STACK_OF(EVP_MD) COMPOSITE_MD_STACK;

/*!
 * @brief Defines a stack of PKEY contexts
 */
DEFINE_STACK_OF(EVP_PKEY_CTX);

/*! 
 * @brief Defines a s tack of PKI_DIGEST_ALG contexts
 */
DEFINE_STACK_OF(EVP_MD_CTX);


/*!
 * @brief Composite Key Context structure
*/
typedef struct _libpki_composite_ctx {

  // MD for Hash-N-Sign
  const EVP_MD * md;

  // Key Components for Key Generation
  COMPOSITE_KEY_STACK * components;

  // Key Generation Parameters
  ASN1_INTEGER * params;

  // Default hash for signature calculation
  // in generic composite key operations when
  // no-hash is used and the specific component
  // does not support direct signing
  const EVP_MD * default_md;

  // List of Algorithms that is used to pass
  // the different X509_ALGOR to the individual
  // components
  X509_ALGORS * sig_algs;

  // ASN1 ITEM for signature parameters generations
  const ASN1_ITEM * asn1_item;

} COMPOSITE_CTX;

// // Used to Concatenate the encodings of the different
// // components when encoding via the ASN1 meth (priv_encode)
// DEFINE_STACK_OF(ASN1_OCTET_STRING)

// Used to Concatenate the encodings of the different
// components when encoding via the ASN1 meth (priv_encode)
DEFINE_STACK_OF(ASN1_BIT_STRING);

END_C_DECLS

#endif

/* END: composite_local.h */

// #endif // ENABLE_COMPOSITE