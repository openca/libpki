/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_TYPES_H
#define _LIBPKI_COMPOSITE_TYPES_H

#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_STACK_H
#include <libpki/stack.h>
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

/*!
 * \brief Structure to hold the stack of key components
 *        and validation param (K of N)
 */
typedef struct _libpki_composite_key_st {
  COMPOSITE_KEY_STACK * components;
  ASN1_INTEGER * params;
} COMPOSITE_KEY;

/*!
 * @brief Defines a stack of MDs
 * @note  This is used to define the MDs used for
 *        signature calculation
 */
DEFINE_STACK_OF(EVP_MD);
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

  // Stack of Algorithm Identifiers for signatures
  COMPOSITE_MD_STACK * components_md;

  // Key Generation Parameters
  ASN1_INTEGER * params;

} COMPOSITE_CTX;

// // Used to Concatenate the encodings of the different
// // components when encoding via the ASN1 meth (priv_encode)
// DEFINE_STACK_OF(ASN1_OCTET_STRING)

// Used to Concatenate the encodings of the different
// components when encoding via the ASN1 meth (priv_encode)
DEFINE_STACK_OF(ASN1_BIT_STRING)

END_C_DECLS

#endif

/* END: composite_local.h */

// #endif // ENABLE_COMPOSITE