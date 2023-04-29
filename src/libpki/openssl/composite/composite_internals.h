/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_LOCAL_H
#define _LIBPKI_COMPOSITE_LOCAL_H

#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_LOG_H
#include <libpki/pki_log.h>
#endif

#ifndef _LIBPKI_ERRORS_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_KEYPAIR_H
#include <libpki/pki_keypair.h>
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
  STACK_OF(EVP_PKEY) * components;
  ASN1_INTEGER * k;
} COMPOSITE_KEY;

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
  
  // MD for signature calculation
  const EVP_MD * md;

  // Key Components for Key Generation
  STACK_OF(EVP_PKEY) * components;

  // Stack of Algorithm Identifiers for signatures
  X509_ALGORS * params;

  // K-of-N parameter
  int k_of_n;

} COMPOSITE_CTX;

// // Used to Concatenate the encodings of the different
// // components when encoding via the ASN1 meth (priv_encode)
// DEFINE_STACK_OF(ASN1_OCTET_STRING)

// Used to Concatenate the encodings of the different
// components when encoding via the ASN1 meth (priv_encode)
DEFINE_STACK_OF(ASN1_BIT_STRING)

// ====================
// Functions Prototypes
// ====================

// COMPOSITE_CTX: Utility Functions
// --------------------------------

/*! \brief Allocates a new Composite CTX */
COMPOSITE_CTX * COMPOSITE_CTX_new_null();

/*! \brief Frees the memory associated with a Composite CTX */
void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx);

/*! \brief Allocates a new Composite CTX from an MD */
COMPOSITE_CTX * COMPOSITE_CTX_new(const PKI_DIGEST_ALG * md);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_set_md(COMPOSITE_CTX * ctx, const PKI_DIGEST_ALG * md);

/*! \brief Returns the MD set for the CTX */
const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx);

/*! \brief Adds a new key to the CTX for Key Generation Ops */
int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX          * ctx, 
                            PKI_X509_KEYPAIR_VALUE * pkey,
                            PKI_X509_ALGOR_VALUE   * alg);

/*! \brief Removes and returns an entry from the stack of Keys */
PKI_X509_KEYPAIR_VALUE * COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX * ctx);

/*! \brief Clears the stack of keys in the Composite CTX */
int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * ctx);

/*! \brief Returns a reference to the stack of keys from the CTX */
STACK_OF(EVP_PKEY) * COMPOSITE_CTX_pkey_stack0(COMPOSITE_CTX * ctx);

// COMPOSITE_KEY: Stack Aliases
// ----------------------------

#define COMPOSITE_KEY_STACK_new()                sk_EVP_PKEY_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_KEY_STACK_free(p)              PKI_STACK_free ((PKI_STACK *)p)
  // Free a stack of EVP_PKEYs

#define COMPOSITE_KEY_STACK_new_null()           sk_EVP_PKEY_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_KEY_STACK_push(key, val)       sk_EVP_PKEY_push(key, val)
  // Pushes a new EVP_PKEY to the key

#define COMPOSITE_KEY_STACK_pop(key)             sk_EVP_PKEY_pop(key)
  // Removes the last EVP_PKEY from the key

#define COMPOSITE_KEY_STACK_pop_free(key)        sk_EVP_PKEY_pop_free(key, EVP_PKEY_free)
  // Removes all the elements of the sk and sk itself

#define COMPOSITE_KEY_STACK_num(key)             sk_EVP_PKEY_num(key)
  // Gets the number of components of a key

#define COMPOSITE_KEY_STACK_value(key, num)      sk_EVP_PKEY_value(key, num)
  // Returns the num-th EVP_PKEY in the stack

#define COMPOSITE_KEY_STACK_add(key, value, num) sk_EVP_PKEY_insert(key, value, num)
  // Adds a component at num-th position

#define COMPOSITE_KEY_STACK_del(key, num)        EVP_PKEY_free(sk_EVP_PKEY_delete(key, num))
  // Deletes the num-th component from the key

#define COMPOSITE_KEY_STACK_get0(key, num)       sk_EVP_PKEY_value(key, num)
  // Alias for the COMPOSITE_KEY_num() define

#define COMPOSITE_KEY_STACK_dup(key)             sk_EVP_PKEY_deep_copy(key, EVP_PKEY_dup, EVP_PKEY_free)
  // Duplicates (deep copy) the key

/// @brief Free all the entries, but not the stack structure itself
/// @brief Pops and free all components from the stack
/// @param key The stack to empty
void COMPOSITE_KEY_STACK_clear(COMPOSITE_KEY_STACK * sk);

// COMPOSITE_KEY: Allocation and management functions
// --------------------------------------------------

/*!
 * \brief Allocates a new Composite Key
 */
COMPOSITE_KEY * COMPOSITE_KEY_new(void);

/*!
 * @brief Free the memory associated with the composite key itself
*/ 
void COMPOSITE_KEY_free(COMPOSITE_KEY * key);

/*!
 * \brief Adds a new key component at the end of the list
 *
 * @param key The Composite key to add the component to
 * @param val The PKI_X509_KEYPAIR_VALUE component to add
 * @retval Returns '1' if successful and '0' otherwise
 */
int COMPOSITE_KEY_push(COMPOSITE_KEY * key, PKI_X509_KEYPAIR_VALUE * val);

/*!
 * \brief Removes the last component from the COMPOSITE_KEY
 *
 * @param key The Composite key to remove the component from
 * @retval The pointer to the removed PKI_X509_KEYPAIR_VALUE
 *         or NULL otherwise
*/
PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_pop(COMPOSITE_KEY * key);

/*!
 * \brief Removes and free the memory of all components from the key
 *
 * @param key The Composite key to remove the components from
 * @retval This function does not return a value
 */
void COMPOSITE_KEY_pop_free(COMPOSITE_KEY * key);

/*!
 * \brief Returns the number of components
 *
 * @param key The COMPOSITE_KEY to count the element of
 * @retval The number of components in the key
*/
int COMPOSITE_KEY_num(COMPOSITE_KEY * key);

/*!
 * \brief Returns the num-th key component
 *
 * This function returns the pointer to the num-th component of
 * the key. The ownership of the component is retained by the
 * key, thus the caller must not free the retrieved component.
 * 
 * @param key The COMPOSITE_KEY to retrieve the component from
 * @param num The number of the component to retrieve
 * @retval The pointer to the num-th entry
*/
PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_value(COMPOSITE_KEY * key, 
                                             int             num);

/*!
 * \brief Adds a component at num-th position
 *
 * @param key The COMPOSITE_KEY_to add the component to
 * @param value The PKI_X509_KEYPAIR_VALUE to add
 * @param num The position where to insert the component
 * @retval The function returns PKI_OK if successful and PKI_ERR
 *        otherwise.
 */
int COMPOSITE_KEY_add(COMPOSITE_KEY          * key, 
                      PKI_X509_KEYPAIR_VALUE * value, 
                      int                      num);

/*!
 * \brief Deletes the num-th component from the key
 *
 * @param key The COMPOSITE_KEY_to delete the component from
 * @param num The num-th of the component to delete
 * @retval The function returns PKI_OK if successful and PKI_ERR otherwise.
 */
int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num);

/*!
 * \brief Deletes all components of a COMPOSITE_KEY
 *
 * @param key The COMPOSITE_KEY_to delete the components from
 * @retval The function returns PKI_OK if successful and PKI_ERR otherwise.
 */
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key);

/*! \brief Alias for @COMPOSITE_KEY_num() function */
#define COMPOSITE_KEY_get0(key, num)  COMPOSITE_KEY_value(key, num)

/*!
 * \brief Duplicates a COMPOSITE_KEY structure
 *
 * @param key The COMPOSITE_KEY to duplicate
 * @retval The duplicated key or NULL in case of errors
 */
COMPOSITE_KEY * COMPOSITE_KEY_dup(const COMPOSITE_KEY * const key);

/*!
 * \brief Returns the total size of the components
 */ 
int COMPOSITE_KEY_size(COMPOSITE_KEY * key);

/*!
 * \brief Returns the total size in bits of the components
 *        (does this even make sense ?)
 */
int COMPOSITE_KEY_bits(COMPOSITE_KEY * bits);

/*!
 * \brief Returns the estimated security bits
 *
 * Returns the security bits of the composite key
 * which is the lowest (if the OR logic is implemented)
 * or is the highest (if the AND logic is implemented)
 * among the key components.
 */
int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * sec_bits);

END_C_DECLS

#endif

/* END: composite_local.h */

// #endif // ENABLE_COMPOSITE