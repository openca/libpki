/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_KEY_H
#define _LIBPKI_COMPOSITE_KEY_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPOSITE_TYPES_H
#include <libpki/openssl/composite/composite_types.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_PKI_X509_H
#include <libpki/pki_x509.h>
#endif

#ifndef _LIBPKI_KEYPAIR_H
#include <libpki/pki_keypair.h>
#endif

BEGIN_C_DECLS

// ====================
// Functions Prototypes
// ====================

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

// COMPOSITE_MD: Stack Aliases
// ----------------------------

#define COMPOSITE_MD_STACK_new()                sk_EVP_MD_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_MD_STACK_free(p)              PKI_STACK_free ((PKI_STACK *)p)
  // Free a stack of EVP_PKEYs

#define COMPOSITE_MD_STACK_new_null()           sk_EVP_MD_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_MD_STACK_push(key, val)       sk_EVP_MD_push(key, val)
  // Pushes a new EVP_PKEY to the key

#define COMPOSITE_MD_STACK_pop(key)             sk_EVP_MD_pop(key)
  // Removes the last EVP_PKEY from the key

#define COMPOSITE_MD_STACK_num(key)             sk_EVP_MD_num(key)
  // Gets the number of components of a key

#define COMPOSITE_MD_STACK_value(key, num)      sk_EVP_MD_value(key, num)
  // Returns the num-th EVP_PKEY in the stack

#define COMPOSITE_MD_STACK_add(key, value, num) sk_EVP_MD_insert(key, value, num)
  // Adds a component at num-th position

#define COMPOSITE_MD_STACK_del(key, num)        sk_EVP_MD_delete(key, num)
  // Deletes the num-th component from the key

#define COMPOSITE_MD_STACK_get0(key, num)       sk_EVP_MD_value(key, num)
  // Alias for the COMPOSITE_KEY_num() define

#define COMPOSITE_MD_STACK_dup(key)             sk_EVP_MD_dup(key)
  // Duplicates (deep copy) the key

//! @brief Free all the entries, but not the stack structure itself
//! @brief Pops and free all components from the stack
//! @param key The stack to empty
void COMPOSITE_MD_STACK_clear(COMPOSITE_MD_STACK * sk);

//! @brief Free all the entries together with the stack structure itself
//! @param key The stack to empty
void COMPOSITE_MD_STACK_pop_free(COMPOSITE_MD_STACK * sk);

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

/*!
 * @brief Sets the signature validation policy (k-of-n)
 *
 * This function sets the k-of-n policy of the composite key.
 * The policy is defined as the minimum number of components
 * that must be validated in order to consider the signature
 * valid.
 * 
 * @param comp_key The COMPOSITE_KEY to set the policy to
 * @param kofn The k-of-n policy to set
 * @retval 1 if successful and 0 otherwise
 */
int COMPOSITE_KEY_set_kofn(COMPOSITE_KEY * comp_key, int kofn);

/*!
 * @brief Returns the signature validation policy (k-of-n)
 *
 * This function returns the k-of-n policy of the composite key.
 * The policy is defined as the minimum number of components
 * that must be validated in order to consider the signature
 * valid.
 * 
 * @param comp_key The COMPOSITE_KEY to retrieve the policy from
 * @retval The k-of-n policy of the key (-1 if not set or set to 0)
 */
int COMPOSITE_KEY_get_kofn(COMPOSITE_KEY * comp_key);

/*!
 * @brief Returns PKI_OK if the signature validation policy is set (k-of-n)
 *
 * This function checks if the k-of-n policy of the composite key
 * is set. The policy is defined as the minimum number of components
 * that must be validated in order to consider the signature
 * valid.
 * 
 * @param comp_key The COMPOSITE_KEY to retrieve the policy from
 * @retval PKI_OK if the policy is set and greater than 0, PKI_ERR otherwise
 */

int COMPOSITE_KEY_has_kofn(COMPOSITE_KEY * comp_key);

END_C_DECLS

#endif

/* END: composite_local.h */

// #endif // ENABLE_COMPOSITE