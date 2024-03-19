/**
 * @file ocsprov_types.h
 * @brief Defines the structure COMPOSITE_KEY_ELEMENT.
 *
 * This file contains the definition of the COMPOSITE_KEY_ELEMENT structure.
 * The COMPOSITE_KEY_ELEMENT structure is used in the OpenSSL Certificate
 * Services Provider (OCSP) module of the libpki library.
 */

#ifndef PKI_OSSL_OCSPROV_TYPES_H
#define PKI_OSSL_OCSPROV_TYPES_H
# pragma once

// General includes
#include <string.h>

// OpenSSL includes
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <openssl/provider.h>
#include <openssl/err.h>

#include <openssl/stack.h>
#include <openssl/safestack.h>

// LibPKI includes
#include <libpki/compat.h>

BEGIN_C_DECLS

/// @brief The control value for pushing a component onto the stack.
# define EVP_PKEY_CTRL_COMPOSITE_PUSH    0x201
/// @brief The control value for popping a component from the stack.
# define EVP_PKEY_CTRL_COMPOSITE_POP     0x202
/// @brief The control value for adding a component to the stack.
# define EVP_PKEY_CTRL_COMPOSITE_ADD     0x203
/// @brief The control value for deleting a component from the stack.
# define EVP_PKEY_CTRL_COMPOSITE_DEL     0x204
/// @brief The control value for clearing the stack.
# define EVP_PKEY_CTRL_COMPOSITE_CLEAR   0x205

// Defines new types of STACKS for Composite
DEFINE_STACK_OF(EVP_PKEY);
DEFINE_STACK_OF(EVP_PKEY_CTX);
DEFINE_STACK_OF(ASN1_BIT_STRING);
DEFINE_STACK_OF(EVP_MD_CTX);
DEFINE_STACK_OF_CONST(EVP_MD);

// Type definitions for clarity and ease of use
typedef STACK_OF(EVP_PKEY) EVP_PKEY_STACK;
typedef STACK_OF(EVP_PKEY_CTX) EVP_PKEY_CTX_STACK;
typedef STACK_OF(ASN1_BIT_STRING) ASN1_BIT_STRING_SEQUENCE;
typedef STACK_OF(EVP_MD_CTX) EVP_MD_CTX_STACK;
typedef STACK_OF(EVP_MD) EVP_MD_STACK;

/// @brief Structure to hold a single element of a composite key
typedef struct _libpki_composite_key_element_st COMPOSITE_KEY_ELEMENT;

/// @brief Stack of Elements for a Composite Key (COMPOSITE_KEY_ELEMENT)
typedef STACK_OF(COMPOSITE_KEY_ELEMENT) COMPOSITE_KEY_ELEMENT_STACK;

/// @brief Structure to hold a composite key
typedef struct _libpki_composite_key_st COMPOSITE_KEY;

/// @brief Composite algorithm Context structure;
typedef struct _libpki_composite_ctx_st COMPOSITE_CTX;

// ====================
// Functions Prototypes
// ====================

// COMPOSITE_KEY: Stack Aliases
// ----------------------------

/**
 * @brief Macro to declare stack management functions for a specific type.
 * 
 * @param type The type for which to declare stack management functions.
 **/
// #define HASH_SYMBOL     #
// #define DECLARE_STACK_FN_INTERNAL(TYPE, sym) \
// \
// sym define TYPE##_STACK_new()               sk_##TYPE##_new_null() \
// sym define TYPE##_STACK_new_null()          sk_##TYPE##_new_null() \
// sym define TYPE##_STACK_free(sk)            sk_##TYPE##_free(sk) \
// sym define TYPE##_STACK_push(sk, val)       sk_##TYPE##_push(sk, val) \
// sym define TYPE##_STACK_pop(sk)             sk_##TYPE##_pop(sk) \
// sym define TYPE##_STACK_pop_free(sk)        sk_##TYPE##_pop_free(sk, TYPE##_free) \
// sym define TYPE##_STACK_num(sk)             sk_##TYPE##_num(sk) \
// sym define TYPE##_STACK_value(sk, num)      sk_##TYPE##_value(sk, num) \
// sym define TYPE##_STACK_add(sk, value, num) sk_##TYPE##_insert(sk, value, num) \
// sym define TYPE##_STACK_del(sk, num)        TYPE##_free(sk_##TYPE##_delete(sk, num)) \
// sym define TYPE##_STACK_get0(sk, num)       sk_##TYPE##_value(sk, num) \
// sym define TYPE##_STACK_dup(sk)             sk_##TYPE##_deep_copy(sk, TYPE##_dup, TYPE##_free) \
// sym define TYPE##_STACK_clear()             for( ; sk_##TYPE##_num(sk) > 0 ; ) TYPE##_free(sk_##TYPE##_pop(sk))

// #define DECLARE_STACK_FN(TYPE) DECLARE_STACK_FN_INTERNAL(TYPE , HASH_SYMBOL )

#define DECLARE_OSSL_STACK_FN(TYPE) \
inline TYPE## *TYPE##_STACK_new() { return sk_##TYPE##_new_null(); } \
inline TYPE## *TYPE##_STACK_new_null() { return sk_##TYPE##_new_null(); } \
inline void    TYPE##_STACK_free(struct stack_st_##TYPE *sk) { return sk_##TYPE##_free(sk); } \
inline int     TYPE##_STACK_push(struct stack_st_##TYPE *sk, TYPE * val) { return sk_##TYPE##_push(sk, val); } \
inline TYPE## *TYPE##_STACK_pop(struct stack_st_##TYPE *sk) { return sk_##TYPE##_pop(sk); } \
inline void    TYPE##_STACK_pop_free(struct stack_st_##TYPE *sk) { return sk_##TYPE##_pop_free(sk, TYPE##_free); } \
inline int     TYPE##_STACK_num(struct stack_st_##TYPE *sk) { return sk_##TYPE##_num(sk); } \
inline TYPE## *TYPE##_STACK_value(struct stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline int     TYPE##_STACK_add(struct stack_st_##TYPE *sk, TYPE * value, int num) { return sk_##TYPE##_insert(sk, value, num); } \
inline void    TYPE##_STACK_del(struct stack_st_##TYPE *sk, int num) { return TYPE##_free(sk_##TYPE##_delete(sk, num)); } \
inline TYPE## *TYPE##_STACK_get0(struct stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline void    TYPE##_STACK_clear(struct stack_st_##TYPE *sk) { for( ; sk_##TYPE##_num(sk) > 0 ; ) TYPE##_free(sk_##TYPE##_pop(sk)); }

#define DECLARE_OSSL_STACK_FN_DUP(TYPE) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, TYPE##_dup, TYPE##_free); }

#define DECLARE_STACK_FN_DUP_EX(TYPE, dup_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, dup_func, TYPE##_free); }

#define DECLARE_STACK_FN_DUP_EX(TYPE, dup_func, free_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, dup_func, free_func); }

#define DECLARE_OSSL_STACK_FN_DEEP_COPY(TYPE) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, TYPE##_dup, TYPE##_free); }

#define DECLARE_OSSL_STACK_FN_DEEP_COPY_EX(TYPE, dup_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, dup_func, TYPE##_free); }

#define DECLARE_STACK_FN_DEEP_COPY_EX(TYPE, dup_func, free_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE## *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, dup_func, free_func); }

DECLARE_OSSL_STACK_FN_DEEP_COPY(EVP_PKEY)
DECLARE_OSSL_STACK_FN(EVP_MD)


// #define EVP_PKEY_STACK_new()                sk_EVP_PKEY_new_null()
//   // Allocates a new stack of EVP_PKEY

// #define EVP_PKEY_STACK_free(p)              sk_EVP_PKEY_free(p)
//   // Free a stack of EVP_PKEYs

// #define EVP_PKEY_STACK_new_null()           sk_EVP_PKEY_new_null()
//   // Allocates a new stack of EVP_PKEY

// #define EVP_PKEY_STACK_push(key, val)       sk_EVP_PKEY_push(key, val)
//   // Pushes a new EVP_PKEY to the key

// #define EVP_PKEY_STACK_pop(key)             sk_EVP_PKEY_pop(key)
//   // Removes the last EVP_PKEY from the key

// #define EVP_PKEY_STACK_pop_free(key)        sk_EVP_PKEY_pop_free(key, EVP_PKEY_free)
//   // Removes all the elements of the sk and sk itself

// #define EVP_PKEY_STACK_num(key)             sk_EVP_PKEY_num(key)
//   // Gets the number of components of a key

// #define EVP_PKEY_STACK_value(key, num)      sk_EVP_PKEY_value(key, num)
//   // Returns the num-th EVP_PKEY in the stack

// #define EVP_PKEY_STACK_add(key, value, num) sk_EVP_PKEY_insert(key, value, num)
//   // Adds a component at num-th position

// #define EVP_PKEY_STACK_del(key, num)        EVP_PKEY_free(sk_EVP_PKEY_delete(key, num))
//   // Deletes the num-th component from the key

// #define EVP_PKEY_STACK_get0(key, num)       sk_EVP_PKEY_value(key, num)
//   // Alias for the COMPOSITE_KEY_num() define

// #define EVP_PKEY_STACK_dup(key)             sk_EVP_PKEY_deep_copy(key, EVP_PKEY_dup, EVP_PKEY_free)
//   // Duplicates (deep copy) the key

// /// @brief Free all the entries, but not the stack structure itself
// /// @brief Pops and free all components from the stack
// /// @param key The stack to empty
// // void EVP_PKEY_STACK_clear(COMPOSITE_KEY_ELEMENT_STACK * sk);

// // COMPOSITE_MD: Stack Aliases
// // ----------------------------

// #define EVP_MD_STACK_new()                sk_EVP_MD_new_null()
//   // Allocates a new stack of EVP_PKEY

// #define EVP_MD_STACK_free(p)              PKI_STACK_free ((PKI_STACK *)p)
//   // Free a stack of EVP_PKEYs

// #define EVP_MD_STACK_new_null()           sk_EVP_MD_new_null()
//   // Allocates a new stack of EVP_PKEY

// #define EVP_MD_STACK_push(key, val)       sk_EVP_MD_push(key, val)
//   // Pushes a new EVP_PKEY to the key

// #define EVP_MD_STACK_pop(key)             sk_EVP_MD_pop(key)
//   // Removes the last EVP_PKEY from the key

// #define EVP_MD_STACK_num(key)             sk_EVP_MD_num(key)
//   // Gets the number of components of a key

// #define EVP_MD_STACK_value(key, num)      sk_EVP_MD_value(key, num)
//   // Returns the num-th EVP_PKEY in the stack

// #define EVP_MD_STACK_add(key, value, num) sk_EVP_MD_insert(key, value, num)
//   // Adds a component at num-th position

// #define EVP_MD_STACK_del(key, num)        sk_EVP_MD_delete(key, num)
//   // Deletes the num-th component from the key

// #define EVP_MD_STACK_get0(key, num)       sk_EVP_MD_value(key, num)
//   // Alias for the COMPOSITE_KEY_num() define

// #define EVP_MD_STACK_dup(key)             sk_EVP_MD_dup(key)
//   // Duplicates (deep copy) the key

// //! @brief Free all the entries, but not the stack structure itself
// //! @brief Pops and free all components from the stack
// //! @param key The stack to empty
// void EVP_MD_STACK_clear(EVP_MD_STACK * sk);

// //! @brief Free all the entries together with the stack structure itself
// //! @param key The stack to empty
// void EVP_MD_STACK_pop_free(EVP_MD_STACK * sk);


END_C_DECLS

#endif // End of PKI_OSSL_OCSPROV_H