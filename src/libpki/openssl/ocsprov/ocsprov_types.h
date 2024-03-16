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


END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H