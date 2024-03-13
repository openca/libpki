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

// ASN1 types
DEFINE_STACK_OF(EVP_PKEY);
typedef STACK_OF(EVP_PKEY) EVP_PKEY_STACK;

DEFINE_STACK_OF(ASN1_BIT_STRING);
typedef STACK_OF(ASN1_BIT_STRING) ASN1_BIT_STRING_SEQUENCE;

// Composite key structure
typedef struct _libpki_composite_key_st {
  int algorithm;
  EVP_PKEY_STACK * components;
  ASN1_INTEGER * params;
} COMPOSITE_KEY;

// Composite signature structure
typedef struct ocsprov_ctx_st {
    // Context-specific data
    const OSSL_CORE_HANDLE *handle;
} PKI_OSSL_OCSPROV_CTX;


END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H