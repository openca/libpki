/* BEGIN: composite_ameth.h */

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <stdio.h>

// #include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/ec.h>

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/opensslv.h>

// #include "crypto/asn1.h"
// #include "crypto/evp.h"

#ifndef OPENSSL_COMPOSITE_LOCAL_H
#include <libpki/openssl/composite/composite_internals.h>
#endif

#ifndef OPENSSL_COMPOSITE_ASN1_METH_H
#define OPENSSL_COMPOSITE_ASN1_METH_H

#ifdef  __cplusplus
extern "C" {
#endif

// ===============
// Data Structures
// ===============

// ======================
// MACRO & Other Oddities
// ======================

// Sets the ID of a ASN1 method
int EVP_PKEY_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id);

#ifdef  __cplusplus
}
#endif

#endif // OPENSSL_COMPOSITE_AMETH_H

/* END: composite_ameth.h */