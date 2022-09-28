/* BEGIN: composite_pmenth.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala
//
// This file contains the definitions for the EVP_PKEY_METHOD that implements:
//
//     Composite Crypto (OR Logic)
//
// the corresponding functions are defined in composite_ameth.c

#include <stdio.h>

#ifndef HEADER_X509_H
#include <openssl/x509.h>
#endif

#ifndef OPENSSL_COMPOSITE_LOCAL_H
#include <libpki/openssl/composite/composite_internals.h>
#endif

#ifndef OPENSSL_COMPOSITE_PKEY_METH_H
#define OPENSSL_COMPOSITE_PKEY_METH_H

#ifdef  __cplusplus
extern "C" {
#endif

// ===========================
// Data Structures and Defines
// ===========================

// ==========================
// EVP_PKEY_METHOD Prototypes
// ==========================


#ifdef  __cplusplus
}
#endif
#endif // OPENSSL_COMPOSITE_PKEY_METH_H

/* END: composite_pmeth.h */