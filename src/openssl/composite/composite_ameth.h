/* BEGIN: composite_ameth.h */

#ifndef _LIBPKI_COMPOSITE_ASN1_METH_H
#define _LIBPKI_COMPOSITE_ASN1_METH_H

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

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

#ifndef _LIBPKI_COMPOSITE_LOCAL_H
#include <libpki/openssl/composite/composite_internals.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

BEGIN_C_DECLS

// ===============
// Data Structures
// ===============

// ======================
// MACRO & Other Oddities
// ======================

// Sets the ID of a ASN1 method
int EVP_PKEY_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id);

END_C_DECLS

#endif // _LIBPKI_COMPOSITE_AMETH_H

/* END: composite_ameth.h */