/* BEGIN: composite_ameth.h */

#ifndef _LIBPKI_COMPOSITE_ASN1_METH_H
#define _LIBPKI_COMPOSITE_ASN1_METH_H

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <stdio.h>

#ifndef HEADER_X509_H
#include <openssl/x509.h>
#endif

#ifndef HEADER_EC_H
#include <openssl/ec.h>
#endif

#ifndef HEADER_ENVELOPE_H
#include <openssl/evp.h>
#endif

#ifndef HEADER_ASN1_H
#include <openssl/asn1.h>
#endif

#ifndef HEADER_OPENSSLV_H
#include <openssl/opensslv.h>
#endif

#ifndef _LIBPKI_COMPOSITE_KEY_H
#include <libpki/openssl/composite/composite_key.h>
#endif

#ifdef _LIBPKI_COMPOSITE_CTX_H
#include <libpki/openssl/composite/composite_ctx.h>
#endif

// #ifndef _LIBPKI_COMPOSITE_UTILS_H
// #include <libpki/openssl/composite/composite_utils.h>
// #endif

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