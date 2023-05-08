/* BEGIN: composite_pmenth.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala
//
// This file contains the definitions for the EVP_PKEY_METHOD that implements:
//
//     Composite Crypto (OR Logic)
//
// the corresponding functions are defined in composite_ameth.c

#ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#define _LIBPKI_COMPOSITE_PKEY_METH_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

#ifndef _LIBPKI_COMPOSITE_TYPES_H
#include <libpki/openssl/composite/composite_types.h>
#endif

#ifndef _LIBPKI_COMPOSITE_KEY_H
#include <libpki/openssl/composite/composite_key.h>
#endif

#ifndef _LIBPKI_COMPOSITE_CTX_H
#include <libpki/openssl/composite/composite_ctx.h>
#endif

#ifndef HEADER_ENVELOPE_H
#include <openssl/evp.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef HEADER_X509_H
#include <openssl/x509.h>
#endif

#ifndef	_STDIO_H_
#include <stdio.h>
#endif

BEGIN_C_DECLS

// ===========================
// Data Structures and Defines
// ===========================

// ==========================
// EVP_PKEY_METHOD Prototypes
// ==========================


#ifdef  __cplusplus
}
#endif
#endif // _LIBPKI_COMPOSITE_PKEY_METH_H

/* END: composite_pmeth.h */