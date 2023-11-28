// Composite Crypto authentication methods.
// (c) 2023 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_ASN1_H
#define _LIBPKI_COMPOSITE_ASN1_H

#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_STACK_H
#include <libpki/stack.h>
#endif

/* 

    ComponentParam ::= SEQUENCE {
        algorithm       algorithmIdentifier,
        canSkipUnknown  BOOLEAN OPT
    }

    ComponentParams ::= SEQUENCE (1..MAX) OF ComponentParam
*/

/*!
 * @brief Composite Parameters to capture the OID and Key
 *        individual parameters
 */
typedef struct Composite_Component_Params_st {
  X509_ALGOR *algorithm;
  ASN1_BOOLEAN * canSkipUnknown;
} COMPONENT_PARAMS;

DECLARE_ASN1_FUNCTIONS(COMPONENT_PARAMS);

// DECLARE_ASN1_DUP_FUNCTION(COMPONENT_PARAM);
COMPONENT_PARAMS *COMPONENT_PARAM_dup(const COMPONENT_PARAMS *a);

DECLARE_STACK_OF(COMPONENT_PARAMS);

typedef STACK_OF(COMPONENT_PARAMS) COMPONENT_PARAMS_STACK;

/*
    CompsiteKeyParams ::= SEQUENCE {
        KOFN            INTEGER,
        components      ComponentParams
    }

*/

typedef struct CompositeKey_Params_st {
  ASN1_INTEGER * KOFN;
  COMPONENT_PARAMS_STACK * components_params;
} COMPOSITE_KEY_PARAMS;


// COMPONENT_PARAM *COMPONENT_PARAM_dup(const COMPONENT_PARAM *a);

DECLARE_ASN1_FUNCTIONS(COMPOSITE_KEY_PARAMS);

// DECLARE_ASN1_DUP_FUNCTION(COMPOSITE_KEY_PARAM);
COMPOSITE_KEY_PARAMS *COMPOSITE_KEY_PARAM_dup(const COMPOSITE_KEY_PARAMS *a);

#endif