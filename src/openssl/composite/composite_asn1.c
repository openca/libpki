// BEGIN: composite_utils.c

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

#ifndef _LIBPKI_COMPOSITE_KEY_H
#include <libpki/openssl/composite/composite_key.h>
#endif

// ===============
// Data Structures
// ===============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_lcl.h"
#endif

// ================
// Component Params
// ================

ASN1_SEQUENCE(COMPONENT_PARAMS) = {
    ASN1_SIMPLE(COMPONENT_PARAMS, algorithm, X509_ALGOR),
    ASN1_OPT(COMPONENT_PARAMS, canSkipUnknown, ASN1_BOOLEAN),
} ASN1_SEQUENCE_END(COMPONENT_PARAMS);

IMPLEMENT_ASN1_FUNCTIONS(COMPONENT_PARAMS);
IMPLEMENT_ASN1_DUP_FUNCTION(COMPONENT_PARAMS);

ASN1_SEQUENCE(COMPOSITE_KEY_PARAMS) = {
    ASN1_OPT(COMPOSITE_KEY_PARAMS, KOFN, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(COMPOSITE_KEY_PARAMS, components_params, COMPONENT_PARAMS),
} ASN1_SEQUENCE_END(COMPOSITE_KEY_PARAMS);

IMPLEMENT_ASN1_FUNCTIONS(COMPOSITE_KEY_PARAMS);
IMPLEMENT_ASN1_DUP_FUNCTION(COMPOSITE_KEY_PARAMS);
