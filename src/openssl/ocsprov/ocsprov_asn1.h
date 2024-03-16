#ifndef PKI_OSSL_OCSPROV_ASN1_H
#define PKI_OSSL_OCSPROV_ASN1_H
# pragma once

// Provider includes
#include <libpki/openssl/ocsprov/ocsprov_types.h>

// Local Includes
#include "ocsprov_lcl.h"

BEGIN_C_DECLS

#ifndef DECODER_PROVIDER
#    pragma error Macro DECODER_PROVIDER undefined
#endif

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                        \
    {                                                          \
        _name, "provider=" DECODER_PROVIDER ",input=" #_input, \
            (ocs_##_input##_to_##_output##_decoder_functions)  \
    }
#define DECODER_w_structure(_name, _input, _structure, _output)              \
    {                                                                        \
        _name,                                                               \
            "provider=" DECODER_PROVIDER ",input=" #_input                   \
            ",structure=" DECODER_STRUCTURE_##_structure,                    \
            (ocs_##_structure##_##_input##_to_##_output##_decoder_functions) \
    }

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                           \
    {                                                       \
        _name, "provider=" ENCODER_PROVIDER ",output=text", \
            (ocs_##_sym##_to_text_encoder_functions)        \
    }
#define ENCODER(_name, _sym, _fips, _output)                     \
    {                                                            \
        _name, "provider=" ENCODER_PROVIDER ",output=" #_output, \
            (ocs_##_sym##_to_##_output##_encoder_functions)      \
    }

#define ENCODER_w_structure(_name, _sym, _output, _structure)              \
    {                                                                      \
        _name,                                                             \
            "provider=" ENCODER_PROVIDER ",output=" #_output               \
            ",structure=" ENCODER_STRUCTURE_##_structure,                  \
            (ocs_##_sym##_to_##_structure##_##_output##_encoder_functions) \
    }

DECLARE_ASN1_ENCODE_FUNCTIONS_name(ASN1_BIT_STRING_SEQUENCE, ASN1_BIT_STRING_SEQUENCE)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(ASN1_BIT_STRING_SEQUENCE, X509_COMPOSITE_PUBKEY_SEQUENCE)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(ASN1_BIT_STRING_SEQUENCE, X509_COMPOSITE_SIG_SEQUENCE)

END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H