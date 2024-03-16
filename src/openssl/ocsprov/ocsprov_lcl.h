#ifndef PKI_OSSL_OCSPROV_LOCAL_H
#define PKI_OSSL_OCSPROV_LOCAL_H
# pragma once

#ifndef PKI_OSSL_OCSPROV_TYPES_H
#include <libpki/openssl/ocsprov/ocsprov_types.h>
#endif

#ifndef PKI_OSSL_OCSPROV_KEY_H
#include "ocsprov_key.h"
#endif

BEGIN_C_DECLS

// Provider Definitions for Decoders
#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params  "type-specific"
#define DECODER_STRUCTURE_type_specific         "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub  "type-specific"
#define DECODER_STRUCTURE_PKCS8                 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo  "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo        "PrivateKeyInfo"

// Provider Definitions for Encoders
#define ENCODER_STRUCTURE_type_specific_keypair   "type-specific"
#define ENCODER_STRUCTURE_type_specific_params    "type-specific"
#define ENCODER_STRUCTURE_type_specific           "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub    "type-specific"
#define ENCODER_STRUCTURE_PKCS8                   "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo    "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo          "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PKCS1                   "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                   "pkcs3"


// Composite key structure
typedef struct _libpki_composite_key_element_st {
  int algorithm;
  EVP_PKEY_STACK * components;
  ASN1_INTEGER * params;
} COMPOSITE_KEY_ELEMENT;

/*!
 * \brief Structure to hold the stack of key components
 *        and validation param (K of N)
 */
typedef struct _libpki_composite_key_st {
  int algorithm;
  COMPOSITE_KEY_ELEMENT_STACK * components;
  ASN1_INTEGER * params;
} COMPOSITE_KEY;

// Composite signature structure
typedef struct _libpki_composite_ctx_st {

  // Context-specific data
  const OSSL_CORE_HANDLE *handle;

  // Key Components for Key Generation
  COMPOSITE_KEY_ELEMENT_STACK * components;

  // Key Generation Parameters
  ASN1_INTEGER * kofn_param;

  // Hash algorithm for the key parameter
  const EVP_MD * md;

  // Default hash for signature calculation
  // in generic composite key operations when
  // no-hash is used and the specific component
  // does not support direct signing
  const EVP_MD * default_md;

  // // List of Algorithms that is used to pass
  // // the different X509_ALGOR to the individual
  // // components
  // X509_ALGORS * sig_algs;

  // // ASN1 ITEM for signature parameters generations
  // const ASN1_ITEM * asn1_item;
} COMPOSITE_CTX;


END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H