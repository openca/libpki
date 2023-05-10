/* BEGIN: composite_pmeth.c */

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_PKEY_CTX_H
#include <libpki/openssl/composite/composite_ctx.h>
#endif

#ifndef _LIBPKI_COMPOSITE_KEY_H
#include <libpki/openssl/composite/composite_key.h>
#endif

#ifndef _LIBPKI_PKI_ID_H
#include <libpki/pki_id.h>
#endif

#ifndef _LIBPKI_PKI_OID_H
#include <libpki/pki_oid.h>
#endif

// ==============
// Local Includes
// ==============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_lcl.h"
#endif

// ======================
// MACRO & Other Oddities
// ======================

#define DEBUG(args...) \
  { fprintf(stderr, "[%s:%d] %s() - ", __FILE__, __LINE__, __func__); \
  fprintf(stderr, ## args) ; fprintf(stderr,"\n"); fflush(stderr) ; }

// ========================
// Exported Global Variable
// ========================

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

#ifdef ENABLE_COMPOSITE

// =======================
// COMPOSITE_CTX Functions
// =======================


COMPOSITE_CTX * COMPOSITE_CTX_new(const PKI_DIGEST_ALG * alg) {

  COMPOSITE_CTX * ret = NULL;
    // Return Pointer

  // Allocates the memory
  ret = COMPOSITE_CTX_new_null();
  if (ret) {
    // If provided, set the default MD
    ret->default_md = alg;
  }

  // All Done
  return ret;
}

COMPOSITE_CTX * COMPOSITE_CTX_new_null() {

  COMPOSITE_CTX * ret = NULL;
    // Return pointer

  // Allocates the needed memory
  ret = PKI_Malloc(sizeof(COMPOSITE_CTX));
  if (!ret) return NULL;

  // Zeroize the memory
  memset(ret, 0, sizeof(COMPOSITE_CTX));

  // Initializes the stack of components
  ret->components = COMPOSITE_KEY_STACK_new();
  if (!ret->components) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    if (ret) PKI_Free(ret);
    return NULL;
  }

  // Sets the default for algorithms that cannot
  // do direct signing
  ret->default_md = PKI_DIGEST_ALG_DEFAULT;

  // No need to initialize the MD or the X509_ALGORs
  // only used during the signing and verifying processes

  // All Done
  return ret;
}

void COMPOSITE_CTX_free(COMPOSITE_CTX * comp_ctx) {

  // Input checks
  if (!comp_ctx) return;

  // Free Components Stack Memory
  if (comp_ctx->components) sk_EVP_PKEY_pop_free(comp_ctx->components, EVP_PKEY_free); 
  comp_ctx->components = NULL;

  // Free the signatures' algorithms, if any
  if (comp_ctx->sig_algs) sk_X509_ALGOR_pop_free(comp_ctx->sig_algs, X509_ALGOR_free);

  // Free the memory
  PKI_ZFree(comp_ctx, sizeof(COMPOSITE_CTX));
}

int COMPOSITE_CTX_set_md(COMPOSITE_CTX * ctx, const EVP_MD * md) {

  // Input Checks
  if (!ctx || !md) return PKI_ERR;

  // Sets the MD
  ctx->md = md;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_set_default_md(COMPOSITE_CTX * ctx, const EVP_MD * md) {

  // Input Checks
  if (!ctx || !md) return PKI_ERR;

  // Sets the MD
  ctx->default_md = md;

  // All Done
  return PKI_OK;
}

const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx) {

  // Input checks
  if (!ctx) return NULL;

  // Returns the internal pointer
  return ctx->md;
}

const EVP_MD * COMPOSITE_CTX_get_default_md(COMPOSITE_CTX * ctx) {

  // Input checks
  if (!ctx) return NULL;

  // Returns the internal pointer
  return ctx->default_md;
}


int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX          * comp_ctx, 
                            PKI_X509_KEYPAIR_VALUE * pkey) {

  // Input Checks
  if (!comp_ctx || !pkey) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Gets the reference to the stack
  if (!comp_ctx->components) {
    PKI_DEBUG("Missing internal stack of keys in CTX");
    return PKI_ERR;
  }

  // Pushes the new component
  COMPOSITE_KEY_STACK_push(comp_ctx->components, pkey);

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX           * comp_ctx,
                           PKI_X509_KEYPAIR_VALUE ** pkey,
                           const PKI_DIGEST_ALG   ** md) {

  PKI_X509_KEYPAIR_VALUE * x = NULL;
      // Return pointer

  // const PKI_DIGEST_ALG * x_md;
  //     // Pointer to the MD associated with the PKEY

  // Input Checks
  if (!comp_ctx || !comp_ctx->components) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Checks for the number of components
  if (sk_EVP_PKEY_num(comp_ctx->components) < 1) {
    // Something is wrong with the stacks
    PKI_ERROR(PKI_ERR_GENERAL, "Inconsistency in number of elements in components stack");
    return PKI_ERR;
  }

  // Pops and returns the last component
  x = COMPOSITE_KEY_STACK_pop(comp_ctx->components);
  if (!x) {
    // Cannot get the EVP_PKEY from the stack
    PKI_ERROR(PKI_ERR_GENERAL, "Cannot get the EVP_PKEY from the components stack");
    return PKI_ERR;
  }

  // Sets the output parameters
  if (pkey) *pkey = x;
  if (md) *md = comp_ctx->md;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * comp_ctx) {

  // Input Checks
  if (!comp_ctx) return PKI_ERR;

  // Clears the components
  if (comp_ctx->components) COMPOSITE_KEY_STACK_clear(comp_ctx->components);

  // Clears the k-of-n parameter
  if (comp_ctx->params) ASN1_INTEGER_free(comp_ctx->params);
  comp_ctx->params = NULL;

  // Clears the signature algorithms
  if (comp_ctx->sig_algs) sk_X509_ALGOR_pop_free(comp_ctx->sig_algs, X509_ALGOR_free);
  comp_ctx->sig_algs = NULL;

  // Clears the MD for hash-n-sign
  comp_ctx->md = NULL;
  
  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const COMPOSITE_KEY_STACK ** const components) {
  // Input Checks
  if (!ctx) return PKI_ERR;

  // Sets the return values
  if (components) *components = ctx->components;

  // All Done
  return PKI_OK;
}

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  COMPOSITE_KEY_STACK * const components) {
  // Input Checks
  if (!ctx) return PKI_ERR;

  // Checks the values and set them in the CTX
  if (components) {
    if (ctx->components) COMPOSITE_KEY_STACK_pop_free(ctx->components);
    ctx->components = components;
  }

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_components_detach(COMPOSITE_CTX        * ctx, 
                                    COMPOSITE_KEY_STACK ** const components) {

  // Input Checks
  if (!ctx) return PKI_ERR;

  // Returns the components if requested
  if (components) *components = ctx->components;
  
  // Resets the internal pointer
  ctx->components = NULL;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_algors_clear(COMPOSITE_CTX  * const ctx) {
  
  // Input Checks
  if (!ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Clears the signature algorithms
  if (ctx->sig_algs) sk_X509_ALGOR_pop_free(ctx->sig_algs, X509_ALGOR_free);
  ctx->sig_algs = NULL;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_explicit_algors_new0(COMPOSITE_CTX  * ctx,
                                       const int        pkey_type,
                                       X509_ALGORS   ** algors) {

  X509_ALGORS * sk = NULL;
  X509_ALGOR algor = { 0x0 };
    // Pointer to the new stack of X509_ALGOR

  PKI_SCHEME_ID scheme = PKI_SCHEME_UNKNOWN;
    // NID of the algorithm

  // Input Checks
  if (!ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  if (!PKI_ID_is_explicit_composite(pkey_type, &scheme)) {
    PKI_DEBUG("Scheme %d is not an explicit composite", scheme);
    return PKI_ERR;
  }

  PKI_DEBUG("Scheme %d is an explicit composite (number of components = %d)", scheme, COMPOSITE_KEY_STACK_num(ctx->components));

  sk = sk_X509_ALGOR_new_null();
  if (!sk) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return PKI_ERR;
  }

  switch (scheme) {

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
      // Dilithium3 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM3), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // RSA component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSA), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256: {
      // Dilithium3 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM3), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ECDSA-with-SHA256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
      // Dilithium3 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM3), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP256r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:{
      // Dilithium3 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM3), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ED 25519 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
      // Dilithium5 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM5), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ECDSA-with-SHA384 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ecdsa_with_SHA384), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
      // Dilithium5 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM5), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool384 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP384r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
      // Dilithium5 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM5), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ED 448 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ED448), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
      // Falcon512 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ECDSA-with-SHA256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ecdsa_with_SHA384), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
      // Falcon512 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP256r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
      // Falcon512 Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP256r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_P256: {
      // Sphincs 256 simple Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_sphincssha256128ssimple), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ECDSA-with-SHA256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_BRAINPOOL256: {
      // Sphincs 256 simple Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_sphincssha256128ssimple), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP256r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_ED25519: {
      // Sphincs 256 simple Component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_sphincssha256128ssimple), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Brainpool256 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(NID_brainpoolP256r1), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {
      // Dilithium3
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_DILITHIUM3), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // RSAPSS component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSAPSS), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
      // Falcon512 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // RSA component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSA), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
      // Dilithium5 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Falcon1024 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSA), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // ECDSA-with-SHA512 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_ECDSA_SHA512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;

    case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_RSA:

    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
      // Dilithium5 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_FALCON512), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // Falcon1024 component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSA), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
      // RSA component
      X509_ALGOR_set0(&algor, OBJ_nid2obj(PKI_ALGOR_RSA), V_ASN1_UNDEF, NULL);
      sk_X509_ALGOR_push(sk, X509_ALGOR_dup(&algor));
    } break;
    
    default:
      PKI_DEBUG("Explicit configuration for scheme %d not supported", scheme);
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      return PKI_ERR;
  }

  // Checks the number of components and algorithms to be the same
  if (sk_X509_ALGOR_num(sk) != COMPOSITE_KEY_STACK_num(ctx->components)) {
    PKI_DEBUG("Number of components (%d) and algorithms (%d) do not match",
              COMPOSITE_KEY_STACK_num(ctx->components), sk_X509_ALGOR_num(ctx->sig_algs));
    sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
    return PKI_ERR;
  }

  PKI_DEBUG("Same number of components and algorithms (%d)", sk_X509_ALGOR_num(sk));

  // Cycles through the components and checks the pkey algors
  for (int idx = 0; idx < COMPOSITE_KEY_STACK_num(ctx->components); idx++) {

    X509_ALGOR * algor = NULL;
      // Pointer to a X509_ALGOR in the stack

    PKI_X509_KEYPAIR_VALUE * pkey = NULL;
      // Pointer to a key in the components' stack

    // int alg_id = 0;
    int pkey_id = 0;
    int md_id = 0;
      // IDs of the pkey and the message digest
  
    PKI_DEBUG("Validating component #%d", idx);

    // Gets the component and the algorithm
    pkey = COMPOSITE_KEY_STACK_value(ctx->components, idx);
    if (!pkey) {
      PKI_DEBUG("Cannot retrieve Key Component #%d", idx);
      return PKI_ERR;
    }
    algor = sk_X509_ALGOR_value(sk, idx);

    // Gets the PKEY and the MD IDs
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(algor->algorithm), &md_id, &pkey_id)) {
      PKI_DEBUG("Cannot parse PKEY and MD IDs for algorithm %s from component #%d",
                OBJ_nid2ln(OBJ_obj2nid(algor->algorithm)), idx);
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Checks that the PKEY ID is valid
    if (pkey_id == NID_undef) {
      PKI_DEBUG("Cannot retrieve the PKEY ID for algorithm %s from component #%d",
                OBJ_nid2ln(OBJ_obj2nid(algor->algorithm)), idx);
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Make sure that the pkey type is the same
    if (pkey_id != EVP_PKEY_type(EVP_PKEY_id(pkey))) {
      PKI_DEBUG("PKEY type (%d) and algorithm (%d) do not match in component #%d",
                pkey_id, EVP_PKEY_type(EVP_PKEY_id(pkey)), idx);
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      return PKI_ERR;
    }

    PKI_DEBUG("SUCCESS: Verified Explicit Component #%d: PKEY ID = %d, MD ID = %d",
              idx, pkey_id, md_id);
  }

  // Updates the internal status
  if (ctx->sig_algs) sk_X509_ALGOR_pop_free(ctx->sig_algs, X509_ALGOR_free);
  ctx->sig_algs = sk;

  // Returns the stack of X509_ALGOR
  if (algors) *algors = sk;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_algors_new0(COMPOSITE_CTX  * ctx,
                              const int        signature_id,
                              X509_ALGORS   ** algors) {
  
  PKI_SCHEME_ID scheme = PKI_SCHEME_UNKNOWN;
    // Scheme of the key

  X509_ALGORS * sk = NULL;
    // Pointer to the new stack of X509_ALGOR

  // Input Checks
  if (!ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Warns about missing pkey_type
  if (signature_id == PKI_ID_UNKNOWN) {
    PKI_DEBUG("Missing pkey_type when building the list of X509_ALGORS, using defaults");
  }

  // Checks if the key is of the explicit composite type
  if (PKI_ID_is_explicit_composite(signature_id, &scheme)) {
    // If it is, then we can use the explicit algors
    return COMPOSITE_CTX_explicit_algors_new0(ctx, signature_id, algors);  
  }

  // Allocates a new stack of X509_ALGOR
  if ((sk = sk_X509_ALGOR_new_null()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
  }

  // Cycles through the components and adds the algors
  for (int idx = 0; idx < COMPOSITE_KEY_STACK_num(ctx->components); idx++) {

    PKI_X509_KEYPAIR_VALUE * x = NULL;
    const PKI_DIGEST_ALG * x_md = NULL;
    int algid = PKI_ALGOR_ID_UNKNOWN;
    PKI_X509_ALGOR_VALUE * algor = NULL;

    // Gets the component
    x = COMPOSITE_KEY_STACK_get0(ctx->components, idx);
    if (!x) {
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot get the component from the stack");
      return PKI_ERR;
    }

    // Gets the right MD
    if (ctx->md && ctx->md != PKI_DIGEST_ALG_NULL) {
      
      PKI_DEBUG("Detected use of hash-n-sign MD (%d)", EVP_MD_type(ctx->md));
      // Use hash-n-sign if set
      x_md = ctx->md;

    } else {
      // Checks if the component requires the digest
      // and we are not using the hash-n-sign paradigm
      // let's use the configured default (if any)
      if (PKI_ID_requires_digest(EVP_PKEY_id(x))) {

        PKI_DEBUG("Digest IS REQUIRED for component #%d", idx);

        // Checks if a default hash was configured
        if(ctx->default_md) {
          // Use the configured default
          x_md = ctx->default_md;
          PKI_DEBUG("Using configured default digest (%d) for component #%d", EVP_MD_type(x_md), idx);
        } else {
          PKI_DEBUG("No configured default, let's retrieve the specific default for component #%d", idx);
          int md_nid = 0;
          // Search for a default digest for the type of key
          if (!EVP_PKEY_get_default_digest_nid(x, &md_nid) || !md_nid) {
            PKI_DEBUG("No default exists for component #%d, using library default");
            // Use the library default MD
            x_md = PKI_DIGEST_ALG_DEFAULT;
          } else {
            PKI_DEBUG("Using default digest %d for component #%d", md_nid, idx);
            x_md = EVP_get_digestbynid(md_nid);
          }
        }
      } else {
        x_md = NULL;
        PKI_DEBUG("Digest IS NOT REQUIRED for component #%d", idx);
      }
    }

    // If PQC, the OBJ_find_sigid_by_algs() does not seem to work,
    // we use a different approach
    if (!x_md && x_md != PKI_DIGEST_ALG_NULL && PKI_ID_is_pqc(EVP_PKEY_type(EVP_PKEY_id(x)))) {

      algid = EVP_PKEY_type(EVP_PKEY_id(x));

    } else {

      // Retrieves the algorithm identifier
      if (!OBJ_find_sigid_by_algs(&algid, 
                                  x_md && x_md != PKI_DIGEST_ALG_NULL ? EVP_MD_type(x_md) : PKI_DIGEST_ALG_ID_UNKNOWN, 
                                  EVP_PKEY_type(EVP_PKEY_id(x)))) {
        // Cannot find the algorithm identifier
        sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
        PKI_ERROR(PKI_ERR_GENERAL, "Cannot find the algorithm identifier");
        return PKI_ERR;
      }
    }

    // Allocates a new X509_ALGOR
    if ((algor = X509_ALGOR_new()) == NULL) {
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
    }

    // Sets the algorithm identifier in the X509_ALGOR
    if (!X509_ALGOR_set0(algor, OBJ_nid2obj(algid), V_ASN1_UNDEF, NULL)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot set the algorithm identifier");
      X509_ALGOR_free(algor);
      sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Adds the algorithm to the stack
    if (!sk_X509_ALGOR_push(sk, algor)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot push the algorithm to the stack");
      X509_ALGOR_free(algor);
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }
  }

  // Updates the internal cache
  if (ctx->sig_algs) sk_X509_ALGOR_pop_free(ctx->sig_algs, X509_ALGOR_free);
  ctx->sig_algs = sk;

  // Also sets the output variable
  if (algors) *algors = sk;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_algors_get0(const COMPOSITE_CTX  * const ctx,
                              const X509_ALGORS   ** const algors) {
  
  // Input Checks
  if (!ctx || !algors) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  *algors = ctx->sig_algs;

  return PKI_OK;
}

int COMPOSITE_CTX_algors_set0(COMPOSITE_CTX * const ctx,
                              X509_ALGORS   * const algors) {
  
  // Input Checks
  if (!ctx || !algors) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Clears the internal values and transfer ownership
  if (ctx->sig_algs) sk_X509_ALGOR_pop_free(ctx->sig_algs, X509_ALGOR_free);
  ctx->sig_algs = algors;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_algors_detach(COMPOSITE_CTX  * const ctx,
                                X509_ALGORS   ** const algors) {

  // Input Checks
  if (!ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Clears the internal values and transfer ownership
  if (algors) *algors = ctx->sig_algs;
  ctx->sig_algs = NULL;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_set_kofn(COMPOSITE_CTX * ctx, int kofn) {

  // Input Checks
  if (!ctx) return PKI_ERR;

  // Sets the K-of-N value  
  if (!ctx->params) ASN1_INTEGER_new();
  ASN1_INTEGER_set(ctx->params, kofn);

  // All Done  
  return PKI_OK;
}

int COMPOSITE_CTX_get_kofn(COMPOSITE_CTX * ctx) {
  
  int ret = 0;
    // Return value

  // Input Checks
  if (!ctx) return PKI_ERR;
  
  // Returns the K-of-N value  
  ret = (int) ASN1_INTEGER_get(ctx->params);

  // All Done
  return ret;
}

#endif // ENABLE_COMPOSITE

/* END: composite_ctx.c */
