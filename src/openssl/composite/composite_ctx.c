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
  
  // // Initializes the stack of components
  // ret->components_md = sk_EVP_MD_new_null();
  // if (!ret->components_md) {
  //   PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
  //   if (ret) PKI_Free(ret);
  //   return NULL;
  // }

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

COMPOSITE_CTX * COMPOSITE_CTX_new(const EVP_MD * md) {

  COMPOSITE_CTX * ret = NULL;
    // Return Pointer

  // Allocates and Initializes the CTX
  ret = COMPOSITE_CTX_new_null();
  if (ret == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  // Sets the MD for the hash-n-sign mode
  ret->md = md;

  // All Done
  return ret;
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

  // PKI_DIGEST_ALG * pkey_md = NULL;
  //     // Pointer to the duplicated algorithm
  
  // PKI_ID algor_id = 0;
  //     // Algorithm ID

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

  // // Gets the MD for the PKEY
  // if ((pkey_md = (EVP_MD *)md) == NULL) {
  //   int pkey_md_nid = 0;
  //   pkey_md_nid = PKI_X509_KEYPAIR_VALUE_get_default_digest(pkey);
  //   if (!pkey_md_nid) {
  //     pkey_md = PKI_DIGEST_ALG_NULL;
  //   } else {
  //     pkey_md = (EVP_MD *)EVP_get_digestbynid(pkey_md_nid);
  //   }
  // }

  // // Checks for a valid algorithm
  // if (!OBJ_find_sigid_by_algs(&algor_id, EVP_MD_type(pkey_md), EVP_PKEY_id(pkey))) {
  //   PKI_DEBUG("Cannot find the algorithm for the given MD (%s) and PKEY (%s)", 
  //             OBJ_nid2sn(EVP_MD_type(pkey_md)), OBJ_nid2sn(EVP_PKEY_id(pkey)));
  //   return PKI_ERR;
  // }

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

int COMPOSITE_CTX_get_algors(COMPOSITE_CTX  * ctx,
                             X509_ALGORS   ** algors) {
  
  // Input Checks
  if (!ctx || !algors) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Gets the X509_ALGORS from the internal context
  if (*algors == NULL) {
    if ((*algors = sk_X509_ALGOR_new_null()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
    }
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
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot get the component from the stack");
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }

    int success = PKI_X509_KEYPAIR_VALUE_is_digest_supported(x, ctx->md);
    if (success == PKI_ERR) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot check if the digest is supported");
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Allocates a new X509_ALGOR
    if ((algor = X509_ALGOR_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
    }

    // Gets the right MD
    if (ctx->md) {
      x_md = ctx->md;
    } else if (ctx->default_md) {
      x_md = ctx->default_md;
    } else {
      x_md = PKI_DIGEST_ALG_DEFAULT;
    }

    // Retrieves the algorithm identifier
    if (!OBJ_find_sigid_by_algs(&algid, 
                                EVP_MD_type(x_md), 
                                EVP_PKEY_type(EVP_PKEY_id(x)))) {
      // Cannot find the algorithm identifier
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot find the algorithm identifier");
      X509_ALGOR_free(algor);
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Sets the algorithm identifier in the X509_ALGOR
    if (!X509_ALGOR_set0(algor, OBJ_nid2obj(algid), V_ASN1_UNDEF, NULL)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot set the algorithm identifier");
      X509_ALGOR_free(algor);
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }

    // Adds the algorithm to the stack
    if (!sk_X509_ALGOR_push(*algors, algor)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot push the algorithm to the stack");
      X509_ALGOR_free(algor);
      sk_X509_ALGOR_pop_free(*algors, X509_ALGOR_free);
      return PKI_ERR;
    }
  }

  // Updates the internal cache
  if (ctx->sig_algs) sk_X509_ALGOR_pop_free(ctx->sig_algs, X509_ALGOR_free);
  ctx->sig_algs = sk_X509_ALGOR_dup(*algors);

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
