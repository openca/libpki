/* BEGIN: composite_ctx.c */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <libpki/openssl/composite/composite_ctx.h>

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_lcl.h"
#endif

// ===============
// Data Structures
// ===============

// ======================
// MACRO & Other Oddities
// ======================

#define DEBUG(args...) \
  { fprintf(stderr, "[%s:%d] %s() - ", __FILE__, __LINE__, __func__); \
  fprintf(stderr, ## args) ; fprintf(stderr,"\n"); fflush(stderr) ; }

// =======================
// COMPOSITE_KEY Functions
// =======================

#ifdef ENABLE_COMPOSITE

int COMPOSITE_KEY_size(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_size = 0;

  // Input Checks
  if (!key) return -1;

  // Retrieves the number of components
  if ((key_num = COMPOSITE_KEY_num(key)) <= 0) return PKI_ERR;

  // Process the individual keys
  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key = NULL;
      // Pointer to the component

    // Retrieves the component
    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      PKI_DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    // Updates the total size
    total_size += EVP_PKEY_size(single_key);
  }

  // All Done
  return total_size;
}

int COMPOSITE_KEY_bits(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_bits = 0;

  // Input Checks
  if (!key) return -1;

  // Returns '0' if no components were found
  if ((key_num = COMPOSITE_KEY_num(key)) <= 0) return 0;

  // Process the individual components
  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key = NULL;
      // Pointer for the component

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      PKI_DEBUG("ERROR: Cannot get key %d", i);
      return -1;
    }

    // Updates the total size
    total_bits += EVP_PKEY_bits(single_key);
  }

  // Total bits
  return total_bits;
}

int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int sec_bits = INT_MAX;
  int component_sec_bits = INT_MAX;

  // Input checks
  if (!key) return -1;

  // Checks we have at least one component
  if ((key_num = COMPOSITE_KEY_num(key)) <= 0) return -1;

  // Cycles through all the components
  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;
      // Pouinter to the individual component

    // Retrieves the component key
    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      PKI_DEBUG("ERROR: Cannot get key %d", i);
      return -1;
    }

    // Retrieves the security bits for the component
    component_sec_bits = EVP_PKEY_security_bits(single_key);

    // Updates the composite security bits if the component's
    // strength is higher than the previous components
    if (sec_bits < component_sec_bits) sec_bits = component_sec_bits;
  }

  // All Done
  return sec_bits;
}

// =======================
// COMPOSITE_CTX Functions
// =======================

COMPOSITE_CTX * COMPOSITE_CTX_new_null() {

  COMPOSITE_CTX * ret = NULL;
    // Return pointer

  // Allocates the needed memory
  ret = PKI_Malloc(sizeof(COMPOSITE_CTX));
  if (!ret) return NULL;

  // Zeroizes the memory
  memset(ret, 0, sizeof(COMPOSITE_CTX));

  // Initializes the stack of components
  ret->components = COMPOSITE_KEY_STACK_new();
  if (!ret->components) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    if (ret) PKI_Free(ret);
    return NULL;
  }
  
  // Initializes the stack of components
  ret->components_md = sk_EVP_MD_new_null();
  if (!ret->components_md) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    if (ret) PKI_Free(ret);
    return NULL;
  }

  // All Done
  return ret;
}

void COMPOSITE_CTX_free(COMPOSITE_CTX * comp_ctx) {

  // Input checks
  if (!comp_ctx) return;

  // Free Components Stack Memory
  if (comp_ctx->components) COMPOSITE_KEY_STACK_pop_free(comp_ctx->components); 
  comp_ctx->components = NULL;

  // Free MD Stack Memory
  if (comp_ctx->components_md) COMPOSITE_MD_STACK_pop_free(comp_ctx->components_md);
  comp_ctx->components_md = NULL;

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

const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx) {

  // Input checks
  if (!ctx) return NULL;

  // Returns the internal pointer
  return ctx->md;
}

int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX          * comp_ctx, 
                            PKI_X509_KEYPAIR_VALUE * pkey,
                            const PKI_DIGEST_ALG   * md) {

  PKI_DIGEST_ALG * pkey_md = NULL;
      // Pointer to the duplicated algorithm
  
  PKI_ID algor_id = 0;
      // Algorithm ID

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

  // Gets the MD for the PKEY
  if ((pkey_md = (EVP_MD *)md) == NULL) {
    int pkey_md_nid = 0;
    pkey_md_nid = PKI_X509_KEYPAIR_VALUE_get_default_digest(pkey);
    if (!pkey_md_nid) {
      pkey_md = PKI_DIGEST_ALG_NULL;
    } else {
      pkey_md = (EVP_MD *)EVP_get_digestbynid(pkey_md_nid);
    }
  }

  // Checks for a valid algorithm
  if (!OBJ_find_sigid_by_algs(&algor_id, EVP_MD_type(pkey_md), EVP_PKEY_id(pkey))) {
    PKI_DEBUG("Cannot find the algorithm for the given MD (%s) and PKEY (%s)", 
              OBJ_nid2sn(EVP_MD_type(pkey_md)), OBJ_nid2sn(EVP_PKEY_id(pkey)));
    return PKI_ERR;
  }

  // Pushes the new component
  COMPOSITE_KEY_STACK_push(comp_ctx->components, pkey);

  // Pushes the MD
  sk_EVP_MD_push(comp_ctx->components_md, pkey_md);

  // Sets the key parameter (if not set)
  if (comp_ctx->params == NULL) {
    comp_ctx->params = ASN1_INTEGER_new();
    ASN1_INTEGER_set(comp_ctx->params, 1);
  }

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX           * comp_ctx,
                           PKI_X509_KEYPAIR_VALUE ** pkey,
                           const PKI_DIGEST_ALG   ** md) {

  PKI_X509_KEYPAIR_VALUE * x = NULL;
      // Return pointer

  PKI_DIGEST_ALG * x_md = NULL;
      // Pointer to the MD associated with the PKEY

  // Input Checks
  if (!comp_ctx || !comp_ctx->components || !comp_ctx->components_md) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Checks for the number of components
  if (sk_EVP_PKEY_num(comp_ctx->components) < 1  ||
      sk_EVP_MD_num(comp_ctx->components_md) < 1 ||
      sk_EVP_PKEY_num(comp_ctx->components) != sk_EVP_MD_num(comp_ctx->components_md)) {
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

  // Also pops the MD from the MD stack
  x_md = sk_EVP_MD_pop(comp_ctx->components_md);
  if (!x_md) {
    // Cannot get the EVP_MD from the stack
    PKI_ERROR(PKI_ERR_GENERAL, "Cannot pop the EVP_MD from the digests components stack");
  }

  // Sets the output parameters
  if (pkey) *pkey = x;
  if (md) *md = x_md;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * comp_ctx) {

  // Input Checks
  if (!comp_ctx) return PKI_ERR;

  // Clears the components
  if (comp_ctx->components) COMPOSITE_KEY_STACK_clear(comp_ctx->components);

  // Clears the MDs
  if (comp_ctx->components_md) COMPOSITE_MD_STACK_clear(comp_ctx->components_md);
  
  // Clears the parameters
  if (comp_ctx->params) ASN1_INTEGER_free(comp_ctx->params);
  comp_ctx->params = NULL;
  
  // Clears the hasn-n-sign config
  comp_ctx->md = NULL;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const COMPOSITE_KEY_STACK ** const components,
                                  const COMPOSITE_MD_STACK  ** components_md) {

  // Input Checks
  if (!ctx) return PKI_ERR;

  // Sets the output parameters
  if (ctx->components && components) *components = ctx->components;
  if (ctx->components_md && components_md) *components_md = ctx->components_md;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  COMPOSITE_KEY_STACK * const components,
                                  COMPOSITE_MD_STACK  * const components_md) {
  // Input Checks
  if (!ctx) return PKI_ERR;

  // Sets the components
  if (ctx->components) COMPOSITE_KEY_STACK_free(ctx->components);
  ctx->components = components;

  // Sets the MDs
  if (ctx->components_md) sk_EVP_MD_pop_free(ctx->components_md, NULL);
  ctx->components_md = components_md;

  // All Done
  return PKI_OK;
}

int COMPOSITE_CTX_X509_get_algors(COMPOSITE_CTX  * ctx,
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
      return PKI_ERR;
    }

    // Gets the MD
    x_md = sk_EVP_MD_value(ctx->components_md, idx);
    if (!x_md) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot get the MD from the stack");
      return PKI_ERR;
    }

    // Allocates a new X509_ALGOR
    if ((algor = X509_ALGOR_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
    }

    // Retrieves the algorithm identifier
    if (!OBJ_find_sigid_by_algs(&algid, EVP_MD_type(x_md), EVP_PKEY_type(EVP_PKEY_id(x)))) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot find the algorithm identifier");
      X509_ALGOR_free(algor);
      return PKI_ERR;
    }

    if (!X509_ALGOR_set0(algor, OBJ_nid2obj(algid), V_ASN1_UNDEF, NULL)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot set the algorithm identifier");
      X509_ALGOR_free(algor);
      return PKI_ERR;
    }

    // Adds the algorithm to the stack
    if (!sk_X509_ALGOR_push(*algors, algor)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot push the algorithm to the stack");
      X509_ALGOR_free(algor);
      return PKI_ERR;
    }
  }

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
    
      // Input Checks
      if (!ctx) return PKI_ERR;
    
      // Gets the K-of-N value
      if (!ctx->params) return 0;
      return (int)ASN1_INTEGER_get(ctx->params);
}

#endif // End of ENABLE_COMPOSITE

/* END: composite_ctx.c */
