// BEGIN: composite_utils.c

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <libpki/openssl/composite/composite_key.h>

// ===============
// Data Structures
// ===============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_lcl.h"
#endif

// ==========================
// Exported Functions: STACKs
// ==========================

void COMPOSITE_KEY_STACK_clear(COMPOSITE_KEY_STACK * sk) {

  // Free all the entries, but not the stack structure itself
  PKI_X509_KEYPAIR_VALUE * tmp_x;

  while (sk != NULL && (tmp_x = sk_EVP_PKEY_pop(sk)) != NULL) { 
    // Frees the component
    if (tmp_x) EVP_PKEY_free(tmp_x);
  }
  
}

void COMPOSITE_MD_STACK_clear(COMPOSITE_MD_STACK * sk) {

  // Free all the entries, but not the stack structure itself
  PKI_X509_KEYPAIR_VALUE * tmp_x;

  // Removes the entries from the stack but do not
  // free them (they are all const pointers)
  while (sk != NULL && sk_EVP_MD_num(sk) > 0) { 
    tmp_x = sk_EVP_MD_pop(sk);
    if (!tmp_x) continue;
  }

  // All Done
  return;
}

void COMPOSITE_MD_STACK_pop_free(COMPOSITE_MD_STACK * sk) {

  // Input Checks
  if (!sk) return;

  // Removes all the entries but do not free the memory
  // because they are all const pointers
  while (sk != NULL && sk_EVP_MD_num(sk) > 0) {
    sk_EVP_MD_pop(sk);
  }

  // Free the STACK structure itself
  sk_EVP_MD_free(sk);

  // All Done
  return;
}

// =======================
// Exported Functions: KEY
// =======================

COMPOSITE_KEY * COMPOSITE_KEY_new(void) {

  COMPOSITE_KEY * ret = NULL;
    // Return Value

  // Allocates the memory structures
  if ((ret = PKI_Malloc(sizeof(COMPOSITE_KEY))) == NULL ||
      ((ret->components = COMPOSITE_KEY_STACK_new()) == NULL)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  // Sets the validation param to default value
  ret->params = NULL;

  // All Done
  return ret;
}

COMPOSITE_KEY * COMPOSITE_KEY_dup(const COMPOSITE_KEY * const key) {

  COMPOSITE_KEY * ret = NULL;
    // Return structure

  // Input checks
  if (!key) return NULL;

  // Allocates the memory
  if ((ret = COMPOSITE_KEY_new()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }
    
  // Copy the K param
  if (key->params) {
    ret->params = ASN1_INTEGER_dup(key->params);
    if (!ret->params) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      COMPOSITE_KEY_free(ret);
      return NULL;
    }
  }

  // Duplicates the stack
  for (int i = 0; i < COMPOSITE_KEY_STACK_num(key->components); i++) {

    PKI_X509_KEYPAIR_VALUE * val = NULL;
      // Pointer to the element to duplicate

    PKI_X509_KEYPAIR * dup = NULL;
      // Duplicated component's value

    PKI_MEM * buff = NULL;
      // Temporary Buffer structure

    PKI_X509 wrapper;
      // Wrapper for the duplicated value

    // Retrieves the value to duplicate
    if ((val = COMPOSITE_KEY_STACK_value(key->components, i)) == NULL) continue;

    // Duplicates the value by serializing and deserializing it
    PKI_X509_KEYPAIR_put_mem(&wrapper, PKI_DATA_FORMAT_ASN1, &buff, NULL, NULL);
    if (!buff) {
      PKI_ERROR(PKI_ERR_HSM_KEYPAIR_EXPORT, NULL);
      goto err;
    }

    // De-Serializes the data from the buffer
    dup = PKI_X509_KEYPAIR_get_mem(buff, PKI_DATA_FORMAT_ASN1, NULL);
    if (!dup) { 
      PKI_ERROR(PKI_ERR_HSM_KEYPAIR_EXPORT, NULL);
      PKI_MEM_free(buff);
      goto err;
    }

    // Free the buffer memory
    PKI_MEM_free(buff);
    buff = NULL;

    // Adds the value to the return object stack
    if (!COMPOSITE_KEY_STACK_push(ret->components, PKI_X509_get_value(dup))) {
      PKI_ERROR(PKI_ERR_HSM_KEYPAIR_IMPORT, NULL);
      PKI_X509_free(dup);
      goto err;
    }

    // Frees the memory
    //
    // NOTE: we don't free the wrapper, since it's a stack variable
    //       and it will be freed automatically when the function
    //       returns
    //

  }

  // All Done
  return ret;

err:

  // Free Memory
  if (ret) COMPOSITE_KEY_free(ret);

  // Error Condition
  return NULL;
}

int COMPOSITE_KEY_push(COMPOSITE_KEY * key, PKI_X509_KEYPAIR_VALUE * val) {

  if (!key || !key->components || !val) return 0;
  
  return COMPOSITE_KEY_STACK_push(key->components, val);
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_pop(COMPOSITE_KEY * key) {

  if (!key || !key->components) return NULL;
  
  return COMPOSITE_KEY_STACK_pop(key->components);
}

void COMPOSITE_KEY_pop_free(COMPOSITE_KEY * key) {

  if (!key || !key->components) return;
  
  COMPOSITE_KEY_STACK_pop_free(key->components);
  key->components = NULL;
}

int COMPOSITE_KEY_num(COMPOSITE_KEY * key) {

  if (!key || !key->components) return 0;
  
  return COMPOSITE_KEY_STACK_num(key->components);
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_value(COMPOSITE_KEY * key, int num) {
  if (!key || !key->components) return 0;
  return COMPOSITE_KEY_STACK_value(key->components, num);
}

int COMPOSITE_KEY_add(COMPOSITE_KEY * key, PKI_X509_KEYPAIR_VALUE * value, int num) {

  if (!key || !key->components || !value) return PKI_ERR;
  
  return COMPOSITE_KEY_STACK_add(key->components, value, num);
}

int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num) {

  EVP_PKEY * tmp_pkey = NULL;

  if (!key || !key->components) return PKI_ERR;

  COMPOSITE_KEY_STACK_del(key->components, num);

  return PKI_OK;
}

// Free all components of the key
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return PKI_ERR;

  EVP_PKEY * tmp_x;
      // Pointer to the individual key component

  // Clears (and free) the stack of key components
  COMPOSITE_KEY_STACK_clear(key->components);

  // Clears the params
  if (key->params) ASN1_INTEGER_free(key->params);
  key->params = NULL;

  // All Done
  return PKI_OK;
}

void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {
  
  // Input Checks
  if (!key) return;

  // Clears the components
  COMPOSITE_KEY_STACK_pop_free(key->components);

  // Clears the params
  if (key->params) ASN1_INTEGER_free(key->params);

  // Free the memory
  PKI_ZFree(key, sizeof(COMPOSITE_KEY));
}

int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const COMPOSITE_KEY_STACK ** const components,
                                  const COMPOSITE_MD_STACK  ** components_md) {
  // Input Checks
  if (!ctx) return PKI_ERR;

  // Sets the return values
  if (components) *components = ctx->components;
  if (components_md) *components_md = ctx->components_md;

  // All Done
  return PKI_OK;
}

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  COMPOSITE_KEY_STACK * const components,
                                  COMPOSITE_MD_STACK  * const components_md) {
  // Input Checks
  if (!ctx) return PKI_ERR;

  // Checks the values and set them in the CTX
  if (components) {
    if (ctx->components) COMPOSITE_KEY_STACK_pop_free(ctx->components);
    ctx->components = components;
  }
  if (components_md) {
    if (ctx->components_md) COMPOSITE_MD_STACK_pop_free(ctx->components_md);
    ctx->components_md = components_md;
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
  
  int ret = 0;
    // Return value

  // Input Checks
  if (!ctx) return PKI_ERR;
  
  // Returns the K-of-N value  
  ret = (int) ASN1_INTEGER_get(ctx->params);

  // All Done
  return ret;
}

// END: composite_internals.c
