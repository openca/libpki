// BEGIN: composite_utils.c

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

// ===============
// Data Structures
// ===============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_internals.h"
#endif

// ==================
// Exported Functions
// ==================

void COMPOSITE_KEY_STACK_clear(COMPOSITE_KEY_STACK * sk) {

  // Free all the entries, but not the stack structure itself
  PKI_X509_KEYPAIR_VALUE * tmp_x;

  while (sk != NULL && (tmp_x = sk_EVP_PKEY_pop(sk)) != NULL) { 
    // Frees the component
    if (tmp_x) EVP_PKEY_free(tmp_x);
  }
  
}

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
  ret->params = 0;

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
  ret->params = key->params;

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
  
  return sk_EVP_PKEY_push(key->components, val);
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_pop(COMPOSITE_KEY * key) {

  if (!key || !key->components) return NULL;
  
  return sk_EVP_PKEY_pop(key->components);
}

void COMPOSITE_KEY_pop_free(COMPOSITE_KEY * key) {

  if (!key || !key->components) return;
  
  sk_EVP_PKEY_pop_free(key->components, EVP_PKEY_free);
  key->components = NULL;

}

int COMPOSITE_KEY_num(COMPOSITE_KEY * key) {

  if (!key || !key->components) return 0;
  
  return sk_EVP_PKEY_num(key->components);
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_value(COMPOSITE_KEY * key, int num) {
  if (!key || !key->components) return 0;
  return sk_EVP_PKEY_value(key->components, num);
}

int COMPOSITE_KEY_add(COMPOSITE_KEY * key, PKI_X509_KEYPAIR_VALUE * value, int num) {

  if (!key || !key->components || !value) return PKI_ERR;
  
  return sk_EVP_PKEY_insert(key->components, value, num);
}

int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num) {

  EVP_PKEY * tmp_pkey = NULL;

  if (!key || !key->components) return PKI_ERR;

  tmp_pkey = sk_EVP_PKEY_delete(key->components, num);
  if (tmp_pkey) EVP_PKEY_free(tmp_pkey);

  return PKI_OK;
}

// Free all components of the key
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return PKI_ERR;

  EVP_PKEY * tmp_x;
      // Pointer to the individual key component

  // Clears (and free) the stack of key components
  while ((tmp_x = sk_EVP_PKEY_pop(key->components)) != NULL) { 
    // Frees the component
    if (tmp_x) EVP_PKEY_free(tmp_x);
  }

  // Clears (no need to free) the stack of MD algorithms
  while(sk_EVP_MD_num(key->params) > 0) {
    // Removes one element from the stack
    sk_EVP_MD_pop(key->params);
  };

  // All Done
  return PKI_OK;
}

void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {
  
  // Input Checks
  if (!key) return;

  // Clears the components
  if (key->components) {
    COMPOSITE_KEY_STACK_pop_free(key->components);
    key->components = NULL;
  }

  // Clears the params
  if (key->params) {
    while (sk_EVP_MD_num(key->params) > 0) {
      sk_EVP_MD_pop(key->params);
    }
    sk_EVP_MD_free(key->params);
    key->params = NULL;
  }

  // Free the memory
  PKI_ZFree(key, sizeof(COMPOSITE_KEY));
}

// END: composite_internals.c
