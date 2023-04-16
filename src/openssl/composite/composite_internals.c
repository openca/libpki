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
  ret->k = 0;

  // All Done
  return ret;
}

COMPOSITE_KEY * COMPOSITE_KEY_dup(const COMPOSITE_KEY * const key) {

  COMPOSITE_KEY * ret = NULL;
    // Return structure

  // Input checks
  if (!key) return NULL;

  // Allocates the memory
  if ((ret = PKI_Malloc(sizeof(COMPOSITE_KEY)))) {
    
    // Copy the K param
    ret->k = key->k;

    // Duplicates the stack
    for (int i = 0; i < COMPOSITE_KEY_STACK_num(key->components); i++) {

      PKI_X509_KEYPAIR_VALUE * val = NULL;
        // Pointer to the element to duplicate

      PKI_X509_KEYPAIR * dup = NULL;
        // Duplicated component's value

      PKI_MEM * buff = NULL;
        // Temporary Buffer structure

      PKI_X509 wrapper;

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
        goto err;
      }

      // Adds the value to the return object stack
      if (!COMPOSITE_KEY_STACK_push(ret->components, PKI_X509_get_value(dup))) {
        PKI_ERROR(PKI_ERR_HSM_KEYPAIR_IMPORT, NULL);
        PKI_X509_free(dup);
        goto err;
      }

      // Resets the dup data structure and free the memory
      

    }
  }

  // All Done
  return ret;

err:

  // Free Memory
  if (ret) COMPOSITE_KEY_free(ret);

  // Error Condition
  return NULL;
}

// Free all components of the key
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return PKI_ERR;

  EVP_PKEY * tmp_x;
      // Pointer to the individual key component

  while ((tmp_x = sk_EVP_PKEY_pop(key->components)) != NULL) { 
    // Frees the component
    if (tmp_x) EVP_PKEY_free(tmp_x);
  }

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

  // Free the memory
  PKI_ZFree(key, sizeof(COMPOSITE_KEY));
}

// END: composite_internals.c
