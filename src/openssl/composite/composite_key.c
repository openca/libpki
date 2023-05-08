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
  PKI_DIGEST_ALG * tmp_x;

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

  if (!key || !key->components) return PKI_ERR;

  COMPOSITE_KEY_STACK_del(key->components, num);

  return PKI_OK;
}

// Free all components of the key
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return PKI_ERR;

  // Clears (and free) the stack of key components
  COMPOSITE_KEY_STACK_clear(key->components);

  // Clears the params
  if (key->params) ASN1_INTEGER_free(key->params);
  key->params = NULL;

  // All Done
  return PKI_OK;
}


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

int COMPOSITE_KEY_set_kofn(COMPOSITE_KEY * comp_key, int kofn) {

  // Input Checks
  if (!comp_key) return PKI_ERR;

  // Sets the K-of-N value  
  if (!comp_key->params) ASN1_INTEGER_new();
  ASN1_INTEGER_set(comp_key->params, kofn);

  // All Done  
  return PKI_OK;
}

int COMPOSITE_KEY_get_kofn(COMPOSITE_KEY * comp_key) {
  
  int ret = 0;
    // Return value

  // Input Checks
  if (!comp_key) return PKI_ERR;
  
  // Returns the K-of-N value  
  ret = (int) ASN1_INTEGER_get(comp_key->params);

  // All Done
  return ret;
}


// END: composite_internals.c
