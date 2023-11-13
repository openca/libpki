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


            // ===================
            // COMPOSITE_PARAM API
            // ===================

// COMPOSITE_PARAM * COMPOSITE_PARAM_new(void) {

//   COMPOSITE_PARAM * cParam = NULL;

//   cParam = PKI_Malloc(sizeof(cParam));
//   if (!cParam) {
//     PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
//     return NULL;
//   }

//   // Sets the defaults
//   cParam->algorithm = NULL;
//   cParam->canSkipUnknown = NULL;

//   // Success
//   return cParam;
// }

// COMPOSITE_KEY_PARAM * COMPOSITE_PARAM_dup(COMPOSITE_KEY_PARAM * cParam) {

//   COMPOSITE_KEY_PARAM * destParam = NULL;

//   if (!cParam) {
//     PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
//     return NULL;
//   }

//   destParam = PKI_Malloc(sizeof(COMPOSITE_KEY_PARAM));
//   if (!destParam) {
//     PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
//     return NULL;
//   }

//   if (cParam->algorithm) {
//     destParam->algorithm = X509_ALGOR_dup(cParam->algorithm);
//     if (!destParam->algorithm) {
//       PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
//       PKI_Free(destParam);
//       return NULL;
//     }
//   }

//   if (cParam->canSkipUnknown) {
//     destParam->canSkipUnknown = CRYPTO_memdup(cParam->canSkipUnknown, sizeof(ASN1_BOOLEAN), __FILE__, __LINE__);
//     if (!destParam->canSkipUnknown) {
//       PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
//       PKI_Free(destParam);
//       return NULL;
//     }
//   }

//   return destParam;
// }


            // =================
            // KEY_COMPONENT API
            // =================

KEY_COMPONENT * KEY_COMPONENT_new(void) {

  KEY_COMPONENT * kComp = NULL;

  kComp = PKI_Malloc(sizeof(KEY_COMPONENT));
  if (!kComp) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  kComp->params = NULL;
  kComp->pkey = NULL;

  return kComp;

}

void KEY_COMPONENT_free(KEY_COMPONENT * kComp) {

  if (!kComp) return;

  if (kComp->params) {
    sk_COMPONENT_PARAMS_pop_free(kComp->params, COMPONENT_PARAMS_free);
    kComp->params = NULL;
  }

  if (kComp->pkey) {
    EVP_PKEY_free(kComp->pkey);
    kComp->pkey = NULL;
  }

  return;
}

KEY_COMPONENT * KEY_COMPONENT_dup(KEY_COMPONENT *kComp) {

  KEY_COMPONENT * destComp = NULL;

  if (!kComp) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return NULL;
  }

  destComp = KEY_COMPONENT_new();
  if (!destComp) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  if (kComp->params && sk_COMPONENT_PARAMS_num(kComp->params) > 0) {
    destComp->params = sk_COMPONENT_PARAMS_dup(kComp->params);
    if (!destComp->params) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }
  }

  if (kComp->pkey) {
    
    PKI_X509_KEYPAIR * dup = NULL;
      // Duplicated component's value

    PKI_MEM * buff = NULL;
      // Temporary Buffer structure
  
    PKI_X509 wrapper;
      // Static wrapper

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
  }

  // Success
  return destComp;

err:

  if (destComp) KEY_COMPONENT_free(destComp);
  return NULL;

}

// ==========================
// Exported Functions: STACKs
// ==========================

void KEY_COMPONENTS_clear(KEY_COMPONENTS * sk) {

  // Free all the entries, but not the stack structure itself
  KEY_COMPONENT * tmp_x;

  while (sk != NULL && (tmp_x = sk_KEY_COMPONENT_pop(sk)) != NULL) { 
    // Frees the component
    if (tmp_x) KEY_COMPONENT_free(tmp_x);
  }
  
}

// =================
// OLD KEY STructure
// =================

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
  const PKI_DIGEST_ALG * tmp_x;

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

  // Allocates the memory structures for the outer structure
  // and the stack of components keys
  if ((ret = PKI_Malloc(sizeof(COMPOSITE_KEY))) == NULL ||
      ((ret->components = KEY_COMPONENTS_new()) == NULL)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  // Sets the no-value value
  ret->algorithm = PKI_ID_UNKNOWN;

  // Sets the K of N parameter (none by default)
  ret->params = NULL;

  // // Sets the validation param to default value
  // ret->params = NULL;

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
    ret->params = COMPOSITE_KEY_PARAM_dup(key->params);
    if (!ret->params) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      COMPOSITE_KEY_free(ret);
      return NULL;
    }
  }

  // Duplicates the stack
  // for (int i = 0; i < COMPOSITE_KEY_STACK_num(key->components); i++) {
    for (int i = 0; i < KEY_COMPONENTS_num(key->components); i++) {

    KEY_COMPONENT * kComp = NULL;
    KEY_COMPONENT * destComp = NULL;
      // Pointer to the element to duplicate

    // Retrieves the value to duplicate an duplicates it
    if (((kComp = KEY_COMPONENTS_value(key->components, i)) == NULL) ||
        (destComp = KEY_COMPONENT_dup(kComp)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }

    // Pushes the component in the destination
    if (!KEY_COMPONENTS_push(ret->components, destComp)) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot push a component in the duplicated key's components.");
      goto err;
    }

    // // Duplicates the value by serializing and deserializing it
    // PKI_X509_KEYPAIR_put_mem(&wrapper, PKI_DATA_FORMAT_ASN1, &buff, NULL, NULL);
    // if (!buff) {
    //   PKI_ERROR(PKI_ERR_HSM_KEYPAIR_EXPORT, NULL);
    //   goto err;
    // }

    // // De-Serializes the data from the buffer
    // dup = PKI_X509_KEYPAIR_get_mem(buff, PKI_DATA_FORMAT_ASN1, NULL);
    // if (!dup) { 
    //   PKI_ERROR(PKI_ERR_HSM_KEYPAIR_EXPORT, NULL);
    //   PKI_MEM_free(buff);
    //   goto err;
    // }

    // // Free the buffer memory
    // PKI_MEM_free(buff);
    // buff = NULL;

    // // Adds the value to the return object stack
    // if (!COMPOSITE_KEY_STACK_push(ret->components, PKI_X509_get_value(dup))) {
    //   PKI_ERROR(PKI_ERR_HSM_KEYPAIR_IMPORT, NULL);
    //   PKI_X509_free(dup);
    //   goto err;
    // }

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

  KEY_COMPONENT * kComp = NULL;

  if (!key || !key->components || !val) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return 0;
  }

  kComp = KEY_COMPONENT_new();
  if (!kComp) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC,  NULL);
  }

  kComp->pkey = val;

  return KEY_COMPONENTS_push(key->components, kComp);  
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_pop(COMPOSITE_KEY * key) {

  PKI_X509_KEYPAIR_VALUE * pkey = NULL;
  KEY_COMPONENT * kComp = NULL;

  if (!key || !key->components) return NULL;
  
  kComp = KEY_COMPONENTS_pop(key->components);
  if (!kComp || !kComp->pkey) PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);

  // Transfer Ownership
  pkey = kComp->pkey;
  kComp->pkey = NULL;

  // Free the container
  KEY_COMPONENT_free(kComp);
  kComp = NULL;

  // Returns the individual key
  return pkey;
}

void COMPOSITE_KEY_pop_free(COMPOSITE_KEY * key) {

  if (!key || !key->components) return;

  KEY_COMPONENTS_pop_free(key->components);
  
  key->components = KEY_COMPONENTS_new();
  if (!key->components) PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);

  return;
}


int COMPOSITE_KEY_num(COMPOSITE_KEY * key) {

  if (!key || !key->components) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }
  
  return KEY_COMPONENTS_num(key->components);
}

PKI_X509_KEYPAIR_VALUE * COMPOSITE_KEY_value(COMPOSITE_KEY * key, int num) {
  
  KEY_COMPONENT * tmp_comp = NULL;

  if (!key || !key->components) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return NULL;
  }

  tmp_comp = KEY_COMPONENTS_value(key->components, num);
  if (!tmp_comp) {
    PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
    return NULL;
  }

  return tmp_comp->pkey;
}

int COMPOSITE_KEY_add(COMPOSITE_KEY * key, PKI_X509_KEYPAIR_VALUE * value, int num) {

  KEY_COMPONENT * kComp = NULL;

  if (!key || !key->components || !value) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  if ((kComp = KEY_COMPONENT_new()) != NULL) {
    kComp->pkey = value;
  }

  return KEY_COMPONENTS_add(key->components, kComp, num);
}

int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num) {

  if (!key || !key->components) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  if (num > KEY_COMPONENTS_num(key->components)) {
    PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
    return PKI_ERR;
  }

  KEY_COMPONENTS_del(key->components, num);

  return PKI_OK;
}

// Free all components of the key
int COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  // Clears (and free) the stack of key components
  KEY_COMPONENTS_clear(key->components);

  // Clears the params
  if (key->params) COMPOSITE_KEY_PARAMS_free(key->params);
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

  // Clears the params
  if (key->params) COMPOSITE_KEY_PARAMS_free(key->params);
  if (key->components) KEY_COMPONENTS_pop_free(key->components);

  // Free the memory
  PKI_ZFree(key, sizeof(COMPOSITE_KEY));
}

int COMPOSITE_KEY_set_kofn(COMPOSITE_KEY * comp_key, int kofn) {

  // Input Checks
  if (!comp_key) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  if (kofn >= KEY_COMPONENTS_num(comp_key->components)) {
    PKI_DEBUG("Maximum value for KOFN is %d (# of Components - 1)",
      KEY_COMPONENTS_num(comp_key->components));
    PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
    return PKI_ERR;
  }

  // If the value is equal or less than 0 we remove the parameter
  if (kofn <= 0) {
    if (!comp_key->params) return PKI_OK;
    if (comp_key->params->KOFN) ASN1_INTEGER_free(comp_key->params->KOFN);
    comp_key->params->KOFN = NULL;
    return PKI_OK;
  }

  // Sets the K-of-N value  
  if (!comp_key->params) {
    comp_key->params = COMPOSITE_KEY_PARAMS_new();
    if (!comp_key->params) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      return PKI_ERR;
    }
    if (!comp_key->params->KOFN) {
      comp_key->params->KOFN = ASN1_INTEGER_new();
      if (!comp_key->params->KOFN) {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return PKI_ERR;
      }
    }
    ASN1_INTEGER_set(comp_key->params->KOFN, kofn);
  } 
  // All Done  
  return PKI_OK;
}

int COMPOSITE_KEY_has_kofn(COMPOSITE_KEY * comp_key) {

  // Returns PKI_OK if a non-zero value is present
  if (COMPOSITE_KEY_get_kofn(comp_key) > 0) return PKI_OK;

  // Returns PKI_ERR if the value is not present
  // or less than zero
  return PKI_ERR;
}

int COMPOSITE_KEY_get_kofn(COMPOSITE_KEY * comp_key) {
  
  int ret = 0;
    // Return value

  // Input Checks
  if (!comp_key) return -1;

  // If not present, we return 0
  if (!comp_key->params || !comp_key->params->KOFN) return 0;
  
  // Returns the K-of-N value  
  ret = (int) ASN1_INTEGER_get(comp_key->params->KOFN);
  if (ret <= 0) return -1;

  // All Done
  return ret;
}


// END: composite_internals.c
