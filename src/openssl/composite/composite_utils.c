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

int EVP_PKEY_assign_COMPOSITE(EVP_PKEY *pkey, void *comp_key) {

  PKI_ID composite_id = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_NAME);
    // Composite ID

  PKI_DEBUG("Composite_ID: %d", composite_id);

  PKI_DEBUG("COMPOSITE: Assign Key of Type (Id: %d - %s)", 
      EVP_PKEY_id(pkey), OBJ_nid2sn(EVP_PKEY_id(pkey)));

  // Checks that the crypto library understands the composite
  // algorithm (dynamic)
  if (composite_id == NID_undef) {
    return PKI_ERROR(PKI_ERR_HSM_KEYPAIR_GENERATE, "Cannot retrieve the 'COMPOSITE' OID");
  }

  // // Debugging
  // PKI_DEBUG("ASSIGN KEY: pkey = %p, comp_key = %p, composite_id = %d", pkey, comp_key, composite_id);

  // Assigns the Key
  return EVP_PKEY_assign(pkey, composite_id, comp_key);

}

// Free all components of the key
void COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return;

  EVP_PKEY * tmp_x;
      // Pointer to the individual key component

  while ((tmp_x = sk_EVP_PKEY_pop(key)) != NULL) { 
    
    // Frees the component
    if (tmp_x) EVP_PKEY_free(tmp_x);
  }

  // All Done
}

void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {
  
  if (!key) return;

  COMPOSITE_KEY_clear(key);
  OPENSSL_free(key);
}

// ==========================
// PKEY/ASN1_METHOD Auxillary
// ==========================

int EVP_PKEY_meth_set_id(EVP_PKEY_METHOD * meth, int pkey_id, int flags) {

  // Input Check
  if (!meth || pkey_id <= 0) return 0;

  // Assigns the generated IDs
	meth->pkey_id = pkey_id;

  if (flags >= 0) meth->flags = flags;

  // All Done
  return 1;
}

int EVP_PKEY_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id) {

  // Input Check
  if (!pkey_ameth || pkey_id <= 0) return 0;

  // Assigns the generated IDs
	pkey_ameth->pkey_id = pkey_id;
	pkey_ameth->pkey_base_id = pkey_id;

  // All Done
  return 1;
}

// END: composite_utils.c
