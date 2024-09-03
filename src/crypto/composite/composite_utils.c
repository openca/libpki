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

// ==================
// Exported Functions
// ==================

int EVP_PKEY_assign_COMPOSITE(EVP_PKEY *pkey, void *comp_key) {

  COMPOSITE_KEY * key = comp_key;
    // Composite Key

  // Checks if we specified an explicit ID
  if (key->algorithm <= 0) {
    key->algorithm = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_NAME);
  }

  PKI_DEBUG("Assigning Composite Key (KEY Algorithm: %d)", key->algorithm);

  // Checks that the crypto library understands the composite algorithm (dynamic)
  if (key->algorithm <= NID_undef) {
    PKI_DEBUG("Cannot assign the Composite Key (unknown algorithm)");
    return PKI_ERR;
  }

  // Assigns the Key
  int success = EVP_PKEY_assign(pkey, key->algorithm, comp_key);
  if (success == 0) {
    PKI_DEBUG("Cannot assign the Composite Key");
    return PKI_ERR;
  }

  // All Done
  return PKI_OK;
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
