/* BEGIN: composite_amenth.c */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#pragma GCC diagnostic ignored "-Wunused-function"

// Local Include
#include "composite_ameth_lcl.h"

#include <libpki/pki_oid.h>

// ===============
// Data Structures
// ===============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_lcl.h"
#endif

// ======================
// MACRO & Other Oddities
// ======================

#define DEBUG(args...) \
  { fprintf(stderr, "[%s:%d] %s() - ", __FILE__, __LINE__, __func__) ; \
    fprintf(stderr, ## args) ; fprintf(stderr,"\n") ; fflush(stderr); }

#ifdef ENABLE_COMPOSITE

// ==============================
// EVP_PKEY_ASN1_METHOD Functions
// ==============================

// Implemented
int pub_decode(EVP_PKEY *pk, X509_PUBKEY *pubkey) {

  // Strategy:
  //
  // Get the COMPOSITE_KEY and decode each EVP_PKEY from
  // each of the X509_PUBKEY that is encoded in ASN1_OCTET_STRING
  // from the generic sequence
  
  EVP_PKEY * tmp_pkey = NULL;
    // Containers for the different
    // encodings of the components

  X509_PUBKEY * tmp_pub = NULL;
    // Pointer to individual components
    // X509_PUBKEY structure

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the Composite Key
    // (just a STACK_OF(EVP_PKEY))

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  ASN1_BIT_STRING aBitStr;
    // Temp Octet Pointer

  const void *params_value = NULL;
    // Value for the parameters

  const unsigned char *param_der = NULL;
  int param_len = 0;
    // Buffer

  X509_ALGOR * pkey_alg = NULL;
  int pkey_type = 0;
    // Public Key Type and Algorithms

  // Input Checking
  if (!pk || !pubkey) return 0;

  // Let's use the aOctetStr to avoid the internal
  // p8 pointers to be modified
  aBitStr.data = pubkey->public_key->data;
  aBitStr.length = pubkey->public_key->length;

  // Gets the Sequence from the data itself, error if
  // it is not a sequence of ASN1_OCTET_STRING
  if ((sk = d2i_ASN1_SEQUENCE_ANY(NULL, 
                (const unsigned char **)&aBitStr.data,
                aBitStr.length)) <= 0) {
    PKI_ERROR(PKI_ERR_GENERAL, "Cannot decode the composite key");
    return 0;
  }

  // Allocates Memory for the inner key structure
  if ((comp_key = COMPOSITE_KEY_new()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new composite key internal structure");
    goto err;
  }

  // Process each component
  for (int i = 0; i < sk_ASN1_TYPE_num(sk); i++) {

    // Retrieve the value
    if ((aType = sk_ASN1_TYPE_value(sk, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the ASN1_TYPE for key #%d", i);
      goto err;
    }

    // Checks we got the right type
    if ((aType->type != V_ASN1_SEQUENCE) || (aType->value.sequence == NULL)) {
      PKI_ERROR(PKI_ERR_PARAM_TYPE, "Composite key encoding error (expecting OCTET STRINGs for component #%d)", i);
      goto err;
    }

    // Sets the Pointers so that our original ones
    // are not moved (can cause memory issues)
    aBitStr.data = aType->value.sequence->data;
    aBitStr.length = aType->value.sequence->length;

    // Retrieve the EVP_PKEY from the ASN1_TYPE
    if ((tmp_pub = d2i_X509_PUBKEY(NULL, 
                      (const unsigned char **)&(aBitStr.data),
                      (long)aBitStr.length)) == NULL) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Cannot decode X509_PUBKEY of Key #%d", i);
      goto err;
    }

    if ((tmp_pkey = X509_PUBKEY_get(tmp_pub)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot retrieve the public key for component #%d", i);
      goto err;
    }

    // Here we can free the X509_PUBKEY structure
    X509_PUBKEY_free(tmp_pub);
    tmp_pub = NULL; // Safety

    // Add the component to the key
    if (!COMPOSITE_KEY_push(comp_key, tmp_pkey)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add component #%d to the composite key", i);
      goto err;
    }
  }

  // Free the stack memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
    ASN1_TYPE_free(aType);
  } sk_ASN1_TYPE_free(sk);

  // ======================
  // Process Key Parameters
  // ======================

  // Retrieves the Public Key parameter
  if (!X509_PUBKEY_get0_param(NULL, 
                              &param_der, 
                              &param_len, 
                              &pkey_alg, 
                              pubkey)) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Cannot get the public key parameters");
        return 0;
  };

  // Gets the type and the parameters
  X509_ALGOR_get0(NULL, &pkey_type, &params_value, pkey_alg);
  if (params_value) {
    // If we have parameters, we need to save them to the key
    if ((comp_key->params = ASN1_INTEGER_dup((ASN1_INTEGER *)params_value)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot duplicate the parameters");
      goto err;
    }
  };

  // Assigns the key in the EVP_PKEY structure
  if (!EVP_PKEY_assign_COMPOSITE(pk, comp_key)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot assign internal composite key structure to the key");
    goto err;
  }

  // All Done.
  return 1;

err:

  // Free the Stack of ASN1_TYPE
  while ((sk != NULL) &&
         (aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
    ASN1_TYPE_free(aType);
  } sk_ASN1_TYPE_free(sk);

  // Free the Composite Key
  if (comp_key) COMPOSITE_KEY_free(comp_key);

  // Error Condition
  return 0;

}

// Implemented
int pub_encode(X509_PUBKEY *pub, const EVP_PKEY *pk) {


  // Strategy:
  //
  // Get the COMPOSITE_KEY and encode each EVP_PKEY in a
  // separate X509_PUBKEY that is placed in an ASN1_OCTET_STRING
  // and then added to the generic SEQUENCE
  //
  // struct X509_pubkey_st {
  //    X509_ALGOR *algor;
  //    ASN1_BIT_STRING *public_key;
  //    EVP_PKEY *pkey;
  //  };
  //
  // Small Comments for ASN1_TYPE - The Structure is defined
  // in openssl/asn1.h and it is basically a type (int) and
  // a value (union). The value.sequence() is where you can
  // put the sequence to get encoded


  EVP_PKEY * tmp_pkey = NULL;
    // Containers for the different
    // encodings of the components

  X509_PUBKEY * tmp_pubkey = NULL;
    // Temp Structure for Privkey component

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the Composite Key
    // (just a STACK_OF(EVP_PKEY))

  ASN1_BIT_STRING * bit_string = NULL;
    // Output Buffer

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  unsigned char * buff = NULL;
  int buff_len = 0;
    // Temporary Storage for ASN1 data

  ASN1_INTEGER * key_param = NULL;
  int key_param_type = V_ASN1_UNDEF;
    // K of N parameter

  // Input Checking
  if (!pub || !pk) return 0;


  // First we should encode the parameters, however
  // in Composite, we do not have parameters, so we
  // can omit them entirely 

  // Gets the Key Bytes
  if ((comp_key = EVP_PKEY_get0(pk)) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the Key Inner Structure");
    return 0;
  }
  
  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new stack of ASN1 Types");
    if (key_param) ASN1_INTEGER_free(key_param);
    return 0;
  }

  // Gets the P8 info for each key and
  // adds it to the output stack
  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    // Get the component of the key
    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot access [%d] component of the key", i);
      goto err;
    }

    if (tmp_pkey->ameth->pub_encode == NULL) {
      PKI_ERROR(PKI_ERR_GENERAL, "Key %d of alg %d does not have a pub_encode ameth.",
          i, tmp_pkey->ameth->pkey_id);
      goto err;
    }

    // Sets the Public Key
    if(!X509_PUBKEY_set(&tmp_pubkey, tmp_pkey)) {
      PKI_ERROR(PKI_ERR_ALGOR_SET, "ERROR: Cannot set the PUBKEY for component #%d", i);
      goto err;
    }

    // Encodes the PUBLIC key
    if ((buff_len = i2d_X509_PUBKEY(tmp_pubkey, &buff)) <= 0) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot ASN1 encode the [%d] component of the key", i);
      goto err;
    }

    // Generates the wrapping string
    if ((bit_string = ASN1_OCTET_STRING_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new OCTET string for component %d", i);
      goto err;
    }

    // This sets and transfer ownership
    ASN1_STRING_set0(bit_string, buff, buff_len);

    // Resets the pointer and length after ownership transfer
    buff = NULL; buff_len = 0;

    // Let's free the X509_PUBKEY structure
    X509_PUBKEY_free(tmp_pubkey);
    tmp_pubkey = NULL;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new ASN1 Type");
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_SEQUENCE, bit_string);
    bit_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add the new Type to the stack of public keys");
      goto err;
    }

  }

  // Encodes the Sequence
  if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot ASN1 encode the stack of public keys");
    goto err;
  }

  // Free the stack's memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
  sk = NULL;

  // Encode the parameters (if any)
  if (comp_key->params) {
    PKI_DEBUG("Detected k-of-n parameter, processing it...\n");
    key_param_type = V_ASN1_INTEGER;
    key_param = ASN1_INTEGER_dup(comp_key->params);
    if (!key_param) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot duplicate the key parameters");
      return 0;
    }
  }

  // We do not have parameters    
  if (!X509_PUBKEY_set0_param(pub, OBJ_nid2obj(pk->ameth->pkey_id),
                        key_param_type, key_param, 
                         buff, buff_len)) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot encode the parameter");
    goto err;
  }

  // All Done
  return 1;

err:

  // Free allocated memory
  if (key_param) ASN1_INTEGER_free(key_param);
  if (buff && buff_len >= 0) OPENSSL_secure_clear_free(buff, (size_t) buff_len);
  if (bit_string) ASN1_BIT_STRING_free(bit_string);
  if (aType) ASN1_TYPE_free(aType);

  if (sk) {
    while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
      ASN1_TYPE_free(aType);
    }
    sk_ASN1_TYPE_free(sk);
    sk = NULL;
  }

  // Error Condition
  return 0;
}

// Implemented
int pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {

  // Strategy: We compare all keys from the two different
  // COMPOSITE_KEY within the EVP_PKEY ptr. If any difference,
  // we return !0

  COMPOSITE_KEY * comp_a = NULL;
  COMPOSITE_KEY * comp_b = NULL;
    // Pointers to inner data structures

  int ret = 0;
    // Return value

  // Input checks
  if (!a || !a->ameth || !b || !b->ameth) return -1;

  if (((comp_a = EVP_PKEY_get0(a)) == NULL) ||
      ((comp_b = EVP_PKEY_get0(b)) == NULL)) {
    // If any of the two is NULL, we return -1
    return -1;
  }

  // Checks both have (or not) parameters
  if ((comp_a->params && !comp_b->params) ||
      (!comp_a->params && comp_b->params) ) {
    // If one has parameters and the other not, we
    // return an error
    return -1;
  }

  // Checks the parameters
  if (ASN1_INTEGER_cmp(comp_a->params, comp_b->params) != 0) {
    // If the parameters are different, we return -1
    return -1;
  }

  // If the number of keys is different, we return -1
  if (COMPOSITE_KEY_num(comp_a) != COMPOSITE_KEY_num(comp_b)) {
    return -1;
  }

  // Compares all components
  for (int i = 0; i < COMPOSITE_KEY_num(comp_b); i++) {
    
    // 'get0' returns the i-th EVP_PKEY, then we apply
    // the call to the two returned ones from a and b

    ret = EVP_PKEY_cmp(
              COMPOSITE_KEY_get0(comp_a, i),
              COMPOSITE_KEY_get0(comp_b, i));

    if (ret != 0) return ret;
  }

  return 0;
}

// Implemented
int pub_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) {
  
  COMPOSITE_KEY * comp_key = NULL;

  if ((comp_key = EVP_PKEY_get0(pkey)) == NULL)
    return 0;

  if (!BIO_indent(out, indent, 128))
    return 0;

  PKI_ID pkey_id = PKI_X509_KEYPAIR_VALUE_get_id(pkey);

  BIO_printf(out, "Composite Public Alternative Keys (%d Equivalent Keys):\n",
    COMPOSITE_KEY_num(comp_key));

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    EVP_PKEY * tmp_pkey = NULL;

    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      BIO_printf(out, "%*s", indent, "");
      BIO_printf(out, "Public Key Component #%d (UNKNOWN): <ERROR>\n", i);
      continue;
    }

    BIO_printf(out, "%*s", indent, "");
    BIO_printf(out, "[%d] Public Key Component (%s):\n",
      i, OBJ_nid2ln(tmp_pkey->ameth->pkey_id));

    if (tmp_pkey->ameth->pub_print) {
      tmp_pkey->ameth->pub_print(out, tmp_pkey, indent + 8, pctx);
    } else {
      BIO_printf(out, "        <NO TEXT FORMAT SUPPORT>\n");
    }
  }

  if (pkey_id == OBJ_txt2nid("COMPOSITE_KEY") 
#ifdef ENABLE_COMBINED
      || pkey_id == OBJ_txt2nid("COMBINED_KEY")
#endif
      ) {
    BIO_printf(out, "%*s", indent, "");
    BIO_printf(out, "Required Valid Components Signatures (K-of-N): %ld (%ld-%d)\n",
      comp_key->params ? ASN1_INTEGER_get(comp_key->params) : -1, 
      comp_key->params ? ASN1_INTEGER_get(comp_key->params) : COMPOSITE_KEY_num(comp_key),
      COMPOSITE_KEY_num(comp_key));
  }

  return 1;
}

// Implemented
int priv_decode(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8) {

  // Strategy:
  //
  // GET the DER representation from the p8 info
  // then we can use the d21_ASN1_SEQUENCE_ANY() to get
  // the stack of P8.
  //
  // For each of the P8, we use the EVP_PKCS82PKEY() to
  // retrieve the corresponding PKEY. Once we have that,
  // we add it to the internal structure of the 'pk' param
  //
  // UPDATE: Let's look at using the auto type function,
  // which is crypto/asn1/d2i_pr.c:
  //
  //   EVP_PKEY *d2i_AutoPrivateKey(
  //                EVP_PKEY **a,
  //                const unsigned char **pp,
  //                long length)
  //
  // The P8 structure is quite simple and it is available
  // in includes/openssl/x509.h:
  //
  //   struct pkcs8_priv_key_info_st {
  //     ASN1_INTEGER *version;
  //     X509_ALGOR *pkeyalg;
  //     ASN1_OCTET_STRING *pkey;
  //     STACK_OF(X509_ATTRIBUTE) *attributes;
  //   };

  EVP_PKEY * tmp_pkey = NULL;
    // Containers for the different
    // encodings of the components

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the Composite Key
    // (just a STACK_OF(EVP_PKEY))

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  ASN1_OCTET_STRING inBitStr;
    // Temp Octet Pointer

  ASN1_OCTET_STRING outBitStr;
    // Temp BitString Pointer

  const void *params_value = NULL;
    // Value for the parameters

  const unsigned char *param_der = NULL;
  int param_len = 0;
    // Buffer

  const X509_ALGOR * pkey_alg;
  int pkey_type = 0;
    // Public Key Type and Algorithms

  // Input Checking
  if (!p8 || !pk) return 0;

  // Let's use the aOctetStr to avoid the internal
  // p8 pointers to be modified
  outBitStr.data = p8->pkey->data;
  outBitStr.length = p8->pkey->length;

  // Gets the Sequence from the data itself, error if
  // it is not a sequence of ASN1_OCTET_STRING
  if ((sk = d2i_ASN1_SEQUENCE_ANY(NULL, 
                (const unsigned char **)&outBitStr.data,
                outBitStr.length)) <= 0) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Cannot decode the composite key");
    return 0;
  }

  // Allocates Memory for the inner key structure
  if ((comp_key = COMPOSITE_KEY_new()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new internal composite key structure");
    goto err;
  }

  // Process the internal components
  for (int i = 0; i < sk_ASN1_TYPE_num(sk); i++) {

    // Gets the single values
    if ((aType = sk_ASN1_TYPE_value(sk, i)) == NULL) {
      PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, "Cannot get the ASN1_TYPE for key #%d", i);
      goto err;
    }

    // Checks we got the right type
    if ((aType->type != V_ASN1_SEQUENCE) || (aType->value.sequence == NULL)) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Decoding error on key component #%d", i);
      goto err;
    }

    // Sets the Pointers so that our original ones
    // are not moved (can cause memory issues)
    inBitStr.data = aType->value.sequence->data;
    inBitStr.length = aType->value.sequence->length;

    // Retrieve the EVP_PKEY from the ASN1_TYPE
    if ((tmp_pkey = d2i_AutoPrivateKey(NULL, 
                      (const unsigned char **)&(inBitStr.data),
                      (long)inBitStr.length)) == NULL) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Cannot decode key component #%d", i);
      goto err;
    }

    // Add the component to the key
    if (!COMPOSITE_KEY_push(comp_key, tmp_pkey)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add component key #%d", i);
      goto err;
    }
  }

  // ======================
  // Process Key Parameters
  // ======================

  // Retrieves the Public Key parameter
  if (!PKCS8_pkey_get0(NULL, 
                       &param_der, 
                       &param_len, 
                       &pkey_alg, 
                       p8)) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_DECODE, "Cannot get the public key parameters");
        return 0;
  };

  const ASN1_OBJECT * alg_oid;

  // Gets the type and the parameters
  X509_ALGOR_get0(&alg_oid, &pkey_type, &params_value, pkey_alg);
  if (params_value) {
    
    // Free current allocated params, if any
    if (comp_key->params) ASN1_INTEGER_free(comp_key->params);
    comp_key->params = NULL;

    // If we have parameters, we need to save them to the key
    if ((comp_key->params = ASN1_INTEGER_dup((ASN1_INTEGER *)params_value)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot duplicate the parameters");
      goto err;
    }
  };

  PKI_DEBUG("GOT THE KEY Algorithm OID: %d", OBJ_obj2nid(alg_oid));
    if (alg_oid) comp_key->algorithm = OBJ_obj2nid(alg_oid);

  // Free the stack memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
    ASN1_TYPE_free(aType);
  } sk_ASN1_TYPE_free(sk);
  sk = NULL; // Safety

  // Assigns the internal structure to the EVP key
  if (!EVP_PKEY_assign_COMPOSITE(pk, comp_key)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot assign Composite Key to EVP_PKEY!");
    goto err;
  }

  // All Done
  return 1;

err:

  // Free the Stack of ASN1_TYPE
  while ((sk != NULL) &&
        (aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
    ASN1_TYPE_free(aType);
  } sk_ASN1_TYPE_free(sk);

  // Free the Composite Key
  if (comp_key) COMPOSITE_KEY_free(comp_key);

  // Error Condition
  return 0;
}

// Implemented
int priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk) {

  // Strategy:
  //
  // GET the DER representation of the different keys
  // by using the same function EVP_PKEY2PKCS8(pkey),
  // then you can use the PKCS8_pkey_get0() to get the
  // binary representation (ASN1_OCTET_STRING)
  // put them into the p8/
  //
  // Small Comments for ASN1_TYPE - The Structure is defined
  // in openssl/asn1.h and it is basically a type (int) and
  // a value (union). The value.sequence() is where you can
  // put the sequence to get encoded

  EVP_PKEY * tmp_pkey = NULL;
    // Containers for the different
    // encodings of the components

  PKCS8_PRIV_KEY_INFO * tmp_pkey_info = NULL;
    // Temp Structure for Privkey component

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the Composite Key
    // (just a STACK_OF(EVP_PKEY))

  ASN1_BIT_STRING * bit_string = NULL;
    // Output Buffer

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  unsigned char * buff = NULL;
  int buff_len = 0;
    // Temporary Storage for ASN1 data

  ASN1_INTEGER * key_param = NULL;
  int key_param_type = V_ASN1_UNDEF;
    // K of N parameter

  // Input Checking
  if (!p8 || !pk) return 0;

  // Gets the Key Bytes
  if ((comp_key = EVP_PKEY_get0(pk)) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the inner composite key structure");
    return 0;
  }
  
  // Allocates the stack of private keys
  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the stack of private key components");
    return 0;
  }

  // Gets the P8 info for each key and
  // adds it to the output stack
  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    // Get the component of the key
    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot access [%d] component of the key", i);
      goto err;
    }

    // Generates the P8 info
    if ((tmp_pkey_info = EVP_PKEY2PKCS8(tmp_pkey)) == NULL) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot generate PKCS8 for [%d] component of the key", i);
      goto err;
    }

    // NOTE: buff must be set to NULL, otherwise OpenSSL
    // thinks there is an already allocated buffer and
    // writes to it and moves the pointer at the end
    buff = NULL;

    // Generates the DER encoding of the component
    if ((buff_len = i2d_PKCS8_PRIV_KEY_INFO(tmp_pkey_info, &buff)) <= 0) {
      PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot ASN1 encode the [%d] component of the key", i);
      goto err;
    }

    // Generates the wrapping OCTET string
    if ((bit_string = ASN1_BIT_STRING_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }

    // This sets and transfer ownership
    ASN1_STRING_set0(bit_string, buff, buff_len);

    // Resets the pointer and length after ownership transfer
    buff = NULL; buff_len = 0;

    // Let's free the X509_PUBKEY structure
    PKCS8_PRIV_KEY_INFO_free(tmp_pkey_info);
    tmp_pkey_info = NULL;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_SEQUENCE, bit_string);
    bit_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }
  }

  buff = NULL;
  if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, "Cannot ASN1 encode the Overall Composite Key");
    goto err;
  }

  // Free the stack's memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
    ASN1_TYPE_free(aType);
  }
  sk_ASN1_TYPE_free(sk);
  sk = NULL;

  // Encode the parameters (if any)
  if (comp_key->params) {
    key_param_type = V_ASN1_INTEGER;
    key_param = ASN1_INTEGER_dup(comp_key->params);
    if (!key_param) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot duplicate the key parameters");
      goto err;
    }
  }

  // PKI_DEBUG("PRIV. KEY. ENCODING: COMPOSITE KEY - algorithm = %d", comp_key->algorithm);
  // PKI_DEBUG("PRIV. KEY. ENCODING: EVP_PKEY TYPE - pk->type = %d, pk->save_type = %d", pk->type, pk->save_type);
  // PKI_DEBUG("PRIV. KEY. ENCODING: PKEY_AMETH - pkey_id = %d", pk->ameth->pkey_id);

  int my_nid = pk->save_type;
  ASN1_OBJECT * obj = OBJ_nid2obj(my_nid);

  // PKI_DEBUG("PRIV. KEY. ENCODING: my_nid = %d", my_nid);
  // PKI_DEBUG("PRIV. KEY. ENCODING: OBJ_nid2obj(%d) = %s", pk->save_type || pk->ameth->pkey_id, PKI_OID_get_descr(obj));

  // Sets the params for the P8
  if (!PKCS8_pkey_set0(p8, obj, 0, key_param_type, key_param, buff, buff_len)) {
    PKI_ERROR(PKI_ERR_GENERAL, "Cannot set the P8 null parameters contents");
    goto err;
  }

  // All Done.
  return 1;

err:

  // Free allocated memory
  if (key_param) ASN1_INTEGER_free(key_param);
  if (buff && buff_len >= 0) OPENSSL_secure_clear_free(buff, (size_t) buff_len);
  if (bit_string) ASN1_BIT_STRING_free(bit_string);

  // Free the Stack of ASN1_TYPE
  if (sk) {
    while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
      ASN1_TYPE_free(aType);
    }
    sk_ASN1_TYPE_free(sk);
    sk = NULL;
  }

  // Error Condition
  return 0;

}

// Implemented
int priv_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) {

  COMPOSITE_KEY * comp_key = NULL;

  if ((comp_key = EVP_PKEY_get0(pkey)) == NULL)
    return 0;

  if (!BIO_indent(out, indent, 128))
    return 0;

  BIO_printf(out, "Composite Alternative Keys (%d Equivalent Keys):\n",
    COMPOSITE_KEY_num(comp_key));

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    EVP_PKEY * tmp_pkey = NULL;

    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      BIO_printf(out, "    Key Component #%d (UNKNOWN): <ERROR>\n", i);
      continue;
    }

    BIO_printf(out, "    [%d] Key Component (%s):\n",
      i, OBJ_nid2ln(tmp_pkey->ameth->pkey_id));

    if (tmp_pkey->ameth->pub_print) {
      tmp_pkey->ameth->pub_print(out, tmp_pkey, indent + 8, pctx);
    } else {
      BIO_printf(out, "        <NO TEXT FORMAT SUPPORT>\n");
    }
  }

  BIO_printf(out, "Required Positive Components Validation (K-of-N): %d\n",
    COMPOSITE_KEY_get_kofn(comp_key));

  return 1;
}

// Implemented
int pkey_size(const EVP_PKEY *pk) {

  int ret = 0;
    // Return Value

  int key_num = 0;
    // Index for cycling across keys

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the inner structure

  EVP_PKEY * pkey = NULL;
    // Individual components keys

  // Input Check
  if (!pk || !pk->ameth) return 0;

  // Gets the Composite Key
  if ((comp_key = EVP_PKEY_get0(pk)) == NULL)
    return 0;

  // Gets the number of keys
  key_num = COMPOSITE_KEY_num(comp_key);

  // Process each key
  for (int i = 0; i < key_num; i++) {

    // Retrieves the individual component
    if ((pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the key material for component %d", i);
      return 0;
    }

    // Updates the total size
    ret += EVP_PKEY_size(pkey);

    // Adds 4 extra bytes for ASN1 encoding (long)
    ret += 4;
  }

  // Adds 4 extra bytes for encoding the sequence (long)
  ret += 4;

  // All Done
  return ret;
}

// Implemented
int pkey_bits(const EVP_PKEY *pk) {

  COMPOSITE_KEY * comp_Key = NULL;
    // Composite Key pointer

  // Input Checks
  if (pk == NULL) return 0;

  if ((comp_Key = EVP_PKEY_get0(pk)) == NULL) {
    DEBUG("ERROR: Cannot retrieve the Composite Key.");
    return 0;
  }

  // Gets the Bits from the COMPOSITE_KEY
  return COMPOSITE_KEY_bits(comp_Key);
}

// Implemented
int pkey_security_bits(const EVP_PKEY *pk) {

  // Strategy:
  //
  // For Alternative Keys (OR logic Operation),
  // we should report the minimum sec_bits level
  // as any of the keys can be used.
  //
  // For Combined Keys (AND logic Operation),
  // we should report the maximum sec_bits level
  // as all of the keys must be used.

  int sec_bits = INT_MAX;
    // Security Bits, we start with
    // the max value and return the lowest

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to the inner data structure

  // Input Checks
  if (pk == NULL) return 0;

  if ((comp_key = EVP_PKEY_get0(pk)) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot retrieve the Composite Key");
    return 0;
  }

  // Process the individual components
  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    EVP_PKEY * tmp_pkey = COMPOSITE_KEY_get0(comp_key, i);
      // Compnent's key

    int tmp_pkey_sec_bits = INT_MAX;
      // Security Bits, starts from INT_MAX

    if (tmp_pkey && tmp_pkey->ameth->pkey_security_bits) {
      // Checks if it is composite (OR) and use the lowest
      // of the current or pkey values
      tmp_pkey_sec_bits = 
          tmp_pkey->ameth->pkey_security_bits(tmp_pkey);
    }

    // If the current sec_bits is larger, let's get the
    // new (smaller) value
    sec_bits > tmp_pkey_sec_bits ? 
      sec_bits = tmp_pkey_sec_bits : sec_bits;
  }

  // If there are no components, we return '0'
  if (sec_bits == INT_MAX) return 0;

  // All Done.
  return sec_bits;
}

// // ========================
// // Key Parameters Functions
// // ========================

// // Not Implemented
// int param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen) {
//   // There are no parameters to decode, always succeed
//   return 1;
// }

// // Not Implemented
// int param_encode(const EVP_PKEY *pkey, unsigned char **pder) {
//   // There are no parameters to encode, always succeed
//   return 1;
// }

// // Not Implemented
// int param_missing(const EVP_PKEY *pk) {
//   // There are no parameters, we return 1 for
//   // indicating there are no missing parameters
//   // (error condition is 0)
//   // return 1;
// }

// // Not Implemented
// int param_copy(EVP_PKEY *to, const EVP_PKEY *from) {
//   // There are no parameters, we return 1 for
//   // indicating there are no missing parameters
//   // (error condition is 0)
//   return 1;
// }

// Implemented
int param_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {

  COMPOSITE_KEY * comp_a = NULL;
  COMPOSITE_KEY * comp_b = NULL;
    // Pointers to the inner data structure

  int param_a = -1;
  int param_b = -1;
    // Holds the parameters' values

  // Input Checks
  if (a == NULL || b == NULL) return -1;

  if ((comp_a = EVP_PKEY_get0(a)) == NULL ||
      (comp_b = EVP_PKEY_get0(b)) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot retrieve the Composite Key");
    return -1;
  }

  // Gets the parameters' values
  if (comp_a->params) param_a = (int) ASN1_INTEGER_get(comp_a->params);
  if (comp_b->params) param_b = (int) ASN1_INTEGER_get(comp_b->params);

  // Compares the values
  if (param_a == param_b) return 0;
  
  // All Done
  return (param_a > param_b ? 1 : -1);
}

// // Not Implemented
// int param_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) {
//   // There are no parameters to print, nothing to do
//   return 1;
// }

// Not Implemented
int sig_print(BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx) {
  BIO_printf(out, "<Composite Signature Bits>\n");
  return 0;
}

// Implemented
void pkey_free(EVP_PKEY *pk) {

  // Purpose: free the algorithm-specific
  // data structure
  COMPOSITE_KEY * comp_key = NULL;
    // Composite Key Pointer

  // Input Validation
  if (!pk || !pk->ameth) return;

  // Gets the Key Bytes
  if ((comp_key = pk->pkey.ptr /* EVP_PKEY_get0(pk) */ ) == NULL) {
    return;
  }

  // Clears the Key and Frees the memory
  COMPOSITE_KEY_free(comp_key);
  pk->pkey.ptr = NULL;

  // All Done.
  return;
}

// Implemented
int pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2) {

  COMPOSITE_KEY * comp_key = NULL;
    // Composite Key Pointer

  // Gets the Key Bytes
  if ((comp_key = (COMPOSITE_KEY *)EVP_PKEY_get0(pkey)) == NULL) {
    return 0;
  }

  /*
  # define ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
  # define ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
  # define ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
  # define ASN1_PKEY_CTRL_CMS_SIGN         0x5
  # define ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
  # define ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8
  */

  switch (op) {

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID: {
      // Deafault MD for the algorithm
      *(int *)arg2 = NID_undef; // NID_sha512;
    } break;

    case COMPOSITE_PKEY_CTRL_SET_K_OF_N: {
      // Sets the Valid Signature Requirement
      if (arg2) {
        if (PKI_OK != COMPOSITE_KEY_set_kofn(comp_key, *((int *)arg2))) {
          PKI_ERROR(PKI_ERR_GENERAL, "Can not set the K of N value");
          return 0;
        }
      }
    } break;

    case COMPOSITE_PKEY_CTRL_GET_K_OF_N: {
      // Gets the Valid Signature Requirement
      *(int *)arg2 = COMPOSITE_KEY_get_kofn(comp_key);
    } break;

    case ASN1_PKEY_CTRL_PKCS7_SIGN:
    case ASN1_PKEY_CTRL_CMS_SIGN: {
      // Signing Operation
    } break;

    case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
    case ASN1_PKEY_CTRL_CMS_ENVELOPE: {
      // Encryption Operation
    } break;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE: {
      // CMS RI Type Operation
    } break;

    default: {
      PKI_DEBUG("Unknown Operation [%d] (arg1 = %ld)", op, arg1);
      return 0;
    }

  }

  // All Done
  return 1;
}

// // ============================
// // Legacy Functions for old PEM
// // ============================

// // Not Implemented
// int old_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// int old_priv_encode(const EVP_PKEY *pkey, unsigned char **pder) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// ==================================
// Custom ASN1 signature verification
// ==================================

// Implemented
int item_verify(EVP_MD_CTX      * ctx, 
                const ASN1_ITEM * it, 
                void            * asn, 
                X509_ALGOR      * sigalg,
                ASN1_BIT_STRING * sig,
                EVP_PKEY        * pkey) {

  EVP_PKEY_CTX * pctx = NULL;
  EVP_PKEY * pkey_val = NULL;
    // OpenSSL's context

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * comp_key = NULL;
    // Composite Key and CTX pointers

  // Get the EVP_PKEY_CTX from the EVP_MD_CTX
  pctx = EVP_MD_CTX_pkey_ctx(ctx);
  if (!pctx) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the EVP_PKEY_CTX from the EVP_MD_CTX");
    return -1;
  }

  // Gets the Composite Context
  comp_ctx = pctx->data;
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Context from the EVP_PKEY_CTX");
    return -1;
  }

  // Get the Composite Key from the EVP_PKEY_CTX
  if ((pkey_val = EVP_PKEY_CTX_get0_pkey(pctx)) != NULL) {
    comp_key = EVP_PKEY_get0(pkey_val);
  }
  if (!comp_key) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Key from the EVP_PKEY_CTX");
  }

  // Gets the PKI_SCHEME_ID from the Composite Key
  PKI_SCHEME_ID scheme_id = PKI_X509_KEYPAIR_VALUE_get_scheme(pkey_val);
  if (scheme_id <= PKI_SCHEME_UNKNOWN) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the PKI_SCHEME_ID from the Composite Key");
    return -1;
  }

  // ======================
  // Process Key Parameters
  // ======================

  int pkey_type = 0;
  int md_type = 0;
    // Public Key Type and Algorithms

  X509_ALGORS * params = NULL;

  const void * packed_sequence;
    // Value for the parameters

  const PKI_OID *pkey_oid = NULL;
    // OID for the public key

  // Gets the type and the parameters
  X509_ALGOR_get0(&pkey_oid, &pkey_type, (const void **)&packed_sequence, sigalg);
  if (!packed_sequence) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the parameters from the X509_ALGOR");
    return -1;
  };

  // Let's see if we are using the hash-n-sign scheme
  // so that we can calculate the digest only once
  if (!OBJ_find_sigid_algs(OBJ_obj2nid(pkey_oid), &md_type, NULL)) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not find the signature algorithm");
    return -1;
  }

  // Sets the algorithm in the COMPOSITE_CTX that we use in
  // the PKEY_METH (digestverify).
  if (PKI_ERR == COMPOSITE_CTX_set_md(comp_ctx, EVP_get_digestbynid(md_type))) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not set the digest algorithm in the COMPOSITE context");
    return -1;
  }
  // Now we need to unpack the sequence of algorithms
  params = ASN1_TYPE_unpack_sequence(&X509_ALGORS_it, packed_sequence);
  if (params == NULL) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not unpack the sequence of algorithms");
    return -1;
  }

  PKI_DEBUG("params_value = %p (num = %d)", params, sk_X509_ALGOR_num(params));

  // Let's copy the parameters into the EVP_PKEY_CTX
  int success = COMPOSITE_CTX_algors_set0(comp_ctx, sk_X509_ALGOR_dup(params));
  if (!success) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not set the parameters into the EVP_PKEY_CTX");
    return -1;
  }

  /*
   * Return value of 2 means carry on, anything else means we exit
   * straight away: either a fatal error of the underlying verification
   * routine handles all verification.
   */

  // // This is needed to pass the list of algorithms
  // EVP_PKEY_CTX_set_app_data(pctx, (void *)a);

  return 2;
}

// Implemented
int item_sign(EVP_MD_CTX      * ctx, 
              const ASN1_ITEM * it, 
              void            * asn, 
              X509_ALGOR      * alg1, 
              X509_ALGOR      * alg2, 
              ASN1_BIT_STRING * sig) {

  EVP_PKEY_CTX * pctx = NULL;
  EVP_PKEY * pkey_val = NULL;
    // OpenSSL's context

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * comp_key = NULL;
    // Composite Key and CTX pointers

  X509_ALGORS * sig_algs = NULL;
    // List of signature algorithms

  int signature_id = NID_undef;
    // Signature ID

  /*
  * Return value meanings:
  * <=0: error.
  *   1: method does everything.
  *   2: carry on as normal.
  *   3: ASN1 method sets algorithm identifiers: just sign.
  * 
  * See ASN1_item_sign_ctx() at OPENSSL/crypto/asn1/a_sign.c:140
  */

  // Get the EVP_PKEY_CTX from the EVP_MD_CTX
  pctx = EVP_MD_CTX_pkey_ctx(ctx);
  if (!pctx) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the EVP_PKEY_CTX from the EVP_MD_CTX");
    return -1;
  }

  // Gets the Composite Context
  comp_ctx = pctx->data;
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Context from the EVP_PKEY_CTX");
    return -1;
  }

  // Get the Composite Key from the EVP_PKEY_CTX
  if ((pkey_val = EVP_PKEY_CTX_get0_pkey(pctx)) != NULL) {
    comp_key = EVP_PKEY_get0(pkey_val);
  }
  if (!comp_key) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Key from the EVP_PKEY_CTX");
  }

  // Gets the PKI_SCHEME_ID from the Composite Key
  PKI_SCHEME_ID scheme_id = PKI_X509_KEYPAIR_VALUE_get_scheme(pkey_val);
  if (scheme_id <= PKI_SCHEME_UNKNOWN) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the PKI_SCHEME_ID from the Composite Key");
    return -1;
  }

  // Here we shall generate and validate the list of components
  // when the pkey_id is one of the explicit composite
  if (PKI_SCHEME_ID_is_explicit_composite(scheme_id) == PKI_OK) {

    PKI_DEBUG("********* DETECTED EXPLICIT COMPOSITE ***************");
    PKI_DEBUG("MISSING CODE FOR AUTO-GENERATING THE X509_ALGORS LIST");
    PKI_DEBUG("********* DETECTED EXPLICIT COMPOSITE ***************");
    signature_id = EVP_PKEY_type(EVP_PKEY_id(pkey_val));

  } else {
    
    // Retrieves the Digest
    const EVP_MD * md = EVP_MD_CTX_md(ctx);
    if (!md) {
      // MD was not initialized by OpenSSL (this is due to the use of the
      // EVP_PKEY_FLAG_SIGCTX_CUSTOM flag in the EVP_PKEY_CTX)
      if (!EVP_DigestInit_ex(ctx, comp_ctx->md, NULL)) {
        PKI_ERROR(PKI_ERR_GENERAL, "Can not initialize the digest");
        return 0;
      }
    }
    
    // Gets the ID for the algorithm components
    int digest_id = NID_undef;
    int pkey_id = EVP_PKEY_id(pkey_val);

    if (md == PKI_DIGEST_ALG_NULL) {
      digest_id = NID_undef;
    } else if (md == NULL) {
      digest_id = PKI_DIGEST_ALG_ID_DEFAULT;
    } else {
      digest_id = EVP_MD_type(md);
    }

    PKI_DEBUG("***** Original Digest %d - Digest ID: %d", EVP_MD_type(md), digest_id);

    // Search for the Algorithm ID
    if (!OBJ_find_sigid_by_algs(&signature_id, digest_id, pkey_id)) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot find the Algorithm ID (digest: %d, pkey: %d)", 
        digest_id, pkey_id);
      return -1;
    }

    PKI_DEBUG("***** Found the Signature ID: %d", signature_id);
  }

  // Checks if we build the list of algorithms with defaults
  // or if we use the pre-configured list of algorithms
  if (comp_ctx->sig_algs) {
    // Use pre-configured list of algorithms
    sig_algs = comp_ctx->sig_algs;
  } else {
    // Let's use the list of keys from the Composite Key (attach)
    int success = COMPOSITE_CTX_components_set0(comp_ctx, comp_key->components);
    if (success == PKI_ERR) {
      PKI_ERROR(PKI_ERR_GENERAL, "Can not get the list of keys from the Composite Key");
      return -1;
    }
    // Build the list with defaults
    success = COMPOSITE_CTX_algors_new0(comp_ctx, signature_id, &sig_algs);
    if (!success || !sig_algs) {
      PKI_ERROR(PKI_ERR_GENERAL, "Can not get the list of algorithms from the Composite Key");
      // Removes the list of components from the context
      COMPOSITE_CTX_components_detach(comp_ctx, NULL);
      return -1;
    }
    // Removes the list of components from the context
    COMPOSITE_CTX_components_detach(comp_ctx, NULL);
  }

  // Pack the list of algorithms
  ASN1_STRING * param_str = NULL;
  param_str = ASN1_item_pack(sig_algs, ASN1_ITEM_rptr(X509_ALGORS), NULL);
  if (!param_str) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not pack the list of algorithms");
    return -1;
  }

  // Sets the Algorithm IDs
  if (alg1 != NULL)
    X509_ALGOR_set0(alg1, OBJ_nid2obj(signature_id), V_ASN1_SEQUENCE, param_str);

  if (alg2 != NULL) {
    // We need to duplicate the parameter string
    ASN1_STRING * param_str_dup = ASN1_STRING_dup(param_str);
    X509_ALGOR_set0(alg2, OBJ_nid2obj(signature_id), V_ASN1_SEQUENCE, param_str_dup);
  }

  // Should return 3 to indicate that the algorithm identifiers
  // are already set.
  return 3;
}

// Not Implemented
int siginf_set(X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig) {
  fprintf(stderr, "%s:%d: DEBUG: siginf_set() called\n", __FILE__, __LINE__);
  return 1;
}

// ===================
// EVP Check Functions
// ===================

int pkey_check(const EVP_PKEY *pkey) {

  COMPOSITE_KEY * comp_key = NULL;

  // Input Checks
  if (!pkey) return 0;

  // Retrieves the Composite Key internal structure
  if ((comp_key = EVP_PKEY_get0(pkey)) == NULL) return 0;

  // Checks we have at least one component
  if (COMPOSITE_KEY_num(comp_key) < 1) return 0;

  // Process each component
  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    EVP_PKEY * tmp_pkey = NULL;
      // Pointer to the individual component

    // If we cannot get any component, we have a problem
    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) return 0;

    // We need an ASN1 method
    if (!tmp_pkey->ameth) return 0;

    // If the component has the check, let's perform
    // it on the single component and return 0 if any
    // of these fail at the component level
    if (tmp_pkey->ameth->pkey_check && tmp_pkey->ameth->pkey_check(tmp_pkey) == 0) {
      PKI_DEBUG("ERROR: Key Check failed for Composite Key Component #%d", i);
      return 0;
    }
  }

  // All Done
  return 1;
}

// Not Implemented
int pkey_public_check(const EVP_PKEY *pkey) {
  
  COMPOSITE_KEY * comp_key = NULL;

  if (!pkey) return 0;

  if ((comp_key = EVP_PKEY_get0(pkey)) == NULL)
    return 0;

  if (COMPOSITE_KEY_num(comp_key) < 1)
    return 0;

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {
    EVP_PKEY * tmp_pkey = NULL;

    // If we cannot get any component, we have a problem
    if ((tmp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL)
      return 0;

    // We need an ASN1 method
    if (!tmp_pkey->ameth) return 0;

    // If the component has the check, let's perform
    // it on the single component and return 0 if any
    // of these fail at the component level
    if (tmp_pkey->ameth->pkey_public_check) {
      if (tmp_pkey->ameth->pkey_public_check(tmp_pkey) == 0) {
        return 0;
      }
    }
  }

  return 1;
}

// Not Implemented
int pkey_param_check(const EVP_PKEY *pkey) {
  return 1;
}

// // =================================
// // Get/Set For Raw priv/pub key data
// // =================================

// // Not Implemented
// int set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// int set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// int get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// int get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// ===========================
// ASN1 PKEY Method Definition
// ===========================

// The Definition of the EVP_PKEY_ASN1_METHOD is provided above and
// it is taken from OPENSSL_SRC/include/crypto/asn1.h, see the
// OPENSSL_SRC/include/ossl_typ.h
EVP_PKEY_ASN1_METHOD composite_asn1_meth = {
    0,                        // int pkey_id; // EVP_PKEY_COMPOSITE
    0,                        // int pkey_base_id; // EVP_PKEY_COMPOSITE
    0,                        // unsigned long pkey_flags; ASN1_PKEY_SIGPARAM_NULL
    "COMPOSITE",              // char *pem_str;
    "Composite Crypto With Combined Keys", // char *info;
    pub_decode,               // int (*pub_decode) (EVP_PKEY *pk, X509_PUBKEY *pub);
    pub_encode,               // int (*pub_encode) (X509_PUBKEY *pub, const EVP_PKEY *pk);
    pub_cmp,                  // int (*pub_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
    pub_print,                // int (*pub_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);

    priv_decode,              // int (*priv_decode) (EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);
    priv_encode,              // int (*priv_encode) (PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);
    priv_print,               // int (*priv_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
    
    pkey_size,                // int (*pkey_size) (const EVP_PKEY *pk);
    pkey_bits,                // int (*pkey_bits) (const EVP_PKEY *pk);
    pkey_security_bits,       // int (*pkey_security_bits) (const EVP_PKEY *pk);
    
    0, // param_decode,             // int (*param_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
    0, // param_encode,             // int (*param_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    0, // param_missing,            // int (*param_missing) (const EVP_PKEY *pk);
    0, // param_copy,               // int (*param_copy) (EVP_PKEY *to, const EVP_PKEY *from);
    0, // param_cmp,                // int (*param_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
    0, // param_print,              // int (*param_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
    
    sig_print,                // int (*sig_print) (BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx);
    pkey_free,                // void (*pkey_free) (EVP_PKEY *pkey);
    pkey_ctrl,                // int (*pkey_ctrl) (EVP_PKEY *pkey, int op, long arg1, void *arg2);
    // Legacy Functions for old PEM
    0, // old_priv_decode,          // int (*old_priv_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
    0, // old_priv_encode,          // int (*old_priv_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    // Custom ASN1 signature verification
    item_verify,              // int (*item_verify) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey);
    item_sign,                // int (*item_sign) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig);
    siginf_set,               // int (*siginf_set) (X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig);
    // PKEY checking interface
    pkey_check,               // int (*pkey_check) (EVP_PKEY *pkey);
    pkey_public_check,        // int (*pkey_public_check) (EVP_PKEY *pkey);
    pkey_param_check,         // int (*pkey_param_check) (EVP_PKEY *pkey);
    0, // set_priv_key,             // int (*set_priv_key) (EVP_PKEY *pk, const unsigned char *priv, size_t len);
    0, // set_pub_key,              // int (*set_pub_key) (EVP_PKEY *pk, const unsigned char *pub, size_t len);
    0, // get_priv_key,             // int (*get_priv_key) (const EVP_PKEY *pk, unsigned char *priv, size_t *len);
    0, // get_pub_key,              // int (*get_pub_key) (const EVP_PKEY *pk, unsigned char *pub, size_t *len);
};

#endif

/* END: composite_amenth.c */
