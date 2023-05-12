/* BEGIN: composite_pmeth.c */

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#include <libpki/openssl/composite/composite_pmeth.h>
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

// =========================
// EVP_PKEY_METHOD Functions
// =========================

// Implemented
static int init(EVP_PKEY_CTX *ctx) {
  
  COMPOSITE_CTX *comp_ctx = NULL;

  // Allocate Memory
  if ((comp_ctx = COMPOSITE_CTX_new_null()) == NULL) return 0;

  // Assigns the algorithm-specific data
  // to the data field
  ctx->data = comp_ctx;

  // These are used during Key Gen to display
  // '.', '+', '*', '\n' during key gen
  ctx->keygen_info = NULL;
  ctx->keygen_info_count = 0;

  // All Done
  return 1;
}

// Implemented
static void cleanup(EVP_PKEY_CTX * ctx) {

  // Input Check
  if (!ctx) return;

  // Retrieves the internal context
  if (ctx->data) COMPOSITE_CTX_free((COMPOSITE_CTX *)ctx->data);
  ctx->data = NULL;

  // All Done
  return;
}

// Implemented
static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * key = NULL;

  // Input Validation
  if (!ctx || !ctx->data || !pkey) return 0;

  // // Some extra checking for correctness
  // if (ctx->pmeth->pkey_id != OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID)) {
  //   PKI_DEBUG("NID is not NID_composite (%d vs. %d)", 
  //     ctx->pmeth->pkey_id, OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID));
  //   return 0;
  // }

  // Checks we have the right data and items
  comp_ctx = ctx->data;
  if (!comp_ctx) {
    // No components present in the key
    PKI_ERROR(PKI_ERR_ALGOR_SET, "Empty Stack of Keys when generating a composed key");
    return 0;
  }

  // // Allocates the Composite Key
  // if ((key = COMPOSITE_KEY_new_null()) == NULL) {
  //   PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
  //   return 0;
  // }

  // // Processes
  // for (int i = 0; i < COMPOSITE_CTX_num(comp_ctx); i++ ) {

  //   EVP_PKEY * tmp_pkey = NULL;
  //     // Pointer to the single component's key

  //   // Retrieves the i-th component
  //   if (!COMPOSITE_CTX_pkey_get0(comp_ctx, &tmp_pkey, i) || (tmp_pkey == NULL)) {
  //     PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add PKEY to Composite Key component #%d", i);
  //     COMPOSITE_KEY_free(key);
  //     return 0;
  //   }

  //   // Adds the key in the key stack
  //   COMPOSITE_KEY_push(key, tmp_pkey);
  // }

  // Transfer the components from the CTX
  if (key->components) COMPOSITE_KEY_STACK_free(key->components);
  key->components = comp_ctx->components;
  comp_ctx->components = NULL;

  // Transfers the parameter
  if (key->params) ASN1_INTEGER_free(key->params);
  key->params = comp_ctx->params;
  comp_ctx->params = NULL;

  // Resets the list of components on the CTX
  comp_ctx->components = COMPOSITE_KEY_STACK_new_null();

  // NOTE: To Get the Structure, use EVP_PKEY_get0(EVP_PKEY *k)
  // NOTE: To Add the Key Structure, use EVP_PKEY_assign()
  EVP_PKEY_assign_COMPOSITE(pkey, key);

  // All Done.
  return 1;
}

// Implemented
static int sign(EVP_PKEY_CTX        * ctx, 
                unsigned char       * sig,
                size_t              * siglen,
                const unsigned char * tbs,
                size_t                tbslen) {

  // int counter = 0;

  X509_ALGORS * sig_algs = NULL;
    // Pointer to the signature algorithms

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to inner key structure

  EVP_PKEY_CTX * pkey_ctx = NULL;
  EVP_PKEY * evp_pkey = NULL;
    // The keypair and context references

  EVP_MD_CTX * md_ctx = NULL;
    // Digest Context

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  ASN1_BIT_STRING * bit_string = NULL;
    // Output Signature to be added
    // to the stack of signatures

  int signature_size = -1;
    // The total signature size

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int comp_key_num = 0;
    // Number of components

  int use_global_hash = 0;
  unsigned char global_hash[EVP_MAX_MD_SIZE];
  size_t global_hashlen = 0;
    // Temp Variables

  unsigned char * buff = NULL;
  unsigned char * pnt  = NULL;
  int buff_len =  0;
    // Temp Pointers

  int ret_code = 0;
    // Return Code for external calls

  int index = 0;
  int total_size = 0;
    // Total Signature Size

  // Input Checks
  if (!ctx || !tbs) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return -1;
  }

  // Gets the composite context
  comp_ctx = ctx->data;
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "No composite context found");
    return -1;
  }

  // Gets the signature algorithms
  sig_algs = comp_ctx->sig_algs;

  PKI_DEBUG("Composite X509_ALGORS: %p", sig_algs);
  PKI_DEBUG("Composite X509_ALGORS: %d", sk_X509_ALGOR_num(sig_algs));

  // Gets the internal key
  evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  if (!evp_pkey) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "No public key found in the context");
    return -1;
  }
  
  // Gets the internal key
  comp_key = EVP_PKEY_get0(evp_pkey);
  if (!comp_key) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "No composite key found in the public key");
    return -1;
  }

  // Checks we have a good stack of components
  comp_key_num = COMPOSITE_KEY_num(comp_key);
  if (comp_key_num <= 0) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the Composite key inner structure");
    return 0;
  }

  /* WARNING: This does not account for extra space for parameters */
  signature_size = EVP_PKEY_size(ctx->pkey); 

  // If no signature buffer is passed, we just return the size
  if (sig == NULL) {
    *siglen = (size_t)signature_size;
    return 1;
  }

  // If we use the hash-n-sign method, we need to hash the data
  // only once, let's do it before the loop in this case
  if (comp_ctx->md && comp_ctx->md != PKI_DIGEST_ALG_NULL) {

    // Indicates we do not need to hash the data again
    use_global_hash = 1;

    // Calculates the Digest (since we use custom digest, the data is not
    // hashed when it is passed to this function)
    int ossl_ret = EVP_Digest(tbs, tbslen, &global_hash[0], (unsigned int *)&global_hashlen, comp_ctx->md, NULL);
    if (ossl_ret == 0) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
      return 0;
    }
  }

  // ================================
  // Components' Signature Generation
  // ================================

  // Allocates the Stack for the signatures
  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the stack of signature");
    goto err;
  }

  // Generates Each Signature Independently
  for (index = 0; index < comp_key_num; index++) {

    PKI_X509_ALGOR_VALUE * alg = NULL;
      // Temp Algorithm Pointer

    PKI_DEBUG("Generating Signature Component #%d", index);

    // Retrieves the i-th component
    if ((evp_pkey = COMPOSITE_KEY_get0(comp_key, index)) == NULL) {
      // PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th component from Key", index);
      goto err;
    }

    // Let's build a PKEY CTX and assign it to the MD CTX
    pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (!pkey_ctx) {
      // PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the %d PKEY CTX component", index);
      goto err;
    }

    // Initializes the Signing process
    ret_code = EVP_PKEY_sign_init(pkey_ctx);
    if (ret_code != 1) {
      // PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, 
      //   "Cannot initialize %d component signature (EVP_PKEY_sign_init code %d)", 
      //   index, ret_code);
      goto err;
    }

    // Retrieves the i-th algorithm
    if ((alg = sk_X509_ALGOR_value(sig_algs, index)) == NULL) {
      // PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th algorithm from Composite Key", index);
      goto err;
    }

    // Checks we have the same algorithm for the key
    int algorithm_pkey_type = 0;
    int md_type = 0;

    OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm), &md_type, &algorithm_pkey_type);
    if (algorithm_pkey_type != EVP_PKEY_type(EVP_PKEY_id(evp_pkey))) {
      // PKI_DEBUG("Algorithm %d does not match the key's algorithm %d when processing component #%d", 
      //   algorithm_pkey_type, EVP_PKEY_id(evp_pkey), index);
      goto err;
    }

    // Gets the Signature's Max Size
    buff_len = EVP_PKEY_size(evp_pkey);

    // Allocate the buffer for the single signature
    if ((pnt = buff = OPENSSL_malloc((size_t)buff_len)) == NULL) {
      // PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the %d-th component signature's buffer");
      goto err;
    }

    // Hash-n-Sign Method
    if (use_global_hash) {

      // PKI_DEBUG("Using Hash-n-Sign method for component #%d", index);
      
      // Signature's generation
      ret_code = EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, global_hash, global_hashlen);
      if (ret_code != 1) {
        DEBUG("Cannot initialize signature for %d component (EVP_PKEY_sign code is %d)", index, ret_code);
        goto err;
      }

      // PKI_DEBUG("END: Using Hash-n-Sign method for component #%d", index);

    } else {
      
      // Checks if we need to hash the data first
      if (md_type != PKI_ID_UNKNOWN) {

        // PKI_DEBUG("Using DIGEST (%d) signing method for component #%d", md_type, index);

        unsigned char hash_data[EVP_MAX_MD_SIZE];
        size_t hash_data_len = 0;
        
        // Calculates the Digest (since we use custom digest, the data is not
        // hashed when it is passed to this function)
        int ossl_ret = EVP_Digest(tbs, tbslen, hash_data, (unsigned int *)hash_data_len, EVP_get_digestbynid(md_type), NULL);
        if (ossl_ret == 0) {
          PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
          goto err;
        }

        // Sign the hashed data
        ret_code = EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, hash_data, hash_data_len);
        if (ret_code != 1) {
          // DEBUG("Cannot initialize signature for %d component (EVP_PKEY_sign code is %d)", index, ret_code);
          goto err;
        }

        // PKI_DEBUG("END: Using DIGEST (%d) signing method for component #%d", md_type, index);

      } else {

        // PKI_DEBUG("Using NO DIGEST (direct signing) method for component #%d", index);
        
        // Sign the data directly
        ret_code = EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen);
        if (ret_code != 1) {
          // DEBUG("Cannot initialize signature for %d component (EVP_PKEY_sign code is %d)", index, ret_code);
          goto err;
        }

        // PKI_DEBUG("END: Using NO DIGEST (direct signing) method for component #%d", index);
      }
    }

    // Removes the reference to the key. This is
    // needed because we otherwise will have memory
    // issue when calling EVP_PKEY_CTX_free()
    pkey_ctx->pkey = NULL;

    // Free the PKEY context
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL; // Safety

    // Updates the overall real size
    total_size += buff_len;

    PKI_DEBUG("Generated Signature for Component #%d Successfully (size: %d)", index, buff_len);
    PKI_DEBUG("Signature Total Size [So Far] ... %d", total_size);

    if ((bit_string = ASN1_BIT_STRING_new()) == NULL) {
      PKI_DEBUG("Cannot allocate the wrapping OCTET STRING for signature's %d component", index);
      goto err;
    }

    // This sets the internal pointers
    ASN1_STRING_set0(bit_string, pnt, buff_len);
    pnt = NULL; buff_len = 0;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot Allocate a new ASN1 Type for signature wrapping");
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_BIT_STRING, bit_string);
    bit_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      PKI_DEBUG("Cannot push the signature's %d component", index);
      goto err;
    }

    // Transfers ownership
    aType = NULL;

    // PKI_DEBUG("Done Processing Composite component %d, counter = %d", index, counter);
    // counter++;
  }

  PKI_DEBUG("End of Signature Generation for All Components (%d)", index);
  PKI_DEBUG("End of Signature Generation for All Components");

  if ((*siglen = (size_t) i2d_ASN1_SEQUENCE_ANY(sk, &sig)) <= 0) {
    PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, "Cannot generate DER representation of the sequence of signatures");
    goto err;
  }

  // Reporting the total size
  PKI_DEBUG("Total Signature Size: %d (estimated: %d)", *siglen, signature_size);

  // Free the stack's memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
    ASN1_TYPE_free(aType);
  } sk_ASN1_TYPE_free(sk);
  sk = NULL;

  // Success
  return 1;

err:
  // Debugging
  PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);

  // Free allocated memory
  if (md_ctx) EVP_MD_CTX_free(md_ctx);
  if (bit_string) ASN1_OCTET_STRING_free(bit_string);
  if (buff && buff_len) PKI_ZFree(buff, (size_t) buff_len);
  if (pkey_ctx) {
    pkey_ctx->pkey = NULL;
    EVP_PKEY_CTX_free(pkey_ctx);
  }
  // if (evp_pkey) EVP_PKEY_free(evp_pkey);

  // Handles the stack of signatures
  if (sk) {
    while(sk_ASN1_TYPE_num(sk) > 0) { 
      sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
    }
    if (sk) sk_ASN1_TYPE_free(sk);
  }

  // Error
  return 0;
}

// Implemented
static int verify(EVP_PKEY_CTX        * ctx,
                  const unsigned char * sig,
                  size_t                siglen,
                  const unsigned char * tbs,
                  size_t                tbslen) {
 
  const X509_ALGORS * params = NULL;
    // Pointer to parameters

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to inner key structure

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int ret_code = 0;
    // OSSL return code

  int comp_key_num = 0;
    // Number of components

  ASN1_BIT_STRING aBitStr;
    // Temp Bit String

  EVP_PKEY_CTX * pkey_ctx = NULL;
  EVP_PKEY * evp_pkey = NULL;
    // The keypair and context references

  // Input Checks
  comp_key_num = COMPOSITE_KEY_num(comp_key);
  if (comp_key_num <= 0) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the Composite key inner structure");
    return 0;
  }

  // Gets the Composite Context
  comp_ctx = (ctx ? ctx->data : NULL);
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Context from the EVP_PKEY_CTX");
    return -1;
  }

  // Get the Composite Key from the EVP_PKEY_CTX
  if ((evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx)) != NULL) {
    comp_key = EVP_PKEY_get0(evp_pkey);
  }
  if (!comp_key) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Composite Key from the EVP_PKEY_CTX");
  }

  // Gets the PKI_SCHEME_ID from the Composite Key
  PKI_SCHEME_ID scheme_id = PKI_X509_KEYPAIR_VALUE_get_scheme(evp_pkey);
  if (scheme_id <= PKI_SCHEME_UNKNOWN) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the PKI_SCHEME_ID from the Composite Key");
    return -1;
  }

  // Gets the Parameters from the Composite CTX
  if (PKI_ERR == COMPOSITE_CTX_algors_get0(comp_ctx, &params)) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get the Parameters from the Composite Context");
    return -1;
  }

  // Let's use the aOctetStr to avoid the internal
  // p8 pointers to be modified
  aBitStr.data = (unsigned char *)sig;
  aBitStr.length = (int) siglen;

  // Gets the Sequence from the data itself, error if
  // it is not a sequence of ASN1_OCTET_STRING
  if ((sk = d2i_ASN1_SEQUENCE_ANY(NULL, 
                                  (const unsigned char **)&aBitStr.data,
                                  aBitStr.length)) <= 0) {
    PKI_ERROR(PKI_ERR_GENERAL, "Cannot decode the composite signature.");
    return 0;
  }

  // Debugging
  PKI_DEBUG("Signature Sequence is Unpacked (Num: %d)!", sk_ASN1_TYPE_num(sk));

  // Checks we have the right number of components
  if (sk_ASN1_TYPE_num(sk) != comp_key_num) {
    PKI_DEBUG("Wrong number of signature's components (%d instead of %d)",
      sk_ASN1_TYPE_num(sk), comp_key_num);
    PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
    goto err;
  }
  if (sk_X509_ALGOR_num(params) != comp_key_num) {
    PKI_DEBUG("Wrong number of signature's components (%d instead of %d)",
      sk_X509_ALGOR_num(params), comp_key_num);
    PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
    goto err;
  }

  // Retrieves the K-of-N parameter from the Composite Key
  int required_validations = COMPOSITE_KEY_get_kofn(comp_key);
  if (required_validations <= 0 || required_validations > comp_key_num) {
    PKI_DEBUG("Wrong K-of-N parameter for the Composite Key detected (%d)", required_validations);
    return -1;
  }

  // Process the internal components
  for (int i = 0; i < sk_ASN1_TYPE_num(sk); i++) {

    unsigned char hashed_data[EVP_MAX_MD_SIZE];
    unsigned int hashed_data_len = 0;
      // Hashed data

    const unsigned char * tbs_data = NULL;
    size_t tbs_datalen = 0;
      // Signature data

    X509_ALGOR * sig_param = NULL;
      // Inividual signature's parameters

    const ASN1_OBJECT * sig_oid;
      // Signature OID

    int sig_pkey_id = 0;
    int md_id = 0;
      // Signature and Hashing Algorithm IDs

    // Gets the single values
    if ((aType = sk_ASN1_TYPE_value(sk, i)) == NULL) {
      PKI_DEBUG("Cannot get the ASN1_TYPE for signature #%d", i);
      return 0;
    }

    // Checks we got the right type
    if ((aType->type != V_ASN1_BIT_STRING) || (aType->value.sequence == NULL)) {
      PKI_DEBUG("Decoding error on signature component #%d (type: %d, value: %p)", 
        i, aType->type, aType->value.sequence);
      return 0;
    }

    // PKI_MEM * mem = NULL;
    // char buff[1024];
    // snprintf(buff, sizeof(buff), "%d_signature_to_verify.bin", i);
    // mem = PKI_MEM_new_data((size_t)aType->value.sequence->length, aType->value.sequence->data);
    // URL_put_data(buff, mem, NULL, NULL, 0, 0, NULL);
    // PKI_MEM_free(mem);

    // snprintf(buff, sizeof(buff), "%d_data_to_verify.bin", i);
    // mem = PKI_MEM_new_data((size_t)tbslen, tbs);
    // URL_put_data("data_to_verify.bin", mem, NULL, NULL, 0, 0, NULL);
    // PKI_MEM_free(mem);

    // Retrieves the i-th parameter to get the specific
    // algorithm to use for hashing, signing, and parameters
    // generation for the individual signatures.
    if ((sig_param = sk_X509_ALGOR_value(params, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th component of signature parameters", i);
      goto err;
    }

    // Retrieves the i-th component
    if ((evp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th component from Key", i);
      goto err;
    }

    // STRATEGY:
    //
    // Check if we are using hash-n-sing, if so, the data was
    // already hashed, let's just sign it
    if (comp_ctx->md) {
      // Global Hash-n-Sign (already hashed, just sign the data)
      tbs_data = tbs;
      tbs_datalen = tbslen;
    } else {

      int success = 0;
        // Return code for the hashing function

      const EVP_MD * md = NULL;
        // MD to use for hashing

      // Global Direct Signing (i.e., hashing is performed on a 
      /// per algorithm basis). Let's get the MD.
      X509_ALGOR_get0(&sig_oid, &sig_pkey_id, NULL, sig_param);
      if (sig_pkey_id != EVP_PKEY_type(EVP_PKEY_id(evp_pkey))) {
        PKI_DEBUG("Signature component #%d is not of the right type, expected (%d) but found (%d)", 
          i, EVP_PKEY_type(EVP_PKEY_id(evp_pkey)), sig_pkey_id);
        goto err;
      }
      // Let's retrieve the MD to use for hashing
      if (!OBJ_find_sigid_algs(OBJ_obj2nid(sig_oid), &md_id, NULL)) {
        PKI_DEBUG("Cannot find the MD for signature component #%d", i);
        goto err;
      }
      // Let's check that, if the MD is NULL, the algorithm can support it
      if (md_id == NID_undef && PKI_ID_requires_digest(sig_pkey_id)) {
        PKI_DEBUG("MD for signature component #%d is NULL, but the pkey (%d) requires a digest", i);
        goto err;
      }

      // Let's calculate the Digest, if needed
      if (md_id != NID_undef) {
        md = EVP_get_digestbynid(md_id);
        if (!md) {
          PKI_DEBUG("Cannot get the MD for signature component #%d", i);
          goto err;
        }
        // Calculates the Digest (since we use custom digest, the data is not
        // hashed when it is passed to this function)
        success = EVP_Digest(tbs, tbslen, hashed_data, &hashed_data_len, md, NULL);
        if (success <= 0) {
          PKI_DEBUG("Cannot calculate the digest for signature component #%d", i);
          PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
          return 0;
        }
        tbs_data = hashed_data;
        tbs_datalen = hashed_data_len;
      }
    }

    // Let's build a PKEY CTX and assign it to the MD CTX
    pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (!pkey_ctx) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the %d PKEY CTX component", i);
      goto err;
    }

    // Initializes the Verify operation
    ret_code = EVP_PKEY_verify_init(pkey_ctx);
    if (ret_code != 1) {

      PKI_DEBUG("Cannot initialize %d component signature (ret code: %d)", i, ret_code);
      
      // // We might need to remove the pkey reference before freeing the pkey_ctx
      // pkey_ctx->pkey = NULL;
      if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
      pkey_ctx = NULL; // Safety

      // Checks if we have enough signatures to validate the data
      if (required_validations >= (comp_key_num - i)) {
        PKI_DEBUG("[%d/%d] Composite verify failure (required validations: %d, remaining: %d)",
          i, comp_key_num, required_validations, (comp_key_num - i - 1));
        goto err;
      }

      // Skip this component and continue with the next one
      continue;
    }

    // Verifies the individual signature
    ret_code = EVP_PKEY_verify(pkey_ctx, 
                               aType->value.sequence->data,
                               (size_t)aType->value.sequence->length,
                               tbs_data,
                               (size_t)tbs_datalen);
    
    // // We might need to remove the pkey reference before freeing the pkey_ctx
    // pkey_ctx->pkey = NULL;
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL; // Safety

    // Checks the results of the verify
    if (ret_code != 1) {
      // Checks if we have enough signatures to validate the data
    if (required_validations >= (comp_key_num - i)) {
      PKI_DEBUG("[%d/%d] Composite verify failure (required validations: %d, remaining: %d)",
        i, comp_key_num, required_validations, (comp_key_num - i - 1));
      goto err;
    }
    // Skip this component and continue with the next one
    continue;
    }

    // // Removes the reference to the pkey. This is needed
    // // because the EVP_PKEY_CTX_free() will otherwise
    // // try to free the memory of the pkey
    // pkey_ctx->pkey = NULL;

    // // Free the EVP_PKEY_CTX
    // if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    // pkey_ctx = NULL; // Safety
    
    // Debugging
    PKI_DEBUG("Signature Component #%d Validated Successfully!", i);

    // Updates the counter for the required validations
    required_validations--;

    // Checks if we can declare victory or if we still have
    // to validate more signatures
    if (required_validations <= 0) {
      PKI_DEBUG("All required signatures validated successfully, skipping the remaining ones (%d)",
        (comp_key_num - i - 1));
      break;
    }
  }

  // Free the stack memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
  sk = NULL;

  // Debugging
  PKI_DEBUG("PMETH Verify Completed Successfully!");

  // All Done.
  return 1;

err:

  // Debugging
  PKI_DEBUG("PMETH Verify Error Condition, releasing resources.");

  // Free the stack memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);

  // Free other memory objects
  if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
  if (evp_pkey) EVP_PKEY_free(evp_pkey);

  // Error
  return 0;
}

// Implemented
static int ctrl(EVP_PKEY_CTX *ctx, int type, int key_id, void *value) {

  // NOTE: The passed ctx does not have the PKEY
  // associated with it. This means we cannot act
  // on the key

  COMPOSITE_CTX * comp_ctx = ctx ? ctx->data : NULL;
    // Pointer to the Composite CTX

  EVP_PKEY * pkey = ctx && ctx->pkey ? ctx->pkey : NULL;;
    // Pointer to the PKEY to add/del

  COMPOSITE_KEY * comp_pkey = pkey ? EVP_PKEY_get0(pkey) : NULL;
    // Pointer to the Composite Key

  // Input checks
  if (!comp_ctx || !comp_pkey) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing CTX (%p) or PKEY (%p)", comp_ctx, comp_pkey);
    return 0;
  }

  // PKI_DEBUG("PKEY_CTRL: Setting (ctrl) (type = %d) (key_id = %d, value = %p)",
  //       type, key_id, value);

  switch (type) {

    // ===================
    // OpenSSL CTRL Values
    // ===================

    case EVP_PKEY_CTRL_GET_MD: {
      *(const EVP_MD **)value = comp_ctx->md;
    } break;

    case EVP_PKEY_CTRL_MD: {

      // Here we need to allocate the digest for each key in the
      // stack (if not there, let's allocate the memory and
      // initialize it)

      // Input checks
      if (!value) {
        PKI_DEBUG("Missing 2nd parameter (value)");
        return 0;
      }

      // Sets the MD
      comp_ctx->md = value;

      // All Done
      return 1;

    } break;


    case EVP_PKEY_OP_TYPE_SIG: {
      // Signature is supported
      return 1;
    } break;

    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
    case EVP_PKEY_CTRL_SET_MAC_KEY:
    case EVP_PKEY_CTRL_SET_IV: {
      DEBUG("ERROR: Non Supported CTRL");
      return -2;
    } break;

    case EVP_PKEY_CTRL_DIGESTINIT: {
      return 1;
    } break;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
    case EVP_PKEY_CTRL_CIPHER: {
      // DEBUGGING
      PKI_DEBUG("CTRL: type = %d, param_1 = %d, param_2 = %p", type, key_id, value);
      PKI_DEBUG("CTRL: No action taken for type = %d", type);
      // All Done
      return 1;
    } break;

    // =====================
    // COMPOSITE CTRL Values
    // =====================

    case EVP_PKEY_CTRL_COMPOSITE_PUSH: {
      // Adds the Key to the internal stack
      if (!COMPOSITE_KEY_STACK_push(comp_ctx->components, (EVP_PKEY *)value)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot add component (type %d) to composite key", pkey->type);
        return 0;
      }
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_ADD: {
      // Adds the Key to the internal stack
      if (!COMPOSITE_KEY_STACK_add(comp_ctx->components, (EVP_PKEY *)value, key_id)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot add component (type %d) to composite key", pkey->type);
        return 0;
      }
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_DEL: {
      // Checks we have the key_id component
      if (key_id <= 0 || key_id >= COMPOSITE_KEY_STACK_num(comp_ctx->components)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE, "Component %d does not exists (max is %d)", 
          key_id, COMPOSITE_KEY_STACK_num(comp_ctx->components));
        return 0;
      }
      // Delete the specific item from the stack
      COMPOSITE_KEY_STACK_del(comp_ctx->components, key_id);
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_POP: {
      
      PKI_X509_KEYPAIR_VALUE * tmp_key = NULL;
        // Pointer to the value to pop

      // Checks we have at least one component
      if (key_id <= 0 || key_id >= COMPOSITE_KEY_STACK_num(comp_ctx->components)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE, "Component %d does not exists (max is %d)", 
          key_id, COMPOSITE_KEY_STACK_num(comp_ctx->components));
        return 0;
      }
      
      // Pops a Key
      tmp_key = COMPOSITE_KEY_STACK_pop(comp_ctx->components);
      
      // Free the associated memory
      if (tmp_key) EVP_PKEY_free(tmp_key);

      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_CLEAR: {
      // Clears all components from the key
      COMPOSITE_KEY_STACK_clear(comp_ctx->components);
      // All Done
      return 1;
    } break;

    default: {
      PKI_ERROR(PKI_ERR_GENERAL, "[PKEY METHOD] Unrecognized CTRL option [%d]", type);
      return 0;
    }
  }

  // Returns OK
  return 1;
}

// // Not Implemented
// static int ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value) {
//   DEBUG("Not implemented, yet.");
//   return 0;
// }

// ===================
// OpenSSL 1.1.x+ Only
// ===================

// Implemented
static int digestsign(EVP_MD_CTX          * ctx,
                      unsigned char       * sig,
                      size_t              * siglen,
                      const unsigned char * tbs,
                      size_t                tbslen) {

  int ossl_ret = 0;
    // OpenSSL return code

  EVP_PKEY_CTX * p_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    // PKEY context

  if (!p_ctx) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  }

  ossl_ret = sign(p_ctx, sig, siglen, tbs, tbslen);
  if (ossl_ret == 0) {
    PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
    return 0;
  }

  return 1;
}

// Implemented
static int digestverify(EVP_MD_CTX          * ctx, 
                        const unsigned char * sig,
                        size_t                siglen,
                        const unsigned char * tbs,
                        size_t                tbslen) {

  unsigned char tbs_hash[EVP_MAX_MD_SIZE];
  unsigned int tbs_hash_len = 0;
    // Container for the Hashed value

  const unsigned char * tbs_data = NULL;
  size_t tbs_datalen = 0;
    // Pointer to the actual data to be signed
    // (hash-n-sign or direct signing)

  int ossl_ret = 0;
    // OpenSSL return code

  EVP_PKEY_CTX * pctx = EVP_MD_CTX_pkey_ctx(ctx);
    // PKEY context

  COMPOSITE_CTX * comp_ctx = NULL;
    // Composite Context

  if (!ctx || !pctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return 0;
  }

  // Gets the Composite Context
  comp_ctx = pctx->data;
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
    return 0;
  }

  // Checks if we have a digest-n-sign situation or if
  // we are directly signing the data
  if (!EVP_PKEY_CTX_get_signature_md(pctx, NULL)) {
    // No Hash-n-Sign requested, we use the data directly
    tbs_data = tbs;
    tbs_datalen = tbslen;
  } else {
    // Calculates the Digest (since we use custom digest, the data is not
    // hashed when it is passed to this function)
    ossl_ret = EVP_Digest(tbs, tbslen, tbs_hash, &tbs_hash_len, EVP_MD_CTX_md(ctx), NULL);
    if (ossl_ret == 0) {
      PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
      return 0;
    }
    // Use the Digest as the data to be signed
    tbs_data = tbs_hash;
    tbs_datalen = tbs_hash_len;
  }

  // Verifies and Returns the result
  ossl_ret = verify(pctx, sig, siglen, tbs_data, tbs_datalen);
  if (ossl_ret == 0) PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);

  // Returns the result
  return ossl_ret;
}

// // Not Implemented
// static int check(EVP_PKEY *pkey) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// static int public_check(EVP_PKEY *pkey) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// static int param_check(EVP_PKEY *pkey) {
//   PKI_DEBUG("Not implemented, yet.");
//   return 0;
// }

// // Not Implemented
// static int digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
//   PKI_DEBUG("Not implemented, yet. Returning Ok anyway.");
//   return 1;
// }

// ======================
// PKEY Method Definition
// ======================
//
// The Definition of the EVP_PKEY_METHOD is a typedef
// of the evp_pkey_method_st from:
// - OPENSSL_SRC/crypto/evp/evp_locl.h (OPENSSL_VERSION <= 1.1.0 or prior)
// - OPENSSL_SRC/crypto/include/internal/evp_int.h (OPENSSL_VERSION >= 1.1.X+)

// NOTE: When the EVP_PKEY_FLAG_SIGCTX_CUSTOM is used, then we can
// return a NULL as a default MD, otherwise OpenSSL will stop the
// execution (see the do_sigver_init() at m_sigver.c:25) because
// it gets the default digest nid (EVP_PKEY_get_default_digest_nid())
// and if tht returns NULL, it assumes it has no valid default
// and returns an error (NO_DEFAULT_DIGEST).

// NOTE: The EVP_PKEY_FLAG_SIGCTX_CUSTOM, when you do not implement
// the signctx_ and verifyctx_ functions, has the side effect to not
// initialize the EVP_MD_CTX * that is passed via the EVP_DigestSign
// interface.

EVP_PKEY_METHOD composite_pkey_meth = {
    0,              // int pkey_id; // EVP_PKEY_COMPOSITE
    0,              // int flags; //EVP_PKEY_FLAG_SIGCTX_CUSTOM
    init,           // int (*init)(EVP_PKEY_CTX *ctx);
    0, // copy,     // int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    cleanup,        // void (*cleanup)(EVP_PKEY_CTX *ctx);
    0,              // paramgen_init,  // int (*paramgen_init)(EVP_PKEY_CTX *ctx);
    0,              // int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    0,              // int (*keygen_init)(EVP_PKEY_CTX *ctx);
    keygen,         // int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    0,              // int (*sign_init) (EVP_PKEY_CTX *ctx);
    sign,           // int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    0,              // verify_init,    // int (*verify_init) (EVP_PKEY_CTX *ctx);
    verify,         // int (*verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    0,              // verify_recover_init,  // int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    0,              // verify_recover, // int (*verify_recover) (EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig, size_t siglen);
    0,              // signctx_init,   // int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    0,              // signctx,        // int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);
    0,              // verifyctx_init, // int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    0,              // verifyctx,      // int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx);
    0,              // encrypt_init,   // int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    0,              // encrypt,        // int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    0,              // decrypt_init,   // int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    0,              // decrypt,        // int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    0,              // derive_init,    // int (*derive_init) (EVP_PKEY_CTX *ctx);
    0,              // derive,         // int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    ctrl,           // int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    0,              // int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    // These are only available on OpenSSL v1.1.X+ //
    digestsign,     // int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    digestverify,   // int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    0,              // int (*check) (EVP_PKEY *pkey);
    0,              // int (*public_check) (EVP_PKEY *pkey);
    0,              // int (*param_check) (EVP_PKEY *pkey);
    0,              // int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
#endif
};

#endif // ENABLE_COMPOSITE

/* END: composite_pmeth.c */
