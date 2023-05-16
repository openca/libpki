/* BEGIN: composite_pmeth.c */

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#include <libpki/openssl/composite/composite_pmeth.h>
#endif

#ifndef _LIBPKI_ID_H
#include <libpki/pki_id.h>
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

static const int DUMP_SIGNATURE_DATA = 1;
  // Dumps the signature data to persistent files

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

  EVP_PKEY * pkey = NULL;
    // Pointer to the larger composite key

  X509_ALGORS * sig_algs = NULL;
    // Pointer to the signature algorithms

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to inner key structure

  unsigned char global_hash_data[EVP_MAX_MD_SIZE];
  size_t global_hash_data_len = 0;
    // Buffer for hashed data (when no global hash is used
    // and the algorithm still requires hashing)

  EVP_MD_CTX * md_ctx = NULL;
    // Digest Context

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  int signature_size = -1;
    // The total signature size

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int comp_key_num = 0;
    // Number of components

  const unsigned char * tbs_data;
  size_t tbs_data_len = 0;
    // Temporary TBS Data and Length

  const EVP_MD * global_hash;
  int use_global_hash = 0;
    // Flag to use the global hash

  int ret_code = 0;
    // Return Code for external calls

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
  
  // Detects the use of global has
  if (comp_ctx->md && comp_ctx->md != PKI_DIGEST_ALG_NULL) {
    // Sets the indicator to use the global hash
    use_global_hash = 1;
    global_hash = comp_ctx->md;
  }

  // Gets the signature algorithms
  sig_algs = comp_ctx->sig_algs;

  PKI_DEBUG("Composite X509_ALGORS: %p", sig_algs);
  PKI_DEBUG("Composite X509_ALGORS: %d", sk_X509_ALGOR_num(sig_algs));

  // Gets the internal key
  pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  if (!pkey) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "No public key found in the context");
    return -1;
  }
  
  // Gets the internal key
  comp_key = EVP_PKEY_get0(pkey);
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

  // ============================
  // Handles the Hash-n-Sign case
  // ============================

  if (use_global_hash) {
    
    PKI_DEBUG("Detected hash-n-sign algorithm (global hash: %s), hashing data", EVP_MD_name(global_hash));

    // We need to hash the data before signing, so we
    // do it once and then we sign the hash
    int ossl_ret = EVP_Digest(tbs, tbslen, global_hash_data, (unsigned int *)&global_hash_data_len, global_hash, NULL);
    if (ossl_ret == 0) {
      PKI_DEBUG("Error while hashing data (ossl_ret=%d)", ossl_ret);
      goto err;
    }
    // Let's point the pointers to the hashed data and its size
    tbs_data = global_hash_data;
    tbs_data_len = global_hash_data_len;

    PKI_DEBUG("Using the Hash-n-Sign data: %p (size: %d)", tbs_data, tbs_data_len);

  } else {

    // No global hash, we need to hash the data
    // or do direct signing
    tbs_data = tbs;
    tbs_data_len = tbslen;

    PKI_DEBUG("Using the Direct Signing of the data: %p (size: %d)", tbs_data, tbs_data_len);
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
  for (int idx = 0; idx < comp_key_num; idx++) {

    PKI_X509_ALGOR_VALUE * alg = NULL;
      // Temp Algorithm Pointer

    unsigned char x_hash[EVP_MAX_MD_SIZE];
    size_t x_hash_len = 0;
      // Buffer for hashed data (when no global hash is used
      // and the algorithm still requires hashing)

    unsigned char * x_tbs_data = NULL;
    size_t x_tbs_data_len =  0;
      // Temp Pointers

    unsigned char * sig_buff = NULL;
    size_t sig_buff_len =  0;
      // Temp Pointers

    EVP_PKEY_CTX * x_pkey_ctx = NULL;
    EVP_PKEY * x_pkey = NULL;
      // The keypair and context references

    int x_pkey_type = NID_undef;
    int x_pkey_size = 0;
      // The type of the key for the component

    int algorithm_pkey_type = 0;
    int md_type = 0;
      // Algorithm and MD Type

    ASN1_BIT_STRING * bit_string = NULL;
      // Output Signature to be added
      // to the stack of signatures

    PKI_DEBUG("Generating Signature Component #%d", idx);

    // Make sure we use the right data
    x_tbs_data = (unsigned char *)tbs_data;
    x_tbs_data_len = tbs_data_len;

    PKI_DEBUG("Initial Data Size is %lu for Component #%d", x_tbs_data_len, idx);

    // Retrieves the i-th component
    if ((x_pkey = COMPOSITE_KEY_get0(comp_key, idx)) == NULL) {
      PKI_DEBUG("Cannot get %d-th component from Key", idx);
      goto err;
    }

    // Retrieves the type of key
    x_pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(x_pkey);
    if (x_pkey_type == NID_undef) {
      PKI_DEBUG("Cannot get %d-th component type from Key", idx);
      goto err;
    }

    // Retrieves the i-th algorithm
    if ((alg = sk_X509_ALGOR_value(sig_algs, idx)) == NULL) {
      PKI_DEBUG("Cannot get %d-th algorithm from Composite Key", idx);
      goto err;
    }

    if (!use_global_hash) {

      PKI_DEBUG("Not Hash-n-Sign - Let's see if we need to hash the data for component #%d", idx);
      
      // Checks we have the same algorithm for the key
      OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm), &md_type, &algorithm_pkey_type);
      if (algorithm_pkey_type != x_pkey_type) {
        PKI_DEBUG("Algorithm %d does not match the key's algorithm %d when processing component #%d", 
          algorithm_pkey_type, x_pkey_type, idx);
        goto err;
      }

      PKI_DEBUG("Parsed Algorithm from the Sig Algs Stack: %d (md type: %d, key type: %d)", 
        OBJ_obj2nid(alg->algorithm), md_type, algorithm_pkey_type);

      // Calculates the Digest (since we use custom digest, the data is not
      // hashed when it is passed to this function)
      if (md_type > 0) {

        PKI_DEBUG("Using Digest Signing for component %d (digest: %s) [tbs_data: %p, tbs_data_len: %d]", 
          idx, EVP_MD_name(EVP_get_digestbynid(md_type)), tbs_data, tbs_data_len);

        PKI_DEBUG("Buffer Information: x_hash: %p, x_hash_len: %lu", x_hash, x_hash_len);

        int ossl_ret = EVP_Digest(tbs_data, tbs_data_len, x_hash, (unsigned int *)&x_hash_len, EVP_get_digestbynid(md_type), NULL);
        if (ossl_ret <= 0) {
          PKI_DEBUG("Error while hashing data (ossl_ret=%d)", ossl_ret);
          goto err;
        }

        x_tbs_data = x_hash;
        x_tbs_data_len = x_hash_len;

        PKI_DEBUG("New data to sign afer generating the Hash for component %d (data: %p, size: %lu)", idx, x_tbs_data, x_tbs_data_len);

      } else {

        PKI_DEBUG("Using Direct Signing for component %d (data size: %d)", idx, x_tbs_data_len);

      }
    }

    PKI_DEBUG("After Logic - Data (%p) and Size (%lu) for Component #%d", x_tbs_data, x_tbs_data_len, idx);


    // // Hash-n-Sign Method
    // if (!use_global_hash && md_type != PKI_ID_UNKNOWN) {

    //     PKI_DEBUG("Using individual DIGEST (%d) signing method for component #%d", md_type, idx);
        
    //     // Calculates the Digest (since we use custom digest, the data is not
    //     // hashed when it is passed to this function)
    //     int ossl_ret = EVP_Digest(tbs, tbslen, x_hash, (unsigned int *)x_hash_len, EVP_get_digestbynid(md_type), NULL);
    //     if (ossl_ret == 0) {
    //       PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
    //       goto err;
    //     }

    //     x_tbs_data = x_hash;
    //     x_tbs_data_len = x_hash_len;

    //     // if (alg) 
    //     //   ASN1_item_sign(comp_ctx->asn1_item, alg, NULL, NULL, NULL, evp_pkey, EVP_get_digestbynid(md_type));

    //     // PKI_DEBUG("END: Using DIGEST (%d) signing method for component #%d", md_type, idx);
    // } else {

    //   // Some debugging info
    //   PKI_DEBUG("Using Direct Signing method for component #%d", idx);
    // }

    //   } else {

    //     PKI_DEBUG("Using NO DIGEST (direct signing) method for component #%d", idx);
        
    //     // Sign the data directly
    //     ret_code = EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen);
    //     if (ret_code != 1) {
    //       // DEBUG("Cannot initialize signature for %d component (EVP_PKEY_sign code is %d)", idx, ret_code);
    //       goto err;
    //     }

    //     if (alg) 
    //       ASN1_item_sign(comp_ctx->asn1_item, alg, NULL, NULL, NULL, evp_pkey, EVP_get_digestbynid(md_type));

    //     // PKI_DEBUG("END: Using NO DIGEST (direct signing) method for component #%d", idx);
    //   }
    // }

    // Checks we have good data pointers
    if (!x_tbs_data || x_tbs_data_len <= 0) {
      PKI_DEBUG("Missing data for component %d (x_tbs_data: %p, x_tbs_data_len: %d)", 
        idx, tbs_data, tbs_data_len);
      goto err;
    }

    // Gets the Signature's Max Size
    x_pkey_size = EVP_PKEY_size(x_pkey);
    if (x_pkey_size <= 0) {
      PKI_DEBUG("Cannot get the size of the %d-th component signature", idx);
      goto err;
    } 
    
    // Saves the size of the buffer to be allocated for the signature
    sig_buff_len = (size_t)x_pkey_size;

    // Allocate the buffer for the single signature
    if ((sig_buff = OPENSSL_malloc(sig_buff_len)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }

    // Let's build a PKEY CTX and assign it to the MD CTX
    x_pkey_ctx = EVP_PKEY_CTX_new(x_pkey, NULL);
    if (!x_pkey_ctx) {
      PKI_DEBUG("Cannot allocate a new CTX for the %d component's signature operation", idx);
      PKI_Free(sig_buff);
      goto err;
    }

    // Initializes the Signing process
    ret_code = EVP_PKEY_sign_init(x_pkey_ctx);
    if (ret_code <= 0) {
      PKI_DEBUG("EVP_PKEY_sign_init() failed with code %d", ret_code);
      PKI_Free(sig_buff);
      EVP_PKEY_CTX_free(x_pkey_ctx);
      goto err;
    }

    // Debugging Info
    PKI_DEBUG("Signing Data (tbs_data: %p, tbs_data_len: %d)", x_tbs_data, x_tbs_data_len);

    // Signature's generation
    ret_code = EVP_PKEY_sign(x_pkey_ctx, sig_buff, (size_t *)&sig_buff_len, x_tbs_data, x_tbs_data_len);
    if (ret_code <= 0) {
      PKI_DEBUG("Cannot generate signature for %d component (EVP_PKEY_sign code is %d)", idx, ret_code);
      PKI_Free(sig_buff);
      EVP_PKEY_CTX_free(x_pkey_ctx);
      goto err;
    }

    // // Signature's generation
    // ret_code = EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs_data, tbs_data_len);
    // if (ret_code <= 0) {
    //   DEBUG("Cannot generate signature for %d component (EVP_PKEY_sign code is %d)", idx, ret_code);
    //   goto err;
    // }

    // Removes the reference to the key. This is
    // needed because we otherwise will have memory
    // issue when calling EVP_PKEY_CTX_free()
    PKI_DEBUG("Freeing the PKEY reference (pkey: %p) - This might not be good, removing it.", x_pkey_ctx->pkey);
    // pkey_ctx->pkey = NULL;

    // Free the PKEY context
    if (x_pkey_ctx) EVP_PKEY_CTX_free(x_pkey_ctx);
    x_pkey_ctx = NULL; // Safety

    if (DUMP_SIGNATURE_DATA == 1) {

      PKI_DEBUG("Dumping %d Component Signature data (%d_signature.bin)", idx, idx);

      PKI_MEM * mem = NULL;
      char buff_name[1024];
      snprintf(buff_name, sizeof(buff_name), "%d_signature.bin", idx);
      mem = PKI_MEM_new_data(sig_buff_len, sig_buff);
      URL_put_data(buff_name, mem, NULL, NULL, 0, 0, NULL);
      PKI_MEM_free(mem);

      PKI_DEBUG("Dumping %d Component TBS data (%d_signature_tbs.bin)", idx, idx);

      snprintf(buff_name, sizeof(buff_name), "%d_signature_tbs.bin", idx);
      mem = PKI_MEM_new_data((size_t)x_tbs_data_len, x_tbs_data);
      URL_put_data(buff_name, mem, NULL, NULL, 0, 0, NULL);
      PKI_MEM_free(mem);
    }

    // Updates the overall real size
    total_size += sig_buff_len;

    // Debugging Info
    PKI_DEBUG("Generated Signature for Component #%d Successfully (size: %d)", idx, sig_buff_len);
    PKI_DEBUG("Signature Total Size [So Far] ... %d", total_size);

    if ((bit_string = ASN1_BIT_STRING_new()) == NULL) {
      PKI_DEBUG("Cannot allocate the wrapping OCTET STRING for signature's %d component", idx);
      PKI_Free(sig_buff);
      goto err;
    }

    // This sets the internal pointers
    ASN1_STRING_set0(bit_string, sig_buff, (int)sig_buff_len);
    sig_buff = NULL; sig_buff_len = 0;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot Allocate a new ASN1 Type for signature wrapping");
      ASN1_STRING_free(bit_string);
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_BIT_STRING, bit_string);
    bit_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      PKI_DEBUG("Cannot push the signature's %d component", idx);
      ASN1_TYPE_free(aType);
      goto err;
    }

    // Transfers ownership
    aType = NULL;

    // PKI_DEBUG("Done Processing Composite component %d, counter = %d", idx, counter);
    // counter++;
  }

  PKI_DEBUG("End of Signature Generation for All Components");

  if ((*siglen = (size_t) i2d_ASN1_SEQUENCE_ANY(sk, &sig)) <= 0) {
    PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, "Cannot generate DER representation of the sequence of signatures");
    goto err;
  }

  // Reporting the total size
  PKI_DEBUG("Total Signature Size: %d (overhead: %d) (estimated: %d)", *siglen, ((int)*siglen - total_size), signature_size);

  if (DUMP_SIGNATURE_DATA == 1) {

    PKI_DEBUG("Dumping Global Signature data (global_signature.bin)");

    PKI_MEM * mem = NULL;
    char buff_name[1024];
    snprintf(buff_name, sizeof(buff_name), "global_signature.bin");
    mem = PKI_MEM_new_data((size_t)*siglen, sig);
    URL_put_data(buff_name, mem, NULL, NULL, 0, 0, NULL);
    PKI_MEM_free(mem);

    PKI_DEBUG("Dumping Global Signature TBS (global_signature_tbs.bin)");

    snprintf(buff_name, sizeof(buff_name), "global_signature_tbs.bin");
    mem = PKI_MEM_new_data((size_t)tbs_data_len, tbs_data);
    URL_put_data(buff_name, mem, NULL, NULL, 0, 0, NULL);
    PKI_MEM_free(mem);
  }
  
  // Free the stack's memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
  sk = NULL;

  // Success
  return 1;

err:
  // Debugging
  PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);

  // Free allocated memory
  if (md_ctx) EVP_MD_CTX_free(md_ctx);
  md_ctx = NULL;

  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
  sk = NULL; // Safety

  // Error
  return 0;
}

// Implemented
static int verify(EVP_PKEY_CTX        * ctx,
                  const unsigned char * sig,
                  size_t                siglen,
                  const unsigned char * tbs,
                  size_t                tbslen) {

  // PKI_X509_ALGOR_VALUE * algor = NULL;
  //   // X509_ALGOR structure
 
  // X509_ALGORS * params = NULL;
  //   // Pointer to parameters

  EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    // Pointer to the key

  COMPOSITE_KEY * comp_key = pkey ? EVP_PKEY_get0(pkey) : NULL;
    // Pointer to inner key structure

  COMPOSITE_CTX * comp_ctx = EVP_PKEY_CTX_get_data(ctx);
    // Pointer to the context

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  int ret_code = 0;
    // OSSL return code

  int comp_key_num = 0;
    // Number of components

  // Checks the validation policy
  int successful_validations = 0;
  int required_valid_components = -1;
    // Number of required valid signatures

  ASN1_BIT_STRING aBitStr;
    // Temp Bit String

  int pkey_type = 0;
    // The keypair and context references

  int use_global_hash = 0;
    // Use the global hash for all components

  // Input Checks
  if (!pkey || !comp_key || !comp_ctx) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing PKEY, Composite Key, or Composite CTX");
    return 0;
  }

  // Checks the number of components
  comp_key_num = comp_key ? COMPOSITE_KEY_num(comp_key) : -1;
  if (comp_key_num <= 0) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the Composite key inner structure");
    return 0;
  }

  // Retrieves the PKEY type (or ID)
  pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(pkey);
  if (pkey_type <= 0) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the PKEY type");
    return 0;
  }

  // Check for the use of a global hash
  if (comp_ctx->md && comp_ctx->md != EVP_md_null()) {
    use_global_hash = 1;
  }

  PKI_DEBUG("Using Global Hash: %d", use_global_hash);

  // Signature Validation Policy
  if (COMPOSITE_KEY_has_kofn(comp_key)) {
    // Retrieves the policy
    required_valid_components = COMPOSITE_KEY_get_kofn(comp_key);
  } else {
    // If the policy is not set, we assume that all the components
    // are required to be valid
    required_valid_components = comp_key_num;
  }

  PKI_DEBUG("Required Valid Components: %d", required_valid_components);

  // // Retrieve the app data (if any)
  // algor = (PKI_X509_ALGOR_VALUE *)EVP_PKEY_CTX_get_app_data(ctx);
  // if (!algor) {
  //   PKI_DEBUG("No App Data Found, using SHA512 as default.");
  //   PKI_DEBUG("We should add the CTRL interface to set the default MD.");
  // }

  // if (algor) {

  //   const ASN1_OBJECT * obj;

  //   X509_ALGOR_get0(&obj, NULL, (const void **)&params, algor);
  //   PKI_DEBUG("Parsing the Parameters: #%d", sk_X509_ALGOR_num(params));
  // }

  // Let's use the aOctetStr to avoid the internal
  // p8 pointers to be modified
  aBitStr.data = (unsigned char *)sig;
  aBitStr.length = (int) siglen;

  // Gets the Sequence from the data itself, error if
  // it is not a sequence of ASN1_OCTET_STRING
  if ((sk = d2i_ASN1_SEQUENCE_ANY(NULL, 
                                  (const unsigned char **)&aBitStr.data,
                                  aBitStr.length)) <= 0) {
    PKI_DEBUG("Cannot decode the composite signature.");
    return 0;
  }

  // Debugging
  PKI_DEBUG("Signature Sequence is Unpacked (Num: %d)!", sk_ASN1_TYPE_num(sk));

  // Checks we have the right number of components
  if (sk_ASN1_TYPE_num(sk) != comp_key_num) {
    PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, 
      "Wrong number of signature's components (%d instead of %d)",
      sk_ASN1_TYPE_num(sk), comp_key_num);
    return 0;
  }

  // Checks the parameters, if we have any
  if (!comp_ctx->sig_algs || sk_X509_ALGOR_num(comp_ctx->sig_algs) <= 0) {
    PKI_DEBUG("No configured set of parameters for composite, generating default ones");
    if (!COMPOSITE_CTX_algors_new0(comp_ctx, pkey_type, comp_ctx->asn1_item, comp_key->components, NULL)) {
      PKI_DEBUG("Cannot configure the validation parameters");
      return 0;
    }
  } else {
    PKI_DEBUG("Using the configured set of parameters for composite!");
  }

  if (DUMP_SIGNATURE_DATA == 1) {

    PKI_MEM * mem = NULL;
    char buff[1024];
    snprintf(buff, sizeof(buff), "global_signature_to_verify.bin");
    mem = PKI_MEM_new_data((size_t)siglen, sig);
    URL_put_data(buff, mem, NULL, NULL, 0, 0, NULL);
    PKI_MEM_free(mem);

    snprintf(buff, sizeof(buff), "global_data_to_verify.bin");
    mem = PKI_MEM_new_data((size_t)tbslen, tbs);
    URL_put_data(buff, mem, NULL, NULL, 0, 0, NULL);
    PKI_MEM_free(mem);
  }

  // Resets the validations tracker
  successful_validations = 0;

  // Process the internal components
  for (int i = 0; i < sk_ASN1_TYPE_num(sk); i++) {

    const unsigned char * tbs_data;
    size_t tbs_data_len = 0;
      // Pointer to the data to be signed

    const unsigned char hashed_data[EVP_MAX_MD_SIZE];
    size_t hashed_data_len = 0;
      // Pointer to the hashed data

    EVP_PKEY * comp_evp_pkey = NULL;
    EVP_PKEY_CTX * comp_pkey_ctx = NULL;
    const EVP_MD * comp_md;
      // EVP_PKEY, EVP_PKEY_CTX, and EVP_MD for the component

    ASN1_TYPE * aType = NULL;
      // ASN1 generic wrapper

    PKI_DEBUG("Star Validating Signature Component #%d", i);

    // Sets the pointers for the validations
    tbs_data = tbs;
    tbs_data_len = tbslen;

    // Returns, if no more validations are required
    if (successful_validations >= required_valid_components) {
      PKI_DEBUG("Required number of valid signatures (%d) reached", required_valid_components);
      break;
    }
    
    // Returns, if not enough validations are possible
    if (required_valid_components - successful_validations > comp_key_num - i) {
      PKI_DEBUG("Required number of valid signatures (%d) not reachable", required_valid_components);
      goto err;
    }

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

    if (DUMP_SIGNATURE_DATA == 1) {

      PKI_DEBUG("Dumping Signature Component #%d", i);

      PKI_MEM * mem = NULL;
      char buff[1024];
      snprintf(buff, sizeof(buff), "%d_signature_to_verify.bin", i);
      mem = PKI_MEM_new_data((size_t)aType->value.sequence->length, aType->value.sequence->data);
      URL_put_data(buff, mem, NULL, NULL, 0, 0, NULL);
      PKI_MEM_free(mem);

      snprintf(buff, sizeof(buff), "%d_data_to_verify.bin", i);
      mem = PKI_MEM_new_data((size_t)tbslen, tbs);
      URL_put_data(buff, mem, NULL, NULL, 0, 0, NULL);
      PKI_MEM_free(mem);
    }

    // Retrieves the i-th component
    if ((comp_evp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th component from Key", i);
      goto err;
    }

    // Checks if we are using a global hash-n-sign (comp_ctx->md is set)
    // or if we need to use a specific hash for this component instead
    // (i.e., when comp_ctx->md is NULL or EVP_md_null())
    if (use_global_hash) {

      // We are using a global hash-n-sign, so the hash was already
      // calculated, we are just using the comp_md to set the algorithm
      // identifier
      tbs_data = tbs;
      tbs_data_len = tbslen;

    } else {

      X509_ALGOR * algor = NULL;
        // Pointer to the algorithm identifier

      const ASN1_OBJECT * comp_sig_obj = NULL;
        // Pointer to the signature algorithm

      // Let's get the i-th algorithm to set the identifier/parameters
      if (comp_ctx->sig_algs) {

        int comp_md_nid = 0;
          // NID of the MD

        PKI_DEBUG("Getting the i-th sig_algs component (%d) from the stack", i);

        algor = sk_X509_ALGOR_value(comp_ctx->sig_algs, i);
        if (!algor) {
          PKI_DEBUG("Cannot get the i-th sig_algs component (%d) from the stack", i);
          goto err;
        }
        X509_ALGOR_get0(&comp_sig_obj, NULL, NULL, algor);
        if (!comp_sig_obj) {
          PKI_DEBUG("Cannot get the algorithm identifier from the i-th sig_algs component (%d)", i);
          goto err;
        }
        if (!OBJ_find_sigid_algs(OBJ_obj2nid(comp_sig_obj), &comp_md_nid, NULL)) {
          PKI_DEBUG("Cannot get the MD component of the algorithm identifier of the i-th sig_algs component (%d)", i);
          goto err;
        }
        comp_md = EVP_get_digestbynid(comp_md_nid);
        if (!comp_md) {
          PKI_DEBUG("Returned NID_undef for the MD of the i-th sig_algs component (%d), but MD is required", i);
          goto err;
        }

      } else {

        // Let's check if we are required to provide a digest, if so,
        // let's get the default for the component
        if (PKI_X509_KEYPAIR_VALUE_requires_digest(comp_evp_pkey)) {

          // We are using a specific hash for this component,
          // we just try to use the defaults
          comp_md = COMPOSITE_CTX_get_default_md(comp_ctx);
          if (!comp_md) {
            int digest_id = NID_undef;

            digest_id = PKI_X509_KEYPAIR_VALUE_get_default_digest(comp_evp_pkey);
            if (!digest_id || (comp_md = EVP_get_digestbynid(digest_id)) == NULL) {
              PKI_DEBUG("Returned NID_undef for the MD of the i-th sig_algs component (%d), but MD is required", i);
              goto err;
            }
          }
        }
        
      }

      // Calculates the digest of the data to be signed
      if (!EVP_Digest(tbs, tbslen, (unsigned char *)hashed_data, (unsigned int *)&hashed_data_len, comp_md, NULL)) {
        PKI_DEBUG("Cannot calculate the digest for component %d", i);
        goto err;
      }

      // Let's point the tbs_data to the hashed data and the
      // tbs_data_len to the length of the hashed data
      tbs_data = hashed_data;
      tbs_data_len = hashed_data_len;
    }

    // Let's build a PKEY CTX and assign it to the MD CTX
    comp_pkey_ctx = EVP_PKEY_CTX_new(comp_evp_pkey, NULL);
    if (!comp_pkey_ctx) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the %d PKEY CTX component", i);
      goto err;
    }

    PKI_DEBUG("Data To Be Signed: tbs_data = %p, tbs_data_len = %d bytes", 
      tbs_data, tbs_data_len);

    PKI_DEBUG("Signature: %d bytes", aType->value.sequence->length);

    // Initializes the Verify operation
    ret_code = EVP_PKEY_verify_init(comp_pkey_ctx);
    if (ret_code <= 0) {
      PKI_DEBUG("Cannot initialize %d component signature (ret code: %d)", i, ret_code);
      // goto err;
    } else {
      // Verifies the individual signature
      ret_code = EVP_PKEY_verify(comp_pkey_ctx, 
                                aType->value.sequence->data,
                                (size_t)aType->value.sequence->length,
                                tbs_data,
                                (size_t)tbs_data_len);
    }

    // Removes the reference to the pkey. This is needed
    // because the EVP_PKEY_CTX_free() will otherwise
    // try to free the memory of the pkey
    // PKI_DEBUG("Freeing the pkey from the EVP_PKEY_CTX - Check this for correctness (we should not need to do this!)");
    // comp_pkey_ctx->pkey = NULL;

    // Free the EVP_PKEY_CTX
    if (comp_pkey_ctx) EVP_PKEY_CTX_free(comp_pkey_ctx);
    comp_pkey_ctx = NULL; // Safety

    // Checks the results of the verify
    if (ret_code != 1) {
      PKI_DEBUG("Signature Validation failed for %d component (EVP_PKEY_verify code is %d)", 
        i, ret_code);
      continue;
    } else {
      // Debugging
      PKI_DEBUG("Signature Component #%d Validated Successfully!", i);

      // Updates the tracker
      successful_validations++;
    }
  }

  // Free the stack memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
  sk = NULL;

  // while ((aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
  //   ASN1_TYPE_free(aType);
  // } sk_ASN1_TYPE_free(sk);
  // sk = NULL; // Safety

  if (successful_validations < required_valid_components) {
    PKI_DEBUG("Not enough valid components (%d out of %d)", successful_validations, required_valid_components);
    return 0;
  }

  // Debugging
  PKI_DEBUG("PMETH Verify Completed Successfully!");

  // All Done.
  return 1;

err:

  // Debugging
  PKI_DEBUG("PMETH Verify Error Condition, releasing resources.");

  // // Free the stack memory
  // if (sk != NULL) {
  //   while ((aType = sk_ASN1_TYPE_pop(sk)) != NULL) {
  //     ASN1_TYPE_free(aType);
  //   } sk_ASN1_TYPE_free(sk);
  //   sk = NULL; // Safety
  // }

  // Free the stack memory
  if (sk) sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);

  // Error
  return 0;
}

// Implemented
static int pmeth_ctrl(EVP_PKEY_CTX *ctx, int type, int key_id, void *value) {

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

  COMPOSITE_CTX * comp_ctx = NULL;
    // Pointer to inner CTX structure
  
  EVP_PKEY_CTX * pctx = EVP_MD_CTX_pkey_ctx(ctx);
    // PKEY context

  const unsigned char * tbs_data;
  size_t tbs_data_len = 0;
    // Pointers to the data to be passed
    // to the generic sign() function

  unsigned char global_hash[EVP_MAX_MD_SIZE];
  size_t global_hashlen = 0;
    // Temp Variables

  if (!pctx) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  }

  // Gets the internal CTX
  comp_ctx = (COMPOSITE_CTX *) EVP_PKEY_CTX_get_data(pctx);
  if (!comp_ctx) {
    PKI_DEBUG("ERROR, no internal CTX found!");
    return 0;
  }

  // Assigns the default data to be signed
  tbs_data = tbs;
  tbs_data_len = tbslen;

  // If we use the hash-n-sign method, we need to hash the data
  // only once, let's do it before the loop in this case
  if (comp_ctx->md && comp_ctx->md != PKI_DIGEST_ALG_NULL) {

    // Calculates the Digest (since we use custom digest, the data is not
    // hashed when it is passed to this function)
    int ossl_ret = EVP_Digest(tbs, tbslen, &global_hash[0], (unsigned int *)&global_hashlen, comp_ctx->md, NULL);
    if (ossl_ret == 0) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
      return 0;
    }

    tbs_data = tbs;
    tbs_data_len = tbslen;
  }

  ossl_ret = sign(pctx, sig, siglen, tbs_data, tbs_data_len);
  if (ossl_ret == 0) {
    PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
    return 0;
  }

  return 1;

//   // We need to get the algorithms from the PKEY_CTX
//   EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(p_ctx);
//     // PKEY

//   COMPOSITE_CTX * comp_ctx = p_ctx->data;
//     // Composite Context

//   PKI_DEBUG("DigestSign: Data To Sign = 0x%p, Size = %lu", tbs, tbslen);
//   PKI_DEBUG("Digest (EVP_md_null()? => %s) to use for signing: %s (%d)", md == EVP_md_null() ? "YES" : "NO", EVP_MD_name(md), EVP_MD_type(md));

//   //
//   // Issue: When we do not use the hash-n-sign, we need to pass the
//   //        digest to the sign function. This is not possible with
//   //        the current implementation.
//   //
//   //        We need to create a new function that does not use the
//   //        digest and sign the data directly but uses a STACK of
//   //        values to sign.
//   //
//   //        Let's create a new sign_ex() function with the following
//   //        signature:
//   //
//   //        int sign_ex(EVP_PKEY_CTX   * ctx, 
//   //                    unsigned char  * sig,
//   //                    size_t         * siglen,
//   //                    PKI_MEM_STACK  * tbs_stack);
//   //

//   if (comp_ctx->md) {

//     unsigned char * tbs_hash = NULL;
//     unsigned int tbs_hash_len = 0;
//       // Container for the Hashed value

//     // If we are using hash-n-sign, just calculate the hash
//     // and use a single tbs entry in the tbs stack for all the
//     // components
//     md = comp_ctx->md;

//     // Hash the contents only if we have a non-NULL digest
//     if (md != EVP_md_null()) {

//       PKI_MEM * tbs_mem = PKI_MEM_new_null();
//       if (!tbs_mem) {
//         PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
//         return 0;
//       }

//       // Calculates the Digest (since we use custom digest, the data is not
//       // hashed when it is passed to this function)
//       ossl_ret = EVP_Digest(tbs, tbslen, tbs_hash, &tbs_hash_len, md, NULL);
//       if (ossl_ret == 0) {
//         PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
//         return 0;
//       }

//     } else {
//       tbs_hash = (unsigned char *) tbs;
//       tbs_hash_len = tbslen;
//     }

//     // Signs and Returns the result
//     ossl_ret = sign(p_ctx, sig, siglen, tbs_hash, (size_t)tbs_hash_len);
//     if (ossl_ret == 0) {
//       PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
//       return 0;
//     }

//     // Success
//     return 1;

//   } else {

//     // Here we are not using the hash-n-sign method
//   }
  

//   // // Calculates the Digest (since we use custom digest, the data is not
//   // // hashed when it is passed to this function)
//   // ossl_ret = EVP_Digest(tbs, tbslen, tbs_hash, &tbs_hash_len, EVP_MD_CTX_md(ctx), NULL);
//   // if (ossl_ret == 0) {
//   //   PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
//   //   return 0;
//   // }

//   // PKI_DEBUG("DigestSign: After Calculation - Data To Sign = 0x%p, Size = %lu", tbs, tbslen);

//   // PKI_DEBUG("DigestSign: After Calculation - tbs_hash_len = %d", tbs_hash_len);

//   // // Signs and Returns the result
//   // ossl_ret = sign(p_ctx, sig, siglen, tbs_hash, (size_t)tbs_hash_len);
//   // if (ossl_ret == 0) {
//   //   PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
//   //   return 0;
//   // }

//   // Success
//   return 1;

//   /*
//   COMPOSITE_KEY * comp_key = EVP_PKEY_get0(ctx && ctx->pkey ? ctx->pkey : NULL);
//     // Pointer to inner key structure

//   COMPOSITE_CTX * comp_ctx = ctx->data;
//     // Pointer to algorithm specific CTX

//   const int signature_size = EVP_PKEY_size(ctx->pkey);
//     // The total signature size

//   STACK_OF(ASN1_TYPE) *sk = NULL;
//     // Stack of ASN1_OCTET_STRINGs

//   ASN1_OCTET_STRING * oct_string = NULL;
//     // Output Signature to be added
//     // to the stack of signatures

//   ASN1_TYPE * aType = NULL;
//     // ASN1 generic wrapper

//   int comp_key_num = 0;
//     // Number of components

//   unsigned char * buff = NULL;
//   unsigned char * pnt  = NULL;
//   int buff_len =  0;
//     // Temp Pointers

//   int total_size = 0;
//     // Total Signature Size

//   if ((comp_key == NULL) || 
//       ((comp_key_num = COMPOSITE_KEY_num(comp_key)) <= 0)) {
//     DEBUG("ERROR: Cannot get the Composite key inner structure");
//     return 0;
//   }

//   if (sig == NULL) {
//     *siglen = (size_t)signature_size;
//     return 1;
//   }

//   if ((size_t)signature_size > (*siglen)) {
//     DEBUG("ERROR: Buffer is too small");
//     return 0;
//   }

//   if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
//     DEBUG("ERROR: Memory Allocation");
//     return 0;
//   }

//   for (int i = 0; i < comp_key_num; i++) {

//     EVP_PKEY_CTX * pkey_ctx = NULL;

//     EVP_MD_CTX * md_ctx = NULL;

//     if (!COMPOSITE_CTX_get0(comp_ctx, i, &pkey_ctx, &md_ctx)) {
//       DEBUG("ERROR: Cannot get %d-th component from CTX", i);
//       return 0;
//     }

//     DEBUG("Determining Signature Size for Component #%d", i);

//     // Let's get the size of the single signature
//     if (EVP_PKEY_sign(pkey_ctx, NULL, (size_t *)&buff_len, tbs, tbslen) != 1) {
//       DEBUG("ERROR: Null Size reported from Key Component #%d", i);
//       goto err;
//     }

//     // Allocate the buffer for the single signature
//     if ((pnt = buff = OPENSSL_malloc(buff_len)) == NULL) {
//       DEBUG("ERROR: Memory Allocation");
//       goto err;
//     }

//     DEBUG("PNT = %p, BUFF = %p", pnt, buff);

//     // Generates the single signature
//     if (EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen) != 1) {
//       DEBUG("ERROR: Component #%d cannot generate signatures", i);
//       goto err;
//     }

//     DEBUG("PNT = %p, BUFF = %p", pnt, buff);

//     // Updates the overall real size
//     total_size += buff_len;

//     DEBUG("Generated Signature for Component #%d Successfully (size: %d)", i, buff_len);
//     DEBUG("Signature Total Size [So Far] ... %d", total_size);

//     if ((oct_string = ASN1_OCTET_STRING_new()) == NULL) {
//       DEBUG("ERROR: Memory Allocation");
//       goto err;
//     }

//     // This sets the internal pointers
//     ASN1_STRING_set0(oct_string, buff, buff_len);

//     // Resets the pointer and length after ownership transfer
//     buff = NULL; buff_len = 0;

//     // Let's now generate the ASN1_TYPE and add it to the stack
//     if ((aType = ASN1_TYPE_new()) == NULL) {
//       DEBUG("ERROR: Memory Allocation");
//       goto err;
//     }

//     // Transfer Ownership to the aType structure
//     ASN1_TYPE_set(aType, V_ASN1_OCTET_STRING, oct_string);
//     oct_string = NULL;

//     // Adds the component to the stack
//     if (!sk_ASN1_TYPE_push(sk, aType)) {
//       DEBUG("ERROR: Cannot push the new Type");
//       goto err;
//     }

//     // Transfers ownership
//     aType = NULL;
//   }

//   if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
//     DEBUG("ERROR: Cannot ASN1 encode the Overall Composite Key");
//     goto err;
//   }

//   // Reporting the total size
//   DEBUG("Total Signature Size: %d (reported: %d)", total_size, EVP_PKEY_size(ctx->pkey))

//   // Free the stack's memory
//   while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
//     ASN1_TYPE_free(aType);
//   }
//   sk_ASN1_TYPE_free(sk);
//   sk = NULL;

//   // Sets the output buffer
//   sig = buff;
//   *siglen = buff_len;

//   // All Done
//   return 1;

// err:

//   DEBUG("ERROR: Signing failed");

//   // Here we need to cleanup the memory

//   return 0;
//   */
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

  unsigned char * tbs_data = NULL;
  size_t tbs_data_len = 0;
    // Pointer to the data to be signed

  int ossl_ret = 0;
    // OpenSSL return code

  EVP_PKEY_CTX * p_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    // PKEY context

  if (!p_ctx) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  }

  COMPOSITE_CTX * comp_ctx = NULL;
    // Composite Context

  // Gets the Composite Context from the EVP_PKEY_CTX
  comp_ctx = EVP_PKEY_CTX_get_data(p_ctx);
  if (!comp_ctx) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  }

  // Calculates the Digest only if we are using a global digest
  // (i.e., the hash-n-sign is in use). This is true if the 
  // comp_ctx->md is not set to NULL or EVP_md_null()
  if (comp_ctx->md != NULL && 
      comp_ctx->md != EVP_md_null()) {

    const EVP_MD * md = EVP_MD_CTX_md(ctx);
      // Digest Algorithm

    if (!md) {
      PKI_DEBUG("ERROR, digest was not properly initialized for hash-n-sign verfiy, let's use the CTX one");
      md = comp_ctx->md;
    }

    if (md != comp_ctx->md) {
      PKI_DEBUG("ERROR, digest algorithm mismatch for hash-n-sign verify");
      return 0;
    }

    // Calculates the Digest (since we use custom digest, the data is not
    // hashed when it is passed to this function)
    ossl_ret = EVP_Digest(tbs, tbslen, tbs_hash, &tbs_hash_len, md, NULL);
    if (ossl_ret == 0) {
      PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
      return 0;
    }

    PKI_DEBUG("Using Hash-n-Sign Algorithm (Digest: %s)", EVP_MD_name(md));

    // Sets the pointers to the data to be validated
    // to the hashed data buffer
    tbs_data = tbs_hash;
    tbs_data_len = tbs_hash_len;

  } else {

    // We are not using a global hash-n-sign algorithm, so we just sign the data
    // directly with all the different components
    tbs_data = (unsigned char *) tbs;
    tbs_data_len = tbslen;
  }

  // Verifies and Returns the result
  ossl_ret = verify(p_ctx, sig, siglen, tbs_data, tbs_data_len);
  if (ossl_ret == 0) {
    PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
    return 0;
  }

  // Success
  return 1;
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
    pmeth_ctrl,     // int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
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
