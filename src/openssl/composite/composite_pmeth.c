/* BEGIN: composite_pmeth.c */

// Temporary Measure until the functions are all used
#pragma GCC diagnostic ignored "-Wunused-function"

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#include <libpki/openssl/composite/composite_pmeth.h>
#endif

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

// ===============
// Data Structures
// ===============

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#include "composite_ossl_internals.h"
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

// ==================
// Internal Functions
// ==================


COMPOSITE_CTX_ITEM * COMPOSITE_CTX_ITEM_new_null() {
  return OPENSSL_zalloc(sizeof(COMPOSITE_CTX_ITEM));
}

// Frees the memory associated with a CTX item
void COMPOSITE_CTX_ITEM_free(COMPOSITE_CTX_ITEM * it) {

  if (!it) return;

  // Handles the EVP_PKEY_CTX (if any)
  if (it->pkey_ctx) EVP_PKEY_CTX_free(it->pkey_ctx);

  // Handles the EVP_MD_CTX (if any)
  if (it->md_ctx != NULL) EVP_MD_CTX_free(it->md_ctx);

  // Free Allocated Memory
  OPENSSL_free(it);

  // All Done
  return;
}

// Free all components of the CTX (not the CTX itself)
void COMPOSITE_CTX_clear(COMPOSITE_CTX *ctx) {

  // Simple Check
  if (!ctx) return;

  // Free all items in the stack
  while (sk_COMPOSITE_CTX_ITEM_num(ctx) > 0) { 
    sk_COMPOSITE_CTX_ITEM_pop_free(ctx, COMPOSITE_CTX_ITEM_free); 
  }
}

void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx) {

  // Simple Check
  if (!ctx) return;

  // Clears all Items in the Stack
  COMPOSITE_CTX_clear(ctx);

  // Frees the stack's memory
  OPENSSL_free(ctx);
}

int COMPOSITE_CTX_add(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  * pkey_ctx, 
                      EVP_MD_CTX    * md_ctx,
                      int             index) {

  COMPOSITE_CTX_ITEM * it = NULL;
    // Internal Structure for the CTX stack

  // NOTE: pkey_ctx is needed, md_ctx is optional
  if (!comp_ctx || !pkey_ctx) return 0;

  if ((it = COMPOSITE_CTX_ITEM_new_null()) != NULL) {
    // Adds the component to the stack 
    if (COMPOSITE_CTX_add_item(comp_ctx, it, index) != 0) {
      // Transfer ownership of the PKEY ctx to the stacked item
      it->pkey_ctx = pkey_ctx;
      it->md_ctx = md_ctx;
    } else {
      PKI_DEBUG("ERROR: Cannot add key to position %d", index);
      COMPOSITE_CTX_ITEM_free(it);
      return 0;
    }
  } else {
    PKI_DEBUG("ERROR: Cannot create new CTX item");
    return 0;
  }

  return 1;
}

int COMPOSITE_CTX_add_pkey(COMPOSITE_CTX * comp_ctx, 
                           EVP_PKEY      * pkey,
                           int             index) {

  EVP_PKEY_CTX * pkey_ctx = NULL;
    // New Context container

  // Input Check
  if (!comp_ctx || !pkey) return 0;

  if ((pkey_ctx = EVP_PKEY_CTX_new_id(pkey->type, NULL)) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot Generate a new COMPOSITE CTX");
    return 0;
  }

  // Adds the component
  if (!COMPOSITE_CTX_add(comp_ctx, pkey_ctx, NULL, index)) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
  }

  // Assigns the EVP_PKEY to the CTX
  pkey_ctx->pkey = pkey;

  // All Done
  return 1;
}

int COMPOSITE_CTX_push(COMPOSITE_CTX * comp_ctx,
                       EVP_PKEY_CTX  * pkey_ctx,
                       EVP_MD_CTX    * md_ctx) {

  // Input Check
  if (!comp_ctx || !pkey_ctx) return 0;

    // Adds the component
  if (COMPOSITE_CTX_add(comp_ctx, pkey_ctx, md_ctx,
                        COMPOSITE_CTX_num(comp_ctx)) == 0) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
  }
  // All Done
  return 1;
}


int COMPOSITE_CTX_push_pkey(COMPOSITE_CTX * comp_ctx,
                            EVP_PKEY      * pkey) {

  EVP_PKEY_CTX * pkey_ctx = NULL;
    // New Context container

  // Input Check
  if (!comp_ctx || !pkey) return PKI_ERR;

  // Creates a new EVP_PKEY_CTX
  if ((pkey_ctx = EVP_PKEY_CTX_new_id(pkey->type, NULL)) == NULL) {
    PKI_DEBUG("ERROR: Cannot Generate a New CTX for key Type %d", pkey->type);
    return PKI_ERR;
  }
  
  if (!COMPOSITE_CTX_push(comp_ctx, pkey_ctx, NULL)) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return PKI_ERR;
  }

  // Assigns the EVP_PKEY to the CTX
  pkey_ctx->pkey = pkey;

  // All Done
  return PKI_OK;

}

int COMPOSITE_CTX_pkey_get0(COMPOSITE_CTX  * comp_ctx,
                            EVP_PKEY      ** pkey_ctx,
                            int              index) {

  COMPOSITE_CTX_ITEM * it = COMPOSITE_CTX_value(comp_ctx, index);
    // Pointer to the internal structure
    // for the CTX of individual keys

  // Simple validation
  if (!it) return PKI_ERR;

  if (!it->pkey_ctx || !it->pkey_ctx->pkey) return PKI_ERR;

  *pkey_ctx = it->pkey_ctx->pkey;

  // All done
  return PKI_OK;
}

int COMPOSITE_CTX_get0(COMPOSITE_CTX  * comp_ctx,
                       int              index,
                       EVP_PKEY_CTX  ** pkey_ctx,
                       EVP_MD_CTX    ** md_ctx) {

  COMPOSITE_CTX_ITEM * it = COMPOSITE_CTX_value(comp_ctx, index);
    // Pointer to the internal structure
    // for the CTX of individual keys

  // Simple validation
  if (!it) return PKI_ERR;

  // Copies references
  pkey_ctx = &it->pkey_ctx;
  md_ctx = &it->md_ctx;

  // All done
  return PKI_OK;
}

int COMPOSITE_CTX_pop(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  ** pkey_ctx,
                      EVP_MD_CTX    ** md_ctx) {

  COMPOSITE_CTX_ITEM * it = NULL;

  int ctx_num = COMPOSITE_CTX_num(comp_ctx);

  if (ctx_num <= 0) return PKI_ERR;

  if ((it = COMPOSITE_CTX_get_item(comp_ctx, ctx_num)) == NULL) {
    PKI_DEBUG("ERROR: Cannot pop component CTX from composite context");
    return PKI_ERR;
  }

  // Copies the references
  *pkey_ctx = it->pkey_ctx;
  *md_ctx = it->md_ctx;

  // Transfers Ownership
  it->pkey_ctx = NULL;
  it->md_ctx = NULL;

  // Free the item memory
  COMPOSITE_CTX_ITEM_free(it);

  // All done
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

// Not Implemented
static int copy(EVP_PKEY_CTX * dst,
                EVP_PKEY_CTX * src) {

  COMPOSITE_CTX * src_comp_ctx = NULL;
  COMPOSITE_CTX * dst_comp_ctx = NULL;
    // Pointers to the contexts
  
  // Input Checks
  if (!src || !src->data || !dst) return 0;

  // Shortcut to the data
  src_comp_ctx = src->data;
  
  // Allocates the needed memory
  if ((dst_comp_ctx = COMPOSITE_CTX_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  };

  // Uses the Algorithm-Specific Data pointer
  dst->data = dst_comp_ctx;

  // Process each component
  for (int i = 0; i < COMPOSITE_CTX_num(src_comp_ctx); i++) {

    COMPOSITE_CTX_ITEM * src_it = NULL;
    COMPOSITE_CTX_ITEM * dst_it = NULL;
      // Pointers to the CTX Items

    EVP_PKEY_CTX * tmp_pkey_ctx = NULL;
    EVP_MD_CTX * tmp_md_ctx = NULL;
      // Pointers to the Component's crypto library internals

    // Retrieves the n-th item
    if ((src_it = COMPOSITE_CTX_get_item(src_comp_ctx, i)) == NULL) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot retrieve composite key element #%d", i);
      return 0;
    }

    // Allocates the memory for the destination n-th component
    if ((dst_it = COMPOSITE_CTX_ITEM_new_null()) == NULL) {
      PKI_ERROR(PKI_ERR_GENERAL, "Cannot allocate memory for copying CTX for composite key component #%d", i);
      return 0;
    }

    // Retrieves the specific item
    if (!COMPOSITE_CTX_get0(src_comp_ctx, i, &tmp_pkey_ctx, &tmp_md_ctx)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the data from the source CTX item for component #%d", i);
      return 0;
    }

    // Duplicate the PKEY context
    if (tmp_pkey_ctx) dst_it->pkey_ctx = EVP_PKEY_CTX_dup(tmp_pkey_ctx);

    // Duplicate the MD context
    if ((dst_it->md_ctx = EVP_MD_CTX_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate EVP_MD_CTX_new() memory.");
      return 0;
    }

    // Checks if we have a valid MD CTX
    if (tmp_md_ctx) {
      // Copy the MD CTX into the destination
      if (!EVP_MD_CTX_copy_ex(dst_it->md_ctx, tmp_md_ctx)) {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot duplicate MD context");
	      return 0;
      }
    }

    // Push the item contex to the composite CTX
    if (!COMPOSITE_CTX_push_item(dst_comp_ctx, dst_it)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot push component #%d in the destination CTX", i);
      return 0;
    }
  }

  // All Done
  return 1;
}

// Implemented
static void cleanup(EVP_PKEY_CTX * ctx) {

  COMPOSITE_CTX * comp_ctx = NULL;
    // Composite Context

  // Input Check
  if (!ctx) return;

  // Retrieves the internal context
  if ((comp_ctx = ctx->data) != NULL) COMPOSITE_CTX_free(comp_ctx);

  // All Done
  return;
}

// Not Implemented
static int paramgen_init(EVP_PKEY_CTX * ctx) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int paramgen(EVP_PKEY_CTX * ctx,
                    EVP_PKEY     * pkey) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Nothing to do here
// Function is invoked by EVP_PKEY_keygen_init() at
// <OPENSSL>/crypto/evp/pmeth_gn2.c
static int keygen_init(EVP_PKEY_CTX *ctx) {
  PKI_DEBUG("Not implemented, yet.");
  return 1;
}

// Implemented
static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * key = NULL;

  // Input Validation
  if (!ctx || !ctx->data || !pkey) return 0;

#ifdef ENABLE_COMPOSITE
  // Some extra checking for correctness
  if (ctx->pmeth->pkey_id != OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID)) {
    PKI_DEBUG("NID is not NID_composite (%d vs. %d)", 
      ctx->pmeth->pkey_id, OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID));
    return 0;
  }
#else
  PKI_DEBUG("ERROR: Missing support for NID_composite");
  return 0;
#endif

  // Checks we have the right data and items
  if (!(comp_ctx = ctx->data) || COMPOSITE_CTX_num(comp_ctx) <= 0) {
    // No components present in the key
    PKI_ERROR(PKI_ERR_ALGOR_SET, "No Keys Are Present in the SEQUENCE");
    return 0;
  }

  // Allocates the Composite Key
  if ((key = COMPOSITE_KEY_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return 0;
  }

  // Processes
  for (int i = 0; i < COMPOSITE_CTX_num(comp_ctx); i++ ) {

    EVP_PKEY * tmp_pkey = NULL;
      // Pointer to the single component's key

    // Retrieves the i-th component
    if (!COMPOSITE_CTX_pkey_get0(comp_ctx, &tmp_pkey, i) || (tmp_pkey == NULL)) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add PKEY to Composite Key component #%d", i);
      COMPOSITE_KEY_free(key);
      return 0;
    }

    // Adds the key in the key stack
    COMPOSITE_KEY_push(key, tmp_pkey);
  }

  // NOTE: To Get the Structure, use EVP_PKEY_get0(EVP_PKEY *k)
  // NOTE: To Add the Key Structure, use EVP_PKEY_assign()
  EVP_PKEY_assign_COMPOSITE(pkey, key);

  // All Done.
  return 1;
}

// Implemented
static int sign_init(EVP_PKEY_CTX *ctx) {

  COMPOSITE_CTX * comp_ctx = ctx->data;
    // Algorithm specific context

  // Input Checks
  if (!comp_ctx) return 0;

  // Process each component separately
  for (int i = 0; i < COMPOSITE_CTX_num(comp_ctx); i++) {

    COMPOSITE_CTX_ITEM * it = NULL;
      // Pointer to Internal Structure that
      // contains also the EVP_PKEY_CTX for
      // the component of the key

    // Retrieves the i-th item, fails otherwise
    if ((it = COMPOSITE_CTX_get_item(comp_ctx, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot retrieve %d-th component of the key", i);
      return 0;
    }

    // Checks for the PKEY CTX
    if (!it->pkey_ctx) {
      // Copies some details from the main EVP_PKEY_CTX
      // into the newly generated one associated to the
      // single component
      it->pkey_ctx = EVP_PKEY_CTX_new_id(
                          ctx->pmeth->pkey_id,
                          ctx->engine);
    }

    // Copies the basic data
    it->pkey_ctx->operation = ctx->operation;
    it->pkey_ctx->app_data  = ctx->app_data;

    // Initialize the Signature for the component
    if (1 != EVP_PKEY_sign_init(it->pkey_ctx)) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot initialize signature for Key Component #%d", i);
      return 0;
    }
  }

  // All Components have been initialized
  return 1;
}

// Implemented
static int sign(EVP_PKEY_CTX        * ctx, 
                unsigned char       * sig,
                size_t              * siglen,
                const unsigned char * tbs,
                size_t                tbslen) {

  // NOTE: The passed CTX (ctx->data) is not the same as when the key
  // was created or loaded. This means that the comp_ctx that is
  // available here is actually empty. We need to reconstruct the
  // different EVP_PKEY_CTX here.

  COMPOSITE_KEY * comp_key = EVP_PKEY_get0(ctx && ctx->pkey ? ctx->pkey : NULL);
    // Pointer to inner key structure

  // COMPOSITE_CTX * comp_ctx = ctx->data;
    // Pointer to algorithm specific CTX

  EVP_MD * pmd = NULL;
    // Digest Algorithm to use for the signature

  const int signature_size = EVP_PKEY_size(ctx->pkey);
    // The total signature size

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  ASN1_OCTET_STRING * oct_string = NULL;
    // Output Signature to be added
    // to the stack of signatures

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int comp_key_num = 0;
    // Number of components

  unsigned char * buff = NULL;
  unsigned char * pnt  = NULL;
  int buff_len =  0;
    // Temp Pointers

  int total_size = 0;
    // Total Signature Size

  // Input Checks
  if ((comp_key == NULL) || ((comp_key_num = COMPOSITE_KEY_num(comp_key)) <= 0)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get the Composite key inner structure");
    return 0;
  }

  // Input checks -> Destination Buffer Pointer
  if (sig == NULL) {
    *siglen = (size_t)signature_size;
    return 1;
  }

  // Input Checks -> Destination Buffer Size
  if ((size_t)signature_size > (*siglen)) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Destination signature buffer is too small");
    return 0;
  }

  // Allocates the Stack for the signatures
  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the stack of signature");
    return 0;
  }

  // Retrieves the set digest for the signature
  if (!EVP_PKEY_CTX_get_signature_md(ctx, &pmd)) {
    pmd = PKI_DIGEST_ALG_DEFAULT;
  }

  // Generates Each Signature Independently
  for (int i = 0; i < comp_key_num; i++) {

    EVP_PKEY * evp_pkey = NULL;
    EVP_PKEY_CTX * pkey_ctx = NULL;
      // Pointers to PKEY and Context

    // Retrieves the i-th component
    if ((evp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot get %d-th component from Key", i);
      return 0;
    }

    // Builds a new PKEY context
    if ((pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new EVP_PKEY_CTX for signature component %d", i);
      return 0;
    };

    // Sets the Operation
    pkey_ctx->operation = EVP_PKEY_OP_SIGN;

    // Setting the digest algorithm to use
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, pmd) <= 0) {
      PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, "Error setting the signature digest");
      goto err;
    }

    // Let's get the size of the single signature
    if (EVP_PKEY_sign(pkey_ctx, NULL, (size_t *)&buff_len, tbs, tbslen) != 1) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Error while retrieving the size for component signature #%d", i);
      goto err;
    }

    // Allocate the buffer for the single signature
    if ((pnt = buff = OPENSSL_malloc((size_t)buff_len)) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the %d-th component signature's buffer");
      goto err;
    }

    // Actually performs the signature
    if (EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen) != 1) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot generate signature's #%d component", i);
      goto err;
    }

    // Updates the overall real size
    total_size += buff_len;

    PKI_DEBUG("Generated Signature for Component #%d Successfully (size: %d)", i, buff_len);
    PKI_DEBUG("Signature Total Size [So Far] ... %d", total_size);

    if ((oct_string = ASN1_OCTET_STRING_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the wrapping OCTET STRING for signature's %d component", i);
      goto err;
    }

    // This sets the internal pointers
    ASN1_STRING_set0(oct_string, pnt, buff_len);
    pnt = NULL; buff_len = 0;

    // Resets the pointer and length after ownership transfer
    buff = NULL; buff_len = 0;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot Allocate a new ASN1 Type for signature wrapping");
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_OCTET_STRING, oct_string);
    oct_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot push the signature's %d component", i);
      goto err;
    }

    // Transfers ownership
    aType = NULL;
  }

  if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
    PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, "Cannot generate DER representation of the sequence of signatures");
    goto err;
  }

  // Reporting the total size
  PKI_DEBUG("Total Signature Size: %d (reported: %d)", total_size, EVP_PKEY_size(ctx->pkey));

  // Free the stack's memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
    ASN1_TYPE_free(aType);
  }
  sk_ASN1_TYPE_free(sk);
  sk = NULL;

  // Sets the output buffer
  sig = buff;
  *siglen = (size_t) buff_len;

  // All Done
  return 1;

err:

  DEBUG("ERROR: Signing failed");

  // Here we need to cleanup the memory

  return 0;
}

// Implemented
static int verify_init(EVP_PKEY_CTX *ctx) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int verify(EVP_PKEY_CTX        * ctx,
                  const unsigned char * sig,
                  size_t                siglen,
                  const unsigned char * tbs,
                  size_t                tbslen) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover_init(EVP_PKEY_CTX *ctx) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover(EVP_PKEY_CTX        * ctx,
                          unsigned char       * rout,
                          size_t              * routlen,
                          const unsigned char * sig,
                          size_t                siglen) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

  return 1;


  COMPOSITE_CTX * comp_ctx = ctx->data;
    // Algorithm specific CTX

  COMPOSITE_KEY * comp_key = EVP_PKEY_get0(ctx->pkey);
    // Pointer to inner structure

  // Input Checks
  if (!ctx || !comp_ctx) return 0;

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    EVP_MD_CTX * md_ctx = NULL;
      // Digest context

    EVP_PKEY_CTX * pkey_ctx = NULL;
      // Component specific CTX

    EVP_PKEY * pkey = COMPOSITE_KEY_get0(comp_key, i);
      // Component specific key

    // Let' check we have the right data
    if (!COMPOSITE_CTX_get0(comp_ctx, i, &pkey_ctx, &md_ctx)) {
      DEBUG("ERROR: Cannot Retrieve CTX for component #%d", i);
      return 0;
    }

    // Checks on the pointers
    if (!pkey || !pkey_ctx) return 0;

    if (mctx) {
      
      if (!md_ctx && 
          ((md_ctx = EVP_MD_CTX_new()) == NULL)) {
        DEBUG("ERROR: Cannot Allocate the MD CTX for Component #%d", i);
      }

      // Initializes the EVP_MD (alias to EVP_MD_reset)
      EVP_MD_CTX_init(md_ctx);

      // Copy the MD to the specific component
      if ((mctx->digest != NULL) && 
          (EVP_MD_CTX_copy(md_ctx, mctx) <= 0)) {
        // This is ok, it fails when the mctx->digest is NULL
        DEBUG("ERROR: Cannot copy the MD CTX for Component #%d", i);
        return 0;
      }
    }

    if (pkey_ctx->pmeth->signctx_init != NULL &&
        (pkey_ctx->pmeth->signctx_init(pkey_ctx, 
                                       md_ctx) != 1)) {
      DEBUG("ERROR: Cannot Initialize Signature for Component #%d", i);
      return 0;
    }
  }

  // All Components have been initialized
  return 1;
}

// Implemented
static int signctx (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) {

  DEBUG("Not implemented, yet.");
  return 0;
}


// Implemented
static int verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int verifyctx (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int encrypt_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int encrypt_pmeth(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int decrypt_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int derive_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
  DEBUG("Not implemented, yet.");
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
      PKI_DEBUG("[ PMETH ] ======= EVP_PKEY_CTRL_GET_MD (Val: 1) ========== ");
    } break;

    case EVP_PKEY_CTRL_MD: {

      // Here we need to allocate the digest for each key in the
      // stack (if not there, let's allocate the memory and
      // initialize it)
      //
      // if (key[x]->digest == NULL) {
      //    /* EVP_MD_CTX */ key[x]->digest = OPENSSL_malloc();
      // }
      //
      // EVP_Digest_Init_ex(key[x]->digest, 
      //    EVP_get_digest_by_nid(*(int*)p2, NULL))
      //
      // NEED TO CHECK:
      //     EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX)

      // Input checks
      if (!value) return 0;

      // const EVP_MD * digest = (EVP_MD *)value;
      //   // Digest to use

      // NOTE: Here we need to create the stack of contexts with the right
      //       EVP_PKEY_CTX and EVP_MD_CTX for each of the components. Let's
      //       work through the stack of keys to create the corresponding
      //       stack of contexts

      for (int i = 0; i < COMPOSITE_KEY_num(comp_pkey); i++) {

        // COMPOSITE_CTX_ITEM * comp_ctx_item = NULL;
        //   // Composite CTX

        EVP_MD_CTX * md_ctx = NULL;
        EVP_PKEY_CTX * pkey_ctx = NULL;
          // Components of the Composite CTX item

        EVP_PKEY * pkey = NULL;
          // Individual Component

        // Retrieve the i-th component
        pkey = COMPOSITE_KEY_value(comp_pkey, i);
        if (pkey == NULL) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot retrieve the %d key component", i);
          return 0;
        }

        // We want to generate a new PKEY and MD contexts
        pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_id(pkey), NULL);
        if (pkey_ctx == NULL) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new PKEY CTX for component %d", i);
          return 0;
        }

        // We also want to duplicate the MD context
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate a new MD CTX for component %d", i);
          if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
          return 0;
        }

        // Sets the PKEY CTX
        EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

        // Assigns the contexts to the composite item and
        // push the new item to the stack of contexts
        if (PKI_OK != COMPOSITE_CTX_push(comp_ctx, pkey_ctx, md_ctx)) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add the new context for component %d", i);
          if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
          if (md_ctx) EVP_MD_CTX_free(md_ctx);
          return 0;
        }
      }

      // Debugging
      PKI_DEBUG("[ PMETH ] Added %d contexts for signature creation", COMPOSITE_KEY_num(comp_pkey));

      // All Done
      return 1;

    } break;


    case EVP_PKEY_OP_TYPE_SIG: {
      DEBUG("[ PMETH ] ======= EVP_PKEY_OP_TYPE_SIG ========== ");
      PKI_DEBUG("Got EVP sign operation - missing code, returning ok");
    } break;

    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
    case EVP_PKEY_CTRL_SET_MAC_KEY:
    case EVP_PKEY_CTRL_SET_IV: {
      DEBUG("ERROR: Non Supported CTRL");
      return -2;
    } break;

    case EVP_PKEY_CTRL_DIGESTINIT: {
      PKI_DEBUG("EVP_PKEY_CTX: Digest Init - nothing to do.");
      // all Done
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

    case EVP_PKEY_CTRL_COMPOSITE_PUSH:
    case EVP_PKEY_CTRL_COMPOSITE_ADD: {
      // Adds the Key to the internal stack
      if (!COMPOSITE_CTX_add_pkey(comp_ctx, (EVP_PKEY *)value, key_id)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot add component (type %d) to composite key", pkey->type);
        return 0;
      }
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_DEL: {
      // Checks we have the key_id component
      if (key_id <= 0 || key_id >= COMPOSITE_CTX_num(comp_ctx)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE, "Component %d does not exists (max is %d)", 
          key_id, COMPOSITE_CTX_num(comp_ctx));
        return 0;
      }
      // Delete the specific item from the stack
      COMPOSITE_CTX_del(comp_ctx, key_id);
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_POP: {
      // Checks we have at least one component
      if (key_id <= 0 || key_id >= COMPOSITE_CTX_num(comp_ctx)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE, "Component %d does not exists (max is %d)", 
          key_id, COMPOSITE_CTX_num(comp_ctx));
        return 0;
      }
      // Pops a Key
      COMPOSITE_CTX_pop_free(comp_ctx);
      // All Done
      return 1;
    } break;

    case EVP_PKEY_CTRL_COMPOSITE_CLEAR: {
      // Clears all components from the key
      COMPOSITE_CTX_clear(comp_ctx);
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

// Not Implemented
static int ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// ===================
// OpenSSL 1.1.x+ Only
// ===================

// Implemented
static int digestsign(EVP_MD_CTX          * ctx,
                      unsigned char       * sig,
                      size_t              * siglen,
                      const unsigned char * tbs,
                      size_t                tbslen) {
  
  PKI_DEBUG("Not Implemented, yet.");

  // return sign(ctx, sig, siglen, tbs, tbslen);

  return 0;
  /*
  COMPOSITE_KEY * comp_key = EVP_PKEY_get0(ctx && ctx->pkey ? ctx->pkey : NULL);
    // Pointer to inner key structure

  COMPOSITE_CTX * comp_ctx = ctx->data;
    // Pointer to algorithm specific CTX

  const int signature_size = EVP_PKEY_size(ctx->pkey);
    // The total signature size

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  ASN1_OCTET_STRING * oct_string = NULL;
    // Output Signature to be added
    // to the stack of signatures

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int comp_key_num = 0;
    // Number of components

  unsigned char * buff = NULL;
  unsigned char * pnt  = NULL;
  int buff_len =  0;
    // Temp Pointers

  int total_size = 0;
    // Total Signature Size

  if ((comp_key == NULL) || 
      ((comp_key_num = COMPOSITE_KEY_num(comp_key)) <= 0)) {
    DEBUG("ERROR: Cannot get the Composite key inner structure");
    return 0;
  }

  if (sig == NULL) {
    *siglen = (size_t)signature_size;
    return 1;
  }

  if ((size_t)signature_size > (*siglen)) {
    DEBUG("ERROR: Buffer is too small");
    return 0;
  }

  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    DEBUG("ERROR: Memory Allocation");
    return 0;
  }

  for (int i = 0; i < comp_key_num; i++) {

    EVP_PKEY_CTX * pkey_ctx = NULL;

    EVP_MD_CTX * md_ctx = NULL;

    if (!COMPOSITE_CTX_get0(comp_ctx, i, &pkey_ctx, &md_ctx)) {
      DEBUG("ERROR: Cannot get %d-th component from CTX", i);
      return 0;
    }

    DEBUG("Determining Signature Size for Component #%d", i);

    // Let's get the size of the single signature
    if (EVP_PKEY_sign(pkey_ctx, NULL, (size_t *)&buff_len, tbs, tbslen) != 1) {
      DEBUG("ERROR: Null Size reported from Key Component #%d", i);
      goto err;
    }

    // Allocate the buffer for the single signature
    if ((pnt = buff = OPENSSL_malloc(buff_len)) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    DEBUG("PNT = %p, BUFF = %p", pnt, buff);

    // Generates the single signature
    if (EVP_PKEY_sign(pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen) != 1) {
      DEBUG("ERROR: Component #%d cannot generate signatures", i);
      goto err;
    }

    DEBUG("PNT = %p, BUFF = %p", pnt, buff);

    // Updates the overall real size
    total_size += buff_len;

    DEBUG("Generated Signature for Component #%d Successfully (size: %d)", i, buff_len);
    DEBUG("Signature Total Size [So Far] ... %d", total_size);

    if ((oct_string = ASN1_OCTET_STRING_new()) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    // This sets the internal pointers
    ASN1_STRING_set0(oct_string, buff, buff_len);

    // Resets the pointer and length after ownership transfer
    buff = NULL; buff_len = 0;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_OCTET_STRING, oct_string);
    oct_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      DEBUG("ERROR: Cannot push the new Type");
      goto err;
    }

    // Transfers ownership
    aType = NULL;
  }

  if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
    DEBUG("ERROR: Cannot ASN1 encode the Overall Composite Key");
    goto err;
  }

  // Reporting the total size
  DEBUG("Total Signature Size: %d (reported: %d)", total_size, EVP_PKEY_size(ctx->pkey))

  // Free the stack's memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
    ASN1_TYPE_free(aType);
  }
  sk_ASN1_TYPE_free(sk);
  sk = NULL;

  // Sets the output buffer
  sig = buff;
  *siglen = buff_len;

  // All Done
  return 1;

err:

  DEBUG("ERROR: Signing failed");

  // Here we need to cleanup the memory

  return 0;
  */
}

// Implemented
static int digestverify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int check(EVP_PKEY *pkey) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int public_check(EVP_PKEY *pkey) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int param_check(EVP_PKEY *pkey) {
  PKI_DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  PKI_DEBUG("Not implemented, yet. Returning Ok anyway.");
  return 1;
}

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
// execution (see the do_sigver_init() at m_sigver.c:25)

EVP_PKEY_METHOD composite_pkey_meth = {
    0,              // int pkey_id; // EVP_PKEY_COMPOSITE
    0,              // int flags; //EVP_PKEY_FLAG_SIGCTX_CUSTOM
    init,           // int (*init)(EVP_PKEY_CTX *ctx);
    copy,           // int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    cleanup,        // void (*cleanup)(EVP_PKEY_CTX *ctx);
    0,              // paramgen_init,  // int (*paramgen_init)(EVP_PKEY_CTX *ctx);
    0,              // paramgen,       // int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    keygen_init,    // int (*keygen_init)(EVP_PKEY_CTX *ctx);
    keygen,         // int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    sign_init,      // int (*sign_init) (EVP_PKEY_CTX *ctx);
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
    ctrl_str,       // int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    // These are only available on OpenSSL v1.1.X+ //
    0, // digestsign,     // int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    0, // digestverify,   // int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    check,          // int (*check) (EVP_PKEY *pkey);
    public_check,   // int (*public_check) (EVP_PKEY *pkey);
    0, // param_check,    // int (*param_check) (EVP_PKEY *pkey);
    0, // digest_custom   // int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
#endif
};

#endif // ENABLE_COMPOSITE

/* END: composite_pmeth.c */
