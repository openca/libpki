/* BEGIN: composite_pmeth.c */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef OPENSSL_COMPOSITE_PKEY_METH_H
#include <libpki/openssl/composite/composite_pmeth.h>
#endif

// ===============
// Data Structures
// ===============

#ifndef OPENSSL_COMPOSITE_OPENSSL_LOCAL_H
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

int NID_composite = 0X0FF1;
  // Value for the composite EVP_PKEY type

int NID_combined = 0X0FF2;
  // Value for the combined EVP_PKEY type

// ==================
// Internal Functions
// ==================


COMPOSITE_CTX_ITEM * COMPOSITE_CTX_ITEM_new_null() {

  DEBUG("DEBUG");
  
  return OPENSSL_zalloc(sizeof(COMPOSITE_CTX_ITEM));

}

// Frees the memory associated with a CTX item
void COMPOSITE_CTX_ITEM_free(COMPOSITE_CTX_ITEM * it) {

  DEBUG("DEBUG");

  if (!it) return;

  // Handles the EVP_PKEY_CTX (if any)
  if (it->pkey_ctx) EVP_PKEY_CTX_free(it->pkey_ctx);
  // Handles the EVP_MD_CTX (if any)
  if (it->md_ctx != NULL) EVP_MD_CTX_free(it->md_ctx);

  // All Done
  OPENSSL_free(it);
  return;
}

// Free all components of the CTX (not the CTX itself)
void COMPOSITE_CTX_clear(COMPOSITE_CTX *ctx) {

  DEBUG("DEBUG");

  // Simple Check
  if (!ctx) return;

  // Free all items in the stack
  while (sk_COMPOSITE_CTX_ITEM_num(ctx) > 0) { 
    sk_COMPOSITE_CTX_ITEM_pop_free(ctx, COMPOSITE_CTX_ITEM_free); 
  }
}

void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx) {

  DEBUG("DEBUG");

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

  DEBUG("DEBUG");

  // NOTE: pkey_ctx is needed, md_ctx is optional
  if (!comp_ctx || !pkey_ctx) return 0;

  if ((it = COMPOSITE_CTX_ITEM_new_null()) != NULL) {
    // Adds the component to the stack 
    if (COMPOSITE_CTX_add_item(comp_ctx, it, index) != 0) {
      // Transfer ownership of the PKEY ctx to the stacked item
      it->pkey_ctx = pkey_ctx;
      it->md_ctx = md_ctx;
    } else {
      DEBUG("ERROR: Cannot add key to position %d", index);
      COMPOSITE_CTX_ITEM_free(it);
      return 0;
    }
  } else {
    DEBUG("ERROR: Cannot create new CTX item");
    return 0;
  }

  return 1;
}

int COMPOSITE_CTX_add_pkey(COMPOSITE_CTX * comp_ctx, 
                           EVP_PKEY      * pkey,
                           int             index) {

  EVP_PKEY_CTX * pkey_ctx = NULL;
    // New Context container

  DEBUG("DEBUG");

  // Input Check
  if (!comp_ctx || !pkey) return 0;

  if ((pkey_ctx = EVP_PKEY_CTX_new_id(pkey->type, NULL)) == NULL) {
    DEBUG("ERROR: Cannot Generate a New CTX for key Type %d", pkey->type);
    return 0;
  }

  // Adds the component
  if (!COMPOSITE_CTX_add(comp_ctx, pkey_ctx, NULL, index)) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
  }

  // Assigns the EVP_PKEY to the CTX
  pkey_ctx->pkey = pkey;

  // Increments Refcount for the Key
  // EVP_PKEY_up_ref(pkey);

  // All Done
  return 1;
}

int COMPOSITE_CTX_push(COMPOSITE_CTX * comp_ctx,
                       EVP_PKEY_CTX  * pkey_ctx,
                       EVP_MD_CTX    * md_ctx) {

  DEBUG("DEBUG");

  // Input Check
  if (!comp_ctx || !pkey_ctx) return 0;

    // Adds the component
  if (COMPOSITE_CTX_add(comp_ctx, pkey_ctx, md_ctx,
                        COMPOSITE_CTX_num(comp_ctx)) == 0) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
  }

  return 1;
}


int COMPOSITE_CTX_push_pkey(COMPOSITE_CTX * comp_ctx,
                            EVP_PKEY      * pkey) {

  DEBUG("DEBUG");

  EVP_PKEY_CTX * pkey_ctx = NULL;
    // New Context container

  // Input Check
  if (!comp_ctx || !pkey) return 0;

  // Creates a new EVP_PKEY_CTX
  if ((pkey_ctx = EVP_PKEY_CTX_new_id(pkey->type, NULL)) == NULL) {
    DEBUG("ERROR: Cannot Generate a New CTX for key Type %d", pkey->type);
    return 0;
  }
  
  if (!COMPOSITE_CTX_push(comp_ctx, pkey_ctx, NULL)) {
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
  }

  // Assigns the EVP_PKEY to the CTX
  pkey_ctx->pkey = pkey;

  // Increments Refcount for the Key
  // EVP_PKEY_up_ref(pkey);
  
  // All Done
  return 1;

}

int COMPOSITE_CTX_pkey_get0(COMPOSITE_CTX  * comp_ctx,
                            EVP_PKEY      ** pkey_ctx,
                            int              index) {

  DEBUG("DEBUG");

  COMPOSITE_CTX_ITEM * it = COMPOSITE_CTX_value(comp_ctx, index);
    // Pointer to the internal structure
    // for the CTX of individual keys

  // Simple validation
  if (!it) return 0;

  if (!it->pkey_ctx || !it->pkey_ctx->pkey) return 0;

  *pkey_ctx = it->pkey_ctx->pkey;

  // EVP_PKEY_up_ref(it->pkey_ctx->pkey);

  // All done
  return 1;
}

int COMPOSITE_CTX_get0(COMPOSITE_CTX  * comp_ctx,
                       int              index,
                       EVP_PKEY_CTX  ** pkey_ctx,
                       EVP_MD_CTX    ** md_ctx) {

  DEBUG("DEBUG");

  COMPOSITE_CTX_ITEM * it = COMPOSITE_CTX_value(comp_ctx, index);
    // Pointer to the internal structure
    // for the CTX of individual keys

  // Simple validation
  if (!it) return 0;

  // Copies references
  pkey_ctx = &it->pkey_ctx;
  md_ctx = &it->md_ctx;

  // All done
  return 1;
}

int COMPOSITE_CTX_pop(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  ** pkey_ctx,
                      EVP_MD_CTX    ** md_ctx) {

  COMPOSITE_CTX_ITEM * it = NULL;

  DEBUG("DEBUG");

  int ctx_num = COMPOSITE_CTX_num(comp_ctx);

  if (ctx_num <= 0) return 0;

  if ((it = COMPOSITE_CTX_get_item(comp_ctx, ctx_num)) == NULL) {
    DEBUG("ERROR: Cannot pop component CTX from composite context");
    return 0;
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
  return 1;
}

int COMPOSITE_KEY_size(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_size = 0;

  DEBUG("DEBUG");

  if (!key) return -1;

  if ((key_num = COMPOSITE_KEY_num(key)) <= 0)
    return 0;

  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    total_size += EVP_PKEY_size(single_key);

    DEBUG("DEBUG: [%d] Current Total Size is [%d] (already total size!)",
      i, total_size);
  }

  DEBUG("Final Total Size: %d", total_size);

  return total_size;
}

int COMPOSITE_KEY_bits(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_bits = 0;

  DEBUG("DEBUG");

  if (!key) return -1;

  if ((key_num = COMPOSITE_KEY_num(key)) <= 0)
    return 0;

  DEBUG("Composite Key (key) => %p", key);

  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    DEBUG("DEBUG: Individual Key [%d] is at [0x%p]", i, single_key);

    total_bits += EVP_PKEY_bits(single_key);

    DEBUG("DEBUG: [%d] Current Total BITS is [%d]",
     i, total_bits);
  }

  DEBUG("Returning Total Bits: %d", total_bits);

  return total_bits;
}

int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int sec_bits = INT_MAX;
  int component_sec_bits = INT_MAX;

  DEBUG("DEBUG");

  if (!key) return -1;

  if ((key_num = COMPOSITE_KEY_num(key)) <= 0)
    return 0;

  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    component_sec_bits = EVP_PKEY_security_bits(single_key);
    if (sec_bits >= component_sec_bits) sec_bits = component_sec_bits;

    DEBUG("DEBUG: [%d] Current Security BITS is [%d]", i, sec_bits);
  }

  DEBUG("Returning Security Bits: %d", sec_bits);

  return sec_bits;
}

// =========================
// EVP_PKEY_METHOD Functions
// =========================

// Implemented
static int init(EVP_PKEY_CTX *ctx) {
  
  COMPOSITE_CTX *comp_ctx = NULL;

  // Allocate Memory
  if ((comp_ctx = COMPOSITE_CTX_new_null()) == NULL)
    return 0;

  // Assigns the algorithm-specific data
  // to the data field
  ctx->data = comp_ctx;

  // These are used during Key Gen to display
  // '.', '+', '*', '\n' during key gen
  ctx->keygen_info = NULL;
  ctx->keygen_info_count = 0;

  DEBUG("Display the OPERATION: %d", ctx->operation)

  DEBUG("Init completed successfully.");

  // All Done
  return 1;
}

// Not Implemented
static int copy(EVP_PKEY_CTX * dst,
                EVP_PKEY_CTX * src) {

  COMPOSITE_CTX * src_comp_ctx = src->data;
  COMPOSITE_CTX * dst_comp_ctx = COMPOSITE_CTX_new_null();

  if (!dst_comp_ctx) return 0;

  dst->data = dst_comp_ctx;

  for (int i = 0; i < COMPOSITE_CTX_num(src_comp_ctx); i++) {

    COMPOSITE_CTX_ITEM * src_it = NULL;
    COMPOSITE_CTX_ITEM * dst_it = NULL;

    EVP_PKEY_CTX * tmp_pkey_ctx = NULL;
    EVP_MD_CTX * tmp_md_ctx = NULL;

    DEBUG("copying component #%d ...", i);

    if ((src_it = COMPOSITE_CTX_get_item(src_comp_ctx, i)) == NULL) {
      DEBUG("ERROR: Cannot retrieve element #%d", i);
      return 0;
    }

    if ((dst_it = COMPOSITE_CTX_ITEM_new_null()) == NULL) {
      DEBUG("ERROR: Cannot allocate memory for copying CTX for component #%d", i);
      return 0;
    }

    if (!COMPOSITE_CTX_get0(src_comp_ctx, i, &tmp_pkey_ctx, &tmp_md_ctx)) {
      DEBUG("ERROR: Cannot get the data from the source CTX item for component #%d", i);
      return 0;
    }

    // Duplicate the PKEY context
    if (tmp_pkey_ctx) dst_it->pkey_ctx = EVP_PKEY_CTX_dup(tmp_pkey_ctx);

    // Duplicate the MD context
    // if (tmp_md_ctx) dst_it->md_ctx = EVP_MD_CTX_dup(tmp_md_ctx);
    if ((dst_it->md_ctx = EVP_MD_CTX_new()) == NULL) {
      DEBUG("ERROR: Cannot allocate EVP_MD_CTX_new() memory.");
      return 0;
    }

    // Duplicate the value
    if (tmp_md_ctx) {
      if (!EVP_MD_CTX_copy_ex(dst_it->md_ctx, tmp_md_ctx)) {
        DEBUG("ERROR: Cannot duplicate MD context");
	return 0;
      }
    }

    // Push the item contex to the composite CTX
    if (!COMPOSITE_CTX_push_item(dst_comp_ctx, dst_it)) {
      DEBUG("ERROR: Cannot push component #%d in the destination CTX", i);
      return 0;
    }
  }

  DEBUG("All Done.");
  return 1;
}

// Implemented
static void cleanup(EVP_PKEY_CTX * ctx) {

  COMPOSITE_CTX * comp_ctx = NULL;
    // Composite Context

  // Input Check
  if (!ctx) return;

  // Retrieves the internal context
  if ((comp_ctx = ctx->data) != NULL)
    COMPOSITE_CTX_free(comp_ctx);

  DEBUG("cleanup completed successfully.");

  return;
}

// Not Implemented
static int paramgen_init(EVP_PKEY_CTX * ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int paramgen(EVP_PKEY_CTX * ctx,
                    EVP_PKEY     * pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Nothing to do here
// Function is invoked by EVP_PKEY_keygen_init() at
// <OPENSSL>/crypto/evp/pmeth_gn2.c
static int keygen_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 1;
}

// Implemented
static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {

  COMPOSITE_CTX * comp_ctx = NULL;
  COMPOSITE_KEY * key = NULL;

  // Input Validation
  if (!ctx || !ctx->data || !pkey) return 0;

#ifdef NID_composite
  // Some extra checking for correctness
  if ((alg_nid = ctx->pmeth->pkey_id) != NID_composite) {
    DEBUG("ERROR: NID is not NID_composite (%d vs. %d)",
      alg_nid, NID_composite);
    return 0;
  }
#else
  DEBUG("ERROR: Missing support for NID_composite");
  return 0;
#endif

  // Checks we have the right data and items
  if (!(comp_ctx = ctx->data) || 
        COMPOSITE_CTX_num(comp_ctx) <= 0) {

    // No components present in the key
    DEBUG("ERROR: No Keys Are Present in the SEQUENCE!");
    return 0;
  }

  // Allocates the Composite Key
  if ((key = COMPOSITE_KEY_new_null()) == NULL) {
    DEBUG("Memory allocation error");
    return 0;
  }

  for (int i = 0; i < COMPOSITE_CTX_num(comp_ctx); i++ ) {

    EVP_PKEY * tmp_pkey = NULL;
      // Pointer to the single component's key

    DEBUG("Adding Key #%d", i);

    if (!COMPOSITE_CTX_pkey_get0(comp_ctx, &tmp_pkey, i) ||
         tmp_pkey == NULL) {
      DEBUG("ERROR: Cannot add PKEY to Composite Key component #%d", i);
      COMPOSITE_KEY_free(key);
    }

    // Adds the key in the key stack
    COMPOSITE_KEY_push(key, tmp_pkey);
  }

  // NOTE: To Get the Structure, use EVP_PKEY_get0(EVP_PKEY *k)
  // NOTE: To Add the Key Structure, use EVP_PKEY_assign()
  EVP_PKEY_assign_COMPOSITE(pkey, key);
  // EVP_PKEY_assign(pkey, -1, comp_ctx->key);

  DEBUG("KeyGen Completed Successfully.");

  return 1;
}

// Implemented
static int sign_init(EVP_PKEY_CTX *ctx) {

  COMPOSITE_CTX * comp_ctx = ctx->data;
    // Algorithm specific context

  if (!comp_ctx) return 0;

  for (int i = 0; i < COMPOSITE_CTX_num(comp_ctx); i++) {

    COMPOSITE_CTX_ITEM * it = NULL;
      // Pointer to Internal Structure that
      // contains also the EVP_PKEY_CTX for
      // the component of the key

    if ((it = COMPOSITE_CTX_get_item(comp_ctx, i)) == NULL)
      return 0;

    if (!it->pkey_ctx) {
      // Copies some details from the main EVP_PKEY_CTX
      // int the newly generated one associated to the
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
      DEBUG("ERROR: Cannot initialize signature for Key Component #%d", i);
      return 0;
    }
  }

  // We add all of these to the EVP_PKEY_CTX... but
  // where does the EVP_PKEY_CTX go?
  DEBUG("Initialized COMPOSITE_CTX at %p (from EVP_PKEY_CTX at %p)",
    comp_ctx, ctx);

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

    EVP_PKEY * evp_pkey = NULL;
    EVP_PKEY_CTX * pkey_ctx = NULL;

    if ((evp_pkey = COMPOSITE_KEY_get0(comp_key, i)) == NULL) {
      DEBUG("ERROR: Cannot get %d-th component from Key", i);
      return 0;
    }

    if ((pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL)) == NULL) {
      DEBUG("ERROR: Cannot allocate a new EVP_PKEY_CTX");
      return 0;
    };

    pkey_ctx->operation = EVP_PKEY_OP_SIGN;

    DEBUG("Determining Signature Size for Component #%d", i);

    // Let's get the size of the single signature
    if (EVP_PKEY_sign(pkey_ctx, NULL, (size_t *)&buff_len, tbs, tbslen) != 1) {
      DEBUG("ERROR: Null Size reported from Key Component #%d", i);
      goto err;
    }

    // Allocate the buffer for the single signature
    if ((pnt = buff = OPENSSL_malloc((size_t)buff_len)) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
      /* Error */
      DEBUG("ERROR: Error setting the signature digest");
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
    ASN1_STRING_set0(oct_string, pnt, buff_len);
    pnt = NULL; buff_len = 0;

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
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int verify(EVP_PKEY_CTX        * ctx,
                  const unsigned char * sig,
                  size_t                siglen,
                  const unsigned char * tbs,
                  size_t                tbslen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover(EVP_PKEY_CTX        * ctx,
                          unsigned char       * rout,
                          size_t              * routlen,
                          const unsigned char * sig,
                          size_t                siglen) {
  DEBUG("Not implemented, yet.");
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

  DEBUG("SIGNCTX INIT");

  DEBUG("ctx = %p, mctx->pctx = %p, mctx->pctx->data = %p",
    ctx, mctx->pctx, mctx->pctx->data);

  DEBUG("COMPOSITE CTX num = %d", COMPOSITE_CTX_num(comp_ctx));
  DEBUG("COMPOSITE KEY num = %d", COMPOSITE_KEY_num(comp_key));

  DEBUG("COMPOSITE CTX num = %d", COMPOSITE_CTX_num(comp_ctx));

  // Status Check
  if (COMPOSITE_CTX_num(comp_ctx) != COMPOSITE_KEY_num(comp_key))

  /*
  if (!EVP_PKEY_sign_init(pkey_ctx)) {
    DEBUG("ERROR: Cannot initialize the Multi-Key PKEY CTX");
    return 0;
  }
  */

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

  COMPOSITE_CTX *comp_ctx = ctx->data;
    // Pointer to the Composite CTX

  EVP_PKEY * pkey = NULL;
    // Pointer to the PKEY to add/del

  DEBUG("PKEY METHOD - CTRL -> CTX = %p, CTX->DATA = %p", ctx, ctx->data);

  // Input checks
  if (!comp_ctx) return 0;

  DEBUG("comp_ctx = %p, ctx->pkey = %p",
    comp_ctx, ctx->pkey);

  DEBUG("Setting (ctrl) (type = %d) (key_id = %d, value = %p)",
        type, key_id, value);

  switch (type) {

    // ===================
    // OpenSSL CTRL Values
    // ===================

    case EVP_PKEY_CTRL_MD: {

      DEBUG("[ PMETH ] ======= Setting the Digest ========== ");

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

    } break;


    case EVP_PKEY_OP_TYPE_SIG: {
      DEBUG("Got EVP sign operation - missing code, returning ok");
    } break;

    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
    case EVP_PKEY_CTRL_SET_MAC_KEY:
    case EVP_PKEY_CTRL_SET_IV: {
      DEBUG("ERROR: Non Supported CTRL");
      return -2;
    } break;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
    case EVP_PKEY_CTRL_CIPHER: {
      
      DEBUG("Nothing to do here CTRL: type = %d, param_1 = %d, param_2 = %p",
        type, key_id, value);

      return 1;

    } break;

    // =====================
    // COMPOSITE CTRL Values
    // =====================

    case EVP_PKEY_CTRL_COMPOSITE_ADD: {

      DEBUG("ADDING KEY to Composite");

      if (!COMPOSITE_CTX_add_pkey(comp_ctx, (EVP_PKEY *)value, key_id)) {
        DEBUG("ERROR: Cannot add component (type %d) to composite key", pkey->type);
        return 0;
      }

      DEBUG("ADD a Key: %d -> %p", key_id, value);

      // All Done
      return 1;

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_PUSH: {

      DEBUG("PUSHING KEY to Composite");

      if (!COMPOSITE_CTX_push_pkey(comp_ctx, (EVP_PKEY *)value)) {
        DEBUG("ERROR: Cannot push component (type %d) to composite key", pkey->type);
        return 0;
      }

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_DEL: {

      DEBUG("DEL a Key: %d", key_id);

      if (key_id <= 0 || key_id >= COMPOSITE_CTX_num(comp_ctx))
        return 0;

      // Delete the specific item from the stack
      COMPOSITE_CTX_del(comp_ctx, key_id);

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_POP: {

      DEBUG("POP a Key");

      COMPOSITE_CTX_pop_free(comp_ctx);

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_CLEAR: {

      DEBUG("Clearing ALL Keys: %d -> %p", key_id, value);

      // Clears all components from the key
      COMPOSITE_CTX_clear(comp_ctx);

    } break;

    default: {
      DEBUG("PKEY METHOD: Unrecognized CTRL (type = %d)", type);
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
  
  DEBUG("Not Implemented, yet.");

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
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int public_check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int param_check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet. Returning Ok anyway.");
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
    0,  // int pkey_id; // EVP_PKEY_COMPOSITE
    0,  // int flags; //EVP_PKEY_FLAG_SIGCTX_CUSTOM
    init,           // int (*init)(EVP_PKEY_CTX *ctx);
    copy,           // int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    cleanup,        // void (*cleanup)(EVP_PKEY_CTX *ctx);
    0, // paramgen_init,  // int (*paramgen_init)(EVP_PKEY_CTX *ctx);
    0, // paramgen,       // int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    keygen_init,    // int (*keygen_init)(EVP_PKEY_CTX *ctx);
    keygen,         // int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    sign_init,      // int (*sign_init) (EVP_PKEY_CTX *ctx);
    sign,           // int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    0, // verify_init,    // int (*verify_init) (EVP_PKEY_CTX *ctx);
    verify,         // int (*verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    0, // verify_recover_init,  // int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    0, // verify_recover, // int (*verify_recover) (EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig, size_t siglen);
    0, // signctx_init,   // int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    0, // signctx,        // int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);
    0, // verifyctx_init, // int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    0, // verifyctx,      // int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx);
    0, // encrypt_init,   // int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    0, // encrypt,        // int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    0, // decrypt_init,   // int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    0, // decrypt,        // int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    0, // derive_init,    // int (*derive_init) (EVP_PKEY_CTX *ctx);
    0, // derive,         // int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
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
