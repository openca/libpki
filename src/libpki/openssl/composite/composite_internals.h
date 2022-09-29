/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <openssl/x509.h>
#include <openssl/asn1t.h>

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef OPENSSL_COMPOSITE_LOCAL_H
#define OPENSSL_COMPOSITE_LOCAL_H

#ifdef  __cplusplus
extern "C" {
#endif

// ========================
// Composite Crypto Support
// ========================

// TODO: Remove the use of this hack that
//       is meant to patch things until we
//       can use the dynamic implementation
//       of the ameth/pmeth
// #define NID_composite           1321
// #define NID_combined            1322

// The Dynamic Approach does not let you reference
// the NID directly, therefore we need a different
// approach by using a global variable
// extern int NID_composite;
// extern int NID_combined;

// We need to find a solution for replacing
// the use of NID_composite with the dynamic
// version of it
// # define EVP_PKEY_COMPOSITE     0
// # define EVP_PKEY_COMBINED      1

// Basic CTRL values for COMPOSITE support
# define EVP_PKEY_CTRL_COMPOSITE_PUSH    0x201
# define EVP_PKEY_CTRL_COMPOSITE_POP     0x202
# define EVP_PKEY_CTRL_COMPOSITE_ADD     0x203
# define EVP_PKEY_CTRL_COMPOSITE_DEL     0x204
# define EVP_PKEY_CTRL_COMPOSITE_CLEAR   0x205

// Declares the assign function, we can not use the
// define mechanism because the EVP_PKEY_COMPOSITE is
// not defined at compile time
// #ifdef ENABLE_COMPOSITE
// # define EVP_PKEY_assign_COMPOSITE(pkey,comp_key)
//     EVP_PKEY_assign((pkey),EVP_PKEY_COMPOSITE, (char *)(comp_key))
// # endif

inline int EVP_PKEY_assign_COMPOSITE(EVP_PKEY *pkey, void *comp_key) {
  // Retrieves the composite ID
  int composite_id = OBJ_txt2nid("composite");
  // Assigns the internal key
  return EVP_PKEY_assign(pkey, composite_id, comp_key);
};

// ==============================
// Declarations & Data Structures
// ==============================

DEFINE_STACK_OF(EVP_PKEY);
  // Provides the Definition for the stack of keys

// DEFINE_STACK_OF_CONST(EVP_PKEY);
  // Provides the Definition for the stack of keys

typedef STACK_OF(EVP_PKEY) COMPOSITE_KEY;
  // The Composite Key is just a Stack of EVP_PKEY

DEFINE_STACK_OF(EVP_PKEY_CTX)
  // Provides the definition for the stack of CTX

DEFINE_STACK_OF(EVP_MD_CTX);
  // Provides the Definition for the stack of keys

// DEFINE_STACK_OF_CONST(EVP_PKEY_CTX)
  // Provides the definition for the stack of CTX

typedef struct {

    EVP_PKEY_CTX * pkey_ctx;
      // Stack of context for the components

    EVP_MD_CTX * md_ctx;
      // Stack of MD CTX for the components

} COMPOSITE_CTX_ITEM;

DEFINE_STACK_OF(COMPOSITE_CTX_ITEM);
//DEFINE_STACK_OF_CONST(COMPOSITE_CTX_ITEM);

typedef STACK_OF(COMPOSITE_CTX_ITEM) COMPOSITE_CTX;

// Used to Concatenate the encodings of the different
// components when encoding via the ASN1 meth (priv_encode)

DEFINE_STACK_OF(ASN1_OCTET_STRING)

// ====================
// Functions Prototypes
// ====================

// COMPOSITE_KEY: Stack Aliases
// ----------------------------

#define COMPOSITE_KEY_new()                sk_EVP_PKEY_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_KEY_new_null()           sk_EVP_PKEY_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_KEY_push(key, val)       sk_EVP_PKEY_push(key, val)
  // Pushes a new EVP_PKEY to the key

#define COMPOSITE_KEY_pop(key)             sk_EVP_PKEY_pop(key)
  // Removes the last EVP_PKEY from the key

#define COMPOSITE_KEY_pop_free(key)        sk_EVP_PKEY_pop_free(key, EVP_PKEY_free)
  // Removes the last EVP_PKEY from the key and frees memory

#define COMPOSITE_KEY_num(key)             sk_EVP_PKEY_num(key)
  // Gets the number of components of a key

#define COMPOSITE_KEY_value(key, num)      sk_EVP_PKEY_value(key, num)
  // Returns the num-th EVP_PKEY in the stack

#define COMPOSITE_KEY_add(key, value, num) sk_EVP_PKEY_insert(key, value, num)
  // Adds a component at num-th position

#define COMPOSITE_KEY_del(key, num)        EVP_PKEY_free(sk_EVP_PKEY_delete(key, num))
  // Deletesthe num-th component from the key

#define COMPOSITE_KEY_get0(key, num)       sk_EVP_PKEY_value(key, num)
  // Alias for the COMPOSITE_KEY_num() define

#define COMPOSITE_KEY_dup(key)             sk_EVP_PKEY_deep_copy(key, EVP_PKEY_dup, EVP_PKEY_free)
  // Duplicates (deep copy) the key

// Free all components of the key
static inline void COMPOSITE_KEY_clear(COMPOSITE_KEY *key) {

  if (!key) return;

  while (sk_EVP_PKEY_num(key) > 0) { 
    sk_EVP_PKEY_pop_free(key, EVP_PKEY_free); 
  }
}

static inline void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {
  
  if (!key) return;

  COMPOSITE_KEY_clear(key);
  OPENSSL_free(key);
}

// COMPOSITE_CTX_ITEM: Prototypes
// ------------------------------

COMPOSITE_CTX_ITEM * COMPOSITE_CTX_ITEM_new_null();
  // Allocates a new internal CTX item

void COMPOSITE_CTX_ITEM_free(COMPOSITE_CTX_ITEM * it);
  // Frees the memory associated with a CTX

// COMPOSITE_CTX: Stack Aliases
// ----------------------------

#define COMPOSITE_CTX_new()                sk_COMPOSITE_CTX_ITEM_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_CTX_new_null()           sk_COMPOSITE_CTX_ITEM_new_null()
  // Allocates a new stack of EVP_PKEY

#define COMPOSITE_CTX_push_item(ctx, val)  sk_COMPOSITE_CTX_ITEM_push(ctx, val)
  // Pushes a new EVP_PKEY_CTX to the CTX

#define COMPOSITE_CTX_pop_item(ctx)        sk_COMPOSITE_CTX_ITEM_pop(ctx)
  // Removes the last EVP_PKEY_CTX from the CTX

#define COMPOSITE_CTX_pop_free(ctx)        sk_COMPOSITE_CTX_ITEM_pop_free(ctx, COMPOSITE_CTX_ITEM_free)
  // Removes the last EVP_PKEY_CTX from the CTX and frees memory

#define COMPOSITE_CTX_num(ctx)             sk_COMPOSITE_CTX_ITEM_num(ctx)
  // Gets the number of components of a ctx

#define COMPOSITE_CTX_value(ctx, num)      sk_COMPOSITE_CTX_ITEM_value(ctx, num)
  // Returns the num-th EVP_PKEY in the stack

#define COMPOSITE_CTX_add_item(ctx, value, num) sk_COMPOSITE_CTX_ITEM_insert(ctx, value, num)
  // Adds a component at num-th position

#define COMPOSITE_CTX_del(ctx, num)        COMPOSITE_CTX_ITEM_free(sk_COMPOSITE_CTX_ITEM_delete(ctx, num))
  // Deletes the num-th component from the key

#define COMPOSITE_CTX_get_item(ctx, num)   sk_COMPOSITE_CTX_ITEM_value(ctx, num)
  // Alias for the COMPOSITE_KEY_num() define

#define COMPOSITE_CTX_dup(ctx)             sk_COMPOSITE_CTX_ITEM_copy(ctx, COMPOSITE_CTX_ITEM_dup, COMPOSITE_CTX_ITEM_free)
  // Duplicates (deep copy) the key

int COMPOSITE_CTX_add(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  * pkey_ctx, 
                      EVP_MD_CTX    * md_ctx,
                      int             index);

int COMPOSITE_CTX_add_pkey(COMPOSITE_CTX * comp_ctx,
                           EVP_PKEY      * pkey,
                           int             index);

int COMPOSITE_CTX_push(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  * pkey_ctx,
                      EVP_MD_CTX    * md_ctx);

int COMPOSITE_CTX_push_pkey(COMPOSITE_CTX * comp_ctx,
                            EVP_PKEY      * pkey);

int COMPOSITE_CTX_get0(COMPOSITE_CTX  * comp_ctx,
                       int              index,
                       EVP_PKEY_CTX  ** pkey_ctx,
                       EVP_MD_CTX    ** md_ctx);

int COMPOSITE_CTX_pkey_get0(COMPOSITE_CTX  * comp_ctx,
                            EVP_PKEY      ** pkey_ctx,
                            int              index);

int COMPOSITE_CTX_pop(COMPOSITE_CTX * comp_ctx,
                      EVP_PKEY_CTX  ** pkey_ctx,
                      EVP_MD_CTX    ** md_ctx);

void COMPOSITE_CTX_clear(COMPOSITE_CTX *ctx);

void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx);

// Returns the total size of the components
int COMPOSITE_KEY_size(COMPOSITE_KEY * key);

// Returns the total size in bits of the components
// (does this even make sense ?)
int COMPOSITE_KEY_bits(COMPOSITE_KEY * bits);

// Returns the security bits of the composite key
// which is the lowest (if the OR logic is implemented)
// or is the highest (if the AND logic is implemented)
// among the key components
int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * sec_bits);


#ifdef  __cplusplus
}
#endif
#endif

/* END: composite_local.h */

// #endif // ENABLE_COMPOSITE