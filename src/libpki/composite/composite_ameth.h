/* BEGIN: composite_ameth.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <stdio.h>
// #include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/ec.h>

#include <libpki/composite/composite_internals.h>

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/opensslv.h>

// #include "crypto/asn1.h"
// #include "crypto/evp.h"

#ifndef OPENSSL_COMPOSITE_ASN1_METH_H
#define OPENSSL_COMPOSITE_ASN1_METH_H

#ifdef  __cplusplus
extern "C" {
#endif

// ===============
// Data Structures
// ===============

// Uses the Definition of NID_compositeCrypto and
// NID_combinedCrypto

// ======================
// MACRO & Other Oddities
// ======================

// ===============================
// EVP_PKEY_ASN1_METHOD Prototypes
// ===============================

// Implemented
static int pub_decode(EVP_PKEY *pk, X509_PUBKEY *pub);

// Implemented
static int pub_encode(X509_PUBKEY *pub, const EVP_PKEY *pk);

// Implemented
static int pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

// Implemented
static int pub_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);

// Implemented
static int priv_decode(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);

// Implemented
static int priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);

// Implemented
static int priv_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);

// Implemented
static int pkey_size(const EVP_PKEY *pk);

// Implemented
static int pkey_bits(const EVP_PKEY *pk);

// Implemented
static int pkey_security_bits(const EVP_PKEY *pk);

// Not Implemented
static int param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen);

// Not Implemented
static int param_encode(const EVP_PKEY *pkey, unsigned char **pder);

// Not Implemented
static int param_missing(const EVP_PKEY *pk);

// Not Implemented
static int param_copy(EVP_PKEY *to, const EVP_PKEY *from);

// Implemented
static int param_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

// Not Implemented
static int param_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);

// Not Implemented
static int sig_print(BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx);

// Implemented
static void pkey_free(EVP_PKEY *pkey);

// Implemented
static int pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2);

// ============================
// Legacy Functions for old PEM
// ============================

// Not Implemented
static int old_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen);

// Not Implemented
static int old_priv_encode(const EVP_PKEY *pkey, unsigned char **pder);

// ====================================
// Custom ASN1 signature & verification
// ====================================

// Implemented
static int item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey);

// Implemented
static int item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig);

// Implemented
static int siginf_set(X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig);

// ===================
// EVP Check Functions
// ===================

// Not Implemented
static int pkey_check(const EVP_PKEY *pkey);

// Not Implemented
static int pkey_public_check(const EVP_PKEY *pkey);

// Not Implemented
static int pkey_param_check(const EVP_PKEY *pkey);

// =================================
// Get/Set For Raw priv/pub key data
// =================================

// Not Implemented
static int set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len);

// Not Implemented
static int set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len);

// Not Implemented
static int get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len);

// Not Implemented
static int get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len);

// ===========================
// ASN1 PKEY Method Definition
// ===========================

// The Definition of the EVP_PKEY_ASN1_METHOD is provided above and
// it is taken from OPENSSL_SRC/include/crypto/asn1.h, see the
// OPENSSL_SRC/include/ossl_typ.h
const EVP_PKEY_ASN1_METHOD composite_asn1_meth = {
    EVP_PKEY_COMPOSITE,       // int pkey_id;
    EVP_PKEY_COMPOSITE,       // int pkey_base_id;
    ASN1_PKEY_SIGPARAM_NULL,  // unsigned long pkey_flags; // ASN1_PKEY_SIGPARAM_NULL
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
    param_decode,             // int (*param_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
    param_encode,             // int (*param_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    param_missing,            // int (*param_missing) (const EVP_PKEY *pk);
    param_copy,               // int (*param_copy) (EVP_PKEY *to, const EVP_PKEY *from);
    param_cmp,                // int (*param_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
    param_print,              // int (*param_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
    sig_print,                // int (*sig_print) (BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx);
    pkey_free,                // void (*pkey_free) (EVP_PKEY *pkey);
    pkey_ctrl,                // int (*pkey_ctrl) (EVP_PKEY *pkey, int op, long arg1, void *arg2);
    // Legacy Functions for old PEM
    old_priv_decode,          // int (*old_priv_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
    old_priv_encode,          // int (*old_priv_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    // Custom ASN1 signature verification
    item_verify,              // int (*item_verify) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey);
    item_sign,                // int (*item_sign) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig);
    siginf_set,               // int (*siginf_set) (X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig);
    // PKEY checking interface
    pkey_check,               // int (*pkey_check) (EVP_PKEY *pkey);
    pkey_public_check,        // int (*pkey_public_check) (EVP_PKEY *pkey);
    pkey_param_check,         // int (*pkey_param_check) (EVP_PKEY *pkey);
    set_priv_key,             // int (*set_priv_key) (EVP_PKEY *pk, const unsigned char *priv, size_t len);
    set_pub_key,              // int (*set_pub_key) (EVP_PKEY *pk, const unsigned char *pub, size_t len);
    get_priv_key,             // int (*get_priv_key) (const EVP_PKEY *pk, unsigned char *priv, size_t *len);
    get_pub_key,              // int (*get_pub_key) (const EVP_PKEY *pk, unsigned char *pub, size_t *len);
};

#ifdef  __cplusplus
}
#endif

#endif // OPENSSL_COMPOSITE_AMETH_H

/* END: composite_amenth.h */