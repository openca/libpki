/* BEGIN: composite_pmenth.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala
//
// This file contains the definitions for the EVP_PKEY_METHOD that implements:
//
//     Composite Crypto (OR Logic)
//
// the corresponding functions are defined in composite_ameth.c

#include <stdio.h>

#ifndef HEADER_X509_H
#include <openssl/x509.h>
#endif

#ifndef OPENSSL_COMPOSITE_LOCAL_H
#include <libpki/openssl/composite/composite_internals.h>
#endif

#ifndef OPENSSL_COMPOSITE_PKEY_METH_H
#define OPENSSL_COMPOSITE_PKEY_METH_H

#ifdef  __cplusplus
extern "C" {
#endif

// ===========================
// Data Structures and Defines
// ===========================

// const EVP_PKEY_METHOD composite_pkey_meth;

// // ==========================
// // EVP_PKEY_METHOD Prototypes
// // ==========================

// // Not Implemented
// static int init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int copy(EVP_PKEY_CTX * dst,
//                 EVP_PKEY_CTX * src);

// // Not Implemented
// static void cleanup(EVP_PKEY_CTX * ctx);

// // Not Implemented
// static int paramgen_init(EVP_PKEY_CTX * ctx);

// // Not Implemented
// static int paramgen(EVP_PKEY_CTX * ctx,
//                     EVP_PKEY     * pkey);

// // Not Implemented
// static int keygen_init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

// // Implemented
// static int sign_init(EVP_PKEY_CTX *ctx);

// // Implemented
// static int sign(EVP_PKEY_CTX        * ctx, 
//                 unsigned char       * sig,
//                 size_t              * siglen,
//                 const unsigned char * tbs,
//                 size_t                tbslen);

// // Implemented
// static int verify_init(EVP_PKEY_CTX *ctx);

// // Implemented
// static int verify(EVP_PKEY_CTX        * ctx,
//                   const unsigned char * sig,
//                   size_t                siglen,
//                   const unsigned char * tbs,
//                   size_t                tbslen);

// // Not Implemented
// static int verify_recover_init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int verify_recover(EVP_PKEY_CTX        * ctx,
//                           unsigned char       * rout,
//                           size_t              * routlen,
//                           const unsigned char * sig,
//                           size_t                siglen);

// // Implemented
// static int signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

// // Implemented
// static int signctx (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);

// // Implemented
// static int verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

// // Implemented
// static int verifyctx (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx);

// // Not Implemented
// static int encrypt_init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int encrypt_pmeth(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

// // Not Implemented
// static int decrypt_init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

// // Not Implemented
// static int derive_init(EVP_PKEY_CTX *ctx);

// // Not Implemented
// static int derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

// // Implemented
// static int ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

// // Not Implemented
// static int ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);

// // ===================
// // OpenSSL 1.1.x+ Only
// // ===================

// // Implemented
// static int digestsign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);

// // Implemented
// static int digestverify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);

// // Not Implemented
// static int check(EVP_PKEY *pkey);

// // Not Implemented
// static int public_check(EVP_PKEY *pkey);

// // Not Implemented
// static int param_check(EVP_PKEY *pkey);

// // Implemented
// static int digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

#ifdef  __cplusplus
}
#endif
#endif // OPENSSL_COMPOSITE_PKEY_METH_H

/* END: composite_pmenth.h */