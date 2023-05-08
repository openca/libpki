/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <strings.h>

#ifndef _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H
#define _LIBPKI_COMPOSITE_OPENSSL_LOCAL_H

#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
# include "../internal/ossl_1_1_1/refcount.h"
# include "../internal/ossl_1_1_1/x509_int.h"
#else
# if OPENSSL_VERSION_NUMBER >= 0x1010000fL
#  include "../internal/ossl_1_1_1/refcount.h"
#  include "../internal/ossl_1_1_0/x509_int.h"
# endif
#endif

#ifdef  __cplusplus
extern "C" {
#endif

// ==============================
// Declarations & Data Structures
// ==============================

// Definition for EVP_PKEY and ECX_KEY
// taken from openssl/include/crypto/evp.h
# ifndef OPENSSL_NO_EC

#define X25519_KEYLEN        32
#define X448_KEYLEN          56
#define ED448_KEYLEN         57

#define MAX_KEYLEN  ED448_KEYLEN

// Definition from 
typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;

#endif

// Definition from pem_pkey.c
struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY *pkey;
};

// EVP_MD_CTX related stuff
// ========================

struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;


// EVP_PKEY related stuff
// ======================

/*
 * Type needs to be a bit field Sub-type needs to be for variations on the
 * method, as in, can it do arbitrary encryption....
 */
struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */ ;

// EVP_PKEY_ASN1_METHOD related stuff
// ==================================

struct evp_pkey_asn1_method_st {
    int pkey_id;
    int pkey_base_id;
    unsigned long pkey_flags;
    char *pem_str;
    char *info;
    int (*pub_decode) (EVP_PKEY *pk, X509_PUBKEY *pub);
    int (*pub_encode) (X509_PUBKEY *pub, const EVP_PKEY *pk);
    int (*pub_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
    int (*pub_print) (BIO *out, const EVP_PKEY *pkey, int indent,
                      ASN1_PCTX *pctx);
    int (*priv_decode) (EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);
    int (*priv_encode) (PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);
    int (*priv_print) (BIO *out, const EVP_PKEY *pkey, int indent,
                       ASN1_PCTX *pctx);
    int (*pkey_size) (const EVP_PKEY *pk);
    int (*pkey_bits) (const EVP_PKEY *pk);
    int (*pkey_security_bits) (const EVP_PKEY *pk);
    int (*param_decode) (EVP_PKEY *pkey,
                         const unsigned char **pder, int derlen);
    int (*param_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    int (*param_missing) (const EVP_PKEY *pk);
    int (*param_copy) (EVP_PKEY *to, const EVP_PKEY *from);
    int (*param_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
    int (*param_print) (BIO *out, const EVP_PKEY *pkey, int indent,
                        ASN1_PCTX *pctx);
    int (*sig_print) (BIO *out,
                      const X509_ALGOR *sigalg, const ASN1_STRING *sig,
                      int indent, ASN1_PCTX *pctx);
    void (*pkey_free) (EVP_PKEY *pkey);
    int (*pkey_ctrl) (EVP_PKEY *pkey, int op, long arg1, void *arg2);
    /* Legacy functions for old PEM */
    int (*old_priv_decode) (EVP_PKEY *pkey,
                            const unsigned char **pder, int derlen);
    int (*old_priv_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    /* Custom ASN1 signature verification */
    int (*item_verify) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                        X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey);
    int (*item_sign) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                      X509_ALGOR *alg1, X509_ALGOR *alg2,
                      ASN1_BIT_STRING *sig);
    int (*siginf_set) (X509_SIG_INFO *siginf, const X509_ALGOR *alg,
                       const ASN1_STRING *sig);
    /* Check */
    int (*pkey_check) (const EVP_PKEY *pk);
    int (*pkey_public_check) (const EVP_PKEY *pk);
    int (*pkey_param_check) (const EVP_PKEY *pk);
    /* Get/set raw private/public key data */
    int (*set_priv_key) (EVP_PKEY *pk, const unsigned char *priv, size_t len);
    int (*set_pub_key) (EVP_PKEY *pk, const unsigned char *pub, size_t len);
    int (*get_priv_key) (const EVP_PKEY *pk, unsigned char *priv, size_t *len);
    int (*get_pub_key) (const EVP_PKEY *pk, unsigned char *pub, size_t *len);
} /* EVP_PKEY_ASN1_METHOD */ ;

// EVP_PKEY_METHOD related stuff
// =============================

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVP_PKEY_CTX *ctx);
    int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*cleanup) (EVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVP_PKEY_CTX *ctx);
    int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init) (EVP_PKEY_CTX *ctx);
    int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);
    int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVP_PKEY_CTX *ctx);
    int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
    int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen);
    int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen);
    int (*check) (EVP_PKEY *pkey);
    int (*public_check) (EVP_PKEY *pkey);
    int (*param_check) (EVP_PKEY *pkey);

    int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
} /* EVP_PKEY_METHOD */ ;

#ifdef  __cplusplus
}
#endif
#endif

/* END: composite_ossl_internals.h */
