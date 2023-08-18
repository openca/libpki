
#ifndef _LIBPKI_PQC_AMETH_LOCAL_H
#define _LIBPKI_PQC_AMETH_LOCAL_H

// Library configuration
#ifdef __LIB_BUILD__
#include <libpki/config.h>
#else
#include <libpki/libpki_enables.h>
#endif

#ifdef ENABLE_OQS

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_PQC_DEFS_H
#include <libpki/openssl/pqc/pqc_defs.h>
#endif

#ifndef LIBPKI_X509_DATA_ST_H
#include "../internal/x509_data_st.h"
#endif

#ifndef _LIBPKI_PQC_TOOLS_H
#include "pqc_tools.h"
#endif

#ifndef HEADER_OPENSSL_TYPES_H
#include <openssl/ossl_typ.h>
#endif

#ifndef HEADER_ERR_H
#include <openssl/err.h>
#endif

BEGIN_C_DECLS

// ==================
// ASN1 Method Macros
// ==================

// Item Sign Macro
// ---------------

#define DEFINE_OQS_ITEM_SIGN(ALG, NID_ALG) \
static int oqs_item_sign_##ALG(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,\
                         X509_ALGOR *alg1, X509_ALGOR *alg2,                   \
                         ASN1_BIT_STRING *str)                                 \
{                                                                              \
    /* Set algorithm identifier */                                             \
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_ALG), V_ASN1_UNDEF, NULL);           \
    if (alg2 != NULL)                                                          \
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_ALG), V_ASN1_UNDEF, NULL);       \
    /* Algorithm identifier set: carry on as normal */                         \
    return 3;                                                                  \
}


// Signature Info Set Macro
// ------------------------

#define DEFINE_OQS_SIGN_INFO_SET(ALG, NID_ALG) \
static int oqs_sig_info_set_##ALG(X509_SIG_INFO *siginf, const X509_ALGOR *alg,  \
                            const ASN1_STRING *sig)                              \
{                                                                                \
    X509_SIG_INFO_set(siginf, NID_sha512, NID_ALG, get_oqs_security_bits(NID_ALG),\
                      X509_SIG_INFO_TLS);                                        \
    return 1;                                                                    \
}

// Generic ASN1 Method NID-dependent define macro
#define DEFINE_ITEM_SIGN_AND_INFO_SET(ALG)     \
static int oqs_item_sign_##ALG(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,\
                         X509_ALGOR *alg1, X509_ALGOR *alg2,                   \
                         ASN1_BIT_STRING *str)                                 \
{                                                                              \
    /* Set algorithm identifier */                                             \
    X509_ALGOR_set0(alg1, OBJ_txt2obj(#ALG,0), V_ASN1_UNDEF, NULL);              \
    if (alg2 != NULL)                                                          \
        X509_ALGOR_set0(alg2, OBJ_txt2obj(#ALG,0), V_ASN1_UNDEF, NULL);          \
    /* Algorithm identifier set: carry on as normal */                         \
    return 3;                                                                  \
}                                                                              \
static int oqs_sig_info_set_##ALG(X509_SIG_INFO *siginf, const X509_ALGOR *alg,    \
                            const ASN1_STRING *sig)                                \
{                                                                                  \
    X509_SIG_INFO_set(siginf, NID_sha512, OBJ_sn2nid(#ALG), get_oqs_security_bits(OBJ_txt2nid(#ALG)), \
                      X509_SIG_INFO_TLS);                                          \
    return 1;                                                                      \
}

// =================
// ASN1 Method Tools
// =================

int oqs_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx, oqs_key_type_t keytype);

// =====================
// ASN1 Method Interface
// =====================

int oqs_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey);

int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey);

int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

int oqs_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8);

int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey);

int oqs_size_lcl(const EVP_PKEY *pkey);

int oqs_bits(const EVP_PKEY *pkey);

int oqs_security_bits(const EVP_PKEY *pkey);

void oqs_free(EVP_PKEY *pkey);

int oqs_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);

int oqs_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx);

int oqs_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx);

int oqs_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *str,
                           EVP_PKEY *pkey);

int oqs_ameth_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2);

END_C_DECLS

# endif // End of ENABLE_OQS

#endif // End of _LIBPKI_PQC_AMETH_LOCAL_H
