#include "ocsprov_encoder.h"

// Forward declaration for encoder functions
static OSSL_FUNC_encoder_newctx_fn ocsprov_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn ocsprov_encoder_freectx;
static OSSL_FUNC_encoder_encode_fn ocsprov_encoder_encode;

// Encoder context structure
typedef struct {
    // Context-specific fields
} PKI_OSSL_OCSPROV_ENCODER_CTX;

// Encoder Dispatch Table
static const OSSL_DISPATCH ocsprov_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))ocsprov_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))ocsprov_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))ocsprov_encoder_encode },
    { 0, NULL }
};

// Encoder Descriptor
const OSSL_DISPATCH *ocsprov_encoders(const OSSL_CORE_HANDLE  * handle,
                                      const OSSL_DISPATCH     * in,
                                      const OSSL_DISPATCH    ** out,
                                      void                    * provctx) {
    // You can return different dispatch tables based on input parameters if needed
    return ocsprov_encoder_functions;
}

// Encoder New Context
static void *ocsprov_encoder_newctx(void *provctx) {
    PKI_OSSL_OCSPROV_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    // Initialize context (if necessary)
    return ctx;
}

// Encoder Free Context
static void ocsprov_encoder_freectx(void *ctx) {
    OPENSSL_free(ctx);
}

// Encoder Encode Function
static int ocsprov_encoder_encode(void              * ctx,
                                  OSSL_CORE_BIO     * out,
                                  const void        * obj_raw,
                                  const OSSL_PARAM    obj_abstraction[],
                                  int                 selection,
                                  OSSL_PASSPHRASE_CALLBACK * cb,
                                  void              * cbarg) {
                                    
    // Implement encoding logic here
    // Normally, you would use the 'data' parameter, which is your EVP key or other object,
    // and encode it to the desired format (e.g., PEM, DER), writing the result to 'out'

    return 1; // Indicate success for this example
}

// struct key2any_ctx_st {
//     PROV_OQS_CTX *provctx;

//     /* Set to 0 if parameters should not be saved (dsa only) */
//     int save_parameters;

//     /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
//     int cipher_intent;

//     EVP_CIPHER *cipher;

//     OSSL_PASSPHRASE_CALLBACK *pwcb;
//     void *pwcbarg;
// };

// typedef int check_key_type_fn(const void *key, int nid);
// typedef int key_to_paramstring_fn(const void *key, int nid, int save,
//                                   void **str, int *strtype);
// typedef int key_to_der_fn(BIO *out, const void *key, int key_nid,
//                           const char *pemname, key_to_paramstring_fn *p2s,
//                           i2d_of_void *k2d, struct key2any_ctx_st *ctx);
// typedef int write_bio_of_void_fn(BIO *bp, const void *x);

// /* Free the blob allocated during key_to_paramstring_fn */
// static void free_asn1_data(int type, void *data)
// {
//     switch (type) {
//     case V_ASN1_OBJECT:
//         ASN1_OBJECT_free(data);
//         break;
//     case V_ASN1_SEQUENCE:
//         ASN1_STRING_free(data);
//         break;
//     }
// }

// static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,
//                                           void *params, int params_type,
//                                           i2d_of_void *k2d)
// {
//     /* der, derlen store the key DER output and its length */
//     unsigned char *der = NULL;
//     int derlen;
//     /* The final PKCS#8 info */
//     PKCS8_PRIV_KEY_INFO *p8info = NULL;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_p8info called\n");

//     if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == NULL
//         || (derlen = k2d(key, &der)) <= 0
//         || !PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
//                             // doesn't work with oqs-openssl:
//                             //  params_type, params,
//                             // does work/interop:
//                             V_ASN1_UNDEF, NULL, der, derlen)) {
//         ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//         PKCS8_PRIV_KEY_INFO_free(p8info);
//         OPENSSL_free(der);
//         p8info = NULL;
//     }

//     return p8info;
// }

// static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info,
//                                  struct key2any_ctx_st *ctx)
// {
//     X509_SIG *p8 = NULL;
//     char kstr[PEM_BUFSIZE];
//     size_t klen = 0;
//     OSSL_LIB_CTX *libctx = PROV_OQS_LIBCTX_OF(ctx->provctx);

//     OQS_ENC_PRINTF("OQS ENC provider: p8info_to_encp8 called\n");

//     if (ctx->cipher == NULL || ctx->pwcb == NULL)
//         return NULL;

//     if (!ctx->pwcb(kstr, PEM_BUFSIZE, &klen, NULL, ctx->pwcbarg)) {
//         ERR_raise(ERR_LIB_USER, PROV_R_UNABLE_TO_GET_PASSPHRASE);
//         return NULL;
//     }
//     /* First argument == -1 means "standard" */
//     p8 = PKCS8_encrypt_ex(-1, ctx->cipher, kstr, klen, NULL, 0, 0, p8info,
//                           libctx, NULL);
//     OPENSSL_cleanse(kstr, klen);
//     return p8;
// }

// static X509_SIG *key_to_encp8(const void *key, int key_nid, void *params,
//                               int params_type, i2d_of_void *k2d,
//                               struct key2any_ctx_st *ctx)
// {
//     PKCS8_PRIV_KEY_INFO *p8info
//         = key_to_p8info(key, key_nid, params, params_type, k2d);
//     X509_SIG *p8 = NULL;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_encp8 called\n");

//     if (p8info == NULL) {
//         free_asn1_data(params_type, params);
//     } else {
//         p8 = p8info_to_encp8(p8info, ctx);
//         PKCS8_PRIV_KEY_INFO_free(p8info);
//     }
//     return p8;
// }

// static X509_PUBKEY *oqsx_key_to_pubkey(const void *key, int key_nid,
//                                        void *params, int params_type,
//                                        i2d_of_void k2d)
// {
//     /* der, derlen store the key DER output and its length */
//     unsigned char *der = NULL;
//     int derlen;
//     /* The final X509_PUBKEY */
//     X509_PUBKEY *xpk = NULL;

//     OQS_ENC_PRINTF2("OQS ENC provider: oqsx_key_to_pubkey called for NID %d\n",
//                     key_nid);

//     if ((xpk = X509_PUBKEY_new()) == NULL || (derlen = k2d(key, &der)) <= 0
//         || !X509_PUBKEY_set0_param(
//             xpk, OBJ_nid2obj(key_nid), V_ASN1_UNDEF,
//             NULL, // as per logic in oqs_meth.c in oqs-openssl
//             der, derlen)) {
//         ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//         X509_PUBKEY_free(xpk);
//         OPENSSL_free(der);
//         xpk = NULL;
//     }

//     return xpk;
// }

// /*
//  * key_to_epki_* produce encoded output with the private key data in a
//  * EncryptedPrivateKeyInfo structure (defined by PKCS#8).  They require
//  * that there's an intent to encrypt, anything else is an error.
//  *
//  * key_to_pki_* primarly produce encoded output with the private key data
//  * in a PrivateKeyInfo structure (also defined by PKCS#8).  However, if
//  * there is an intent to encrypt the data, the corresponding key_to_epki_*
//  * function is used instead.
//  *
//  * key_to_spki_* produce encoded output with the public key data in an
//  * X.509 SubjectPublicKeyInfo.
//  *
//  * Key parameters don't have any defined envelopment of this kind, but are
//  * included in some manner in the output from the functions described above,
//  * either in the AlgorithmIdentifier's parameter field, or as part of the
//  * key data itself.
//  */

// static int key_to_epki_der_priv_bio(BIO *out, const void *key, int key_nid,
//                                     ossl_unused const char *pemname,
//                                     key_to_paramstring_fn *p2s,
//                                     i2d_of_void *k2d,
//                                     struct key2any_ctx_st *ctx)
// {
//     int ret = 0;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;
//     X509_SIG *p8;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_epki_der_priv_bio called\n");

//     if (!ctx->cipher_intent)
//         return 0;

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
//     if (p8 != NULL)
//         ret = i2d_PKCS8_bio(out, p8);

//     X509_SIG_free(p8);

//     return ret;
// }

// static int key_to_epki_pem_priv_bio(BIO *out, const void *key, int key_nid,
//                                     ossl_unused const char *pemname,
//                                     key_to_paramstring_fn *p2s,
//                                     i2d_of_void *k2d,
//                                     struct key2any_ctx_st *ctx)
// {
//     int ret = 0;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;
//     X509_SIG *p8;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_epki_pem_priv_bio called\n");

//     if (!ctx->cipher_intent)
//         return 0;

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
//     if (p8 != NULL)
//         ret = PEM_write_bio_PKCS8(out, p8);

//     X509_SIG_free(p8);

//     return ret;
// }

// static int key_to_pki_der_priv_bio(BIO *out, const void *key, int key_nid,
//                                    ossl_unused const char *pemname,
//                                    key_to_paramstring_fn *p2s, i2d_of_void *k2d,
//                                    struct key2any_ctx_st *ctx)
// {
//     int ret = 0;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;
//     PKCS8_PRIV_KEY_INFO *p8info;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_pki_der_priv_bio called\n");

//     if (ctx->cipher_intent)
//         return key_to_epki_der_priv_bio(out, key, key_nid, pemname, p2s, k2d,
//                                         ctx);

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     p8info = key_to_p8info(key, key_nid, str, strtype, k2d);

//     if (p8info != NULL)
//         ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);
//     else
//         free_asn1_data(strtype, str);

//     PKCS8_PRIV_KEY_INFO_free(p8info);

//     return ret;
// }

// static int key_to_pki_pem_priv_bio(BIO *out, const void *key, int key_nid,
//                                    ossl_unused const char *pemname,
//                                    key_to_paramstring_fn *p2s, i2d_of_void *k2d,
//                                    struct key2any_ctx_st *ctx)
// {
//     int ret = 0, cmp_len = 0;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;
//     PKCS8_PRIV_KEY_INFO *p8info;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_pki_pem_priv_bio called\n");

//     if (ctx->cipher_intent)
//         return key_to_epki_pem_priv_bio(out, key, key_nid, pemname, p2s, k2d,
//                                         ctx);

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     p8info = key_to_p8info(key, key_nid, str, strtype, k2d);
//     if (p8info != NULL)
//         ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);
//     else
//         free_asn1_data(strtype, str);

//     PKCS8_PRIV_KEY_INFO_free(p8info);

//     return ret;
// }

// static int key_to_spki_der_pub_bio(BIO *out, const void *key, int key_nid,
//                                    ossl_unused const char *pemname,
//                                    key_to_paramstring_fn *p2s, i2d_of_void *k2d,
//                                    struct key2any_ctx_st *ctx)
// {
//     int ret = 0;
//     OQSX_KEY *okey = (OQSX_KEY *)key;
//     X509_PUBKEY *xpk = NULL;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_spki_der_pub_bio called\n");

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     xpk = oqsx_key_to_pubkey(key, key_nid, str, strtype, k2d);

//     if (xpk != NULL)
//         ret = i2d_X509_PUBKEY_bio(out, xpk);

//     X509_PUBKEY_free(xpk);
//     return ret;
// }

// static int key_to_spki_pem_pub_bio(BIO *out, const void *key, int key_nid,
//                                    ossl_unused const char *pemname,
//                                    key_to_paramstring_fn *p2s, i2d_of_void *k2d,
//                                    struct key2any_ctx_st *ctx)
// {
//     int ret = 0;
//     X509_PUBKEY *xpk = NULL;
//     void *str = NULL;
//     int strtype = V_ASN1_UNDEF;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_spki_pem_pub_bio called\n");

//     if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters, &str, &strtype))
//         return 0;

//     xpk = oqsx_key_to_pubkey(key, key_nid, str, strtype, k2d);

//     if (xpk != NULL)
//         ret = PEM_write_bio_X509_PUBKEY(out, xpk);
//     else
//         free_asn1_data(strtype, str);

//     /* Also frees |str| */
//     X509_PUBKEY_free(xpk);
//     return ret;
// }

// /*
//  * key_to_type_specific_* produce encoded output with type specific key data,
//  * no envelopment; the same kind of output as the type specific i2d_ and
//  * PEM_write_ functions, which is often a simple SEQUENCE of INTEGER.
//  *
//  * OpenSSL tries to discourage production of new keys in this form, because
//  * of the ambiguity when trying to recognise them, but can't deny that PKCS#1
//  * et al still are live standards.
//  *
//  * Note that these functions completely ignore p2s, and rather rely entirely
//  * on k2d to do the complete work.
//  */
// /*
// static int key_to_type_specific_der_bio(BIO *out, const void *key,
//                                         int key_nid,
//                                         ossl_unused const char *pemname,
//                                         key_to_paramstring_fn *p2s,
//                                         i2d_of_void *k2d,
//                                         struct key2any_ctx_st *ctx)
// {
//     unsigned char *der = NULL;
//     int derlen;
//     int ret;

//     OQS_ENC_PRINTF("OQS ENC provider: key_to_type_specific_der_bio called\n");

//     if ((derlen = k2d(key, &der)) <= 0) {
//         ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//         return 0;
//     }

//     ret = BIO_write(out, der, derlen);
//     OPENSSL_free(der);
//     return ret > 0;
// }
// #define key_to_type_specific_der_priv_bio key_to_type_specific_der_bio
// #define key_to_type_specific_der_pub_bio key_to_type_specific_der_bio
// #define key_to_type_specific_der_param_bio key_to_type_specific_der_bio

// static int key_to_type_specific_pem_bio_cb(BIO *out, const void *key,
//                                            int key_nid, const char *pemname,
//                                            key_to_paramstring_fn *p2s,
//                                            i2d_of_void *k2d,
//                                            struct key2any_ctx_st *ctx)
// {
//     OQS_ENC_PRINTF("OQS ENC provider: key_to_type_specific_pem_bio_cb called
// \n");

//     return PEM_ASN1_write_bio(k2d, pemname, out, key, ctx->cipher,
//                               NULL, 0, ctx->pwcb, ctx->pwcbarg) > 0;
// }

// static int key_to_type_specific_pem_priv_bio(BIO *out, const void *key,
//                                              int key_nid, const char *pemname,
//                                              key_to_paramstring_fn *p2s,
//                                              i2d_of_void *k2d,
//                                              struct key2any_ctx_st *ctx)
// {
//     OQS_ENC_PRINTF("OQS ENC provider: key_to_type_specific_pem_priv_bio
// called\n");

//     return key_to_type_specific_pem_bio_cb(out, key, key_nid, pemname,
//                                            p2s, k2d, ctx, ctx->pwcb,
// ctx->pwcbarg);

// }

// static int key_to_type_specific_pem_pub_bio(BIO *out, const void *key,
//                                             int key_nid, const char *pemname,
//                                             key_to_paramstring_fn *p2s,
//                                             i2d_of_void *k2d,
//                                             struct key2any_ctx_st *ctx)
// {
//     OQS_ENC_PRINTF("OQS ENC provider: key_to_type_specific_pem_pub_bio
// called\n");

//     return key_to_type_specific_pem_bio_cb(out, key, key_nid, pemname,
//                                            p2s, k2d, ctx, NULL, NULL);
// }

// #ifndef OPENSSL_NO_KEYPARAMS
// static int key_to_type_specific_pem_param_bio(BIO *out, const void *key,
//                                               int key_nid, const char *pemname,
//                                               key_to_paramstring_fn *p2s,
//                                               i2d_of_void *k2d,
//                                               struct key2any_ctx_st *ctx)
// {
//     OQS_ENC_PRINTF("OQS ENC provider: key_to_type_specific_pem_param_bio
// called\n");

//     return key_to_type_specific_pem_bio_cb(out, key, key_nid, pemname,
//                                            p2s, k2d, ctx, NULL, NULL);
// }
// #endif
// */
// /* ---------------------------------------------------------------------- */

// static int prepare_oqsx_params(const void *oqsxkey, int nid, int save,
//                                void **pstr, int *pstrtype)
// {
//     ASN1_OBJECT *params = NULL;
//     OQSX_KEY *k = (OQSX_KEY *)oqsxkey;

//     OQS_ENC_PRINTF3(
//         "OQS ENC provider: prepare_oqsx_params called with nid %d (tlsname: %s)\n",
//         nid, k->tls_name);

//     if (k->tls_name && OBJ_sn2nid(k->tls_name) != nid) {
//         ERR_raise(ERR_LIB_USER, PKI_OSSL_OCSPROV_R_INVALID_KEY);
//         return 0;
//     }

//     if (nid != NID_undef) {
//         params = OBJ_nid2obj(nid);
//         if (params == NULL)
//             return 0;
//     } else {
//         ERR_raise(ERR_LIB_USER, PKI_OSSL_OCSPROV_R_MISSING_OID);
//         return 0;
//     }

//     if (OBJ_length(params) == 0) {
//         /* unexpected error */
//         ERR_raise(ERR_LIB_USER, PKI_OSSL_OCSPROV_R_MISSING_OID);
//         ASN1_OBJECT_free(params);
//         return 0;
//     }
//     *pstr = params;
//     *pstrtype = V_ASN1_OBJECT;
//     return 1;
// }

// static int oqsx_spki_pub_to_der(const void *vxkey, unsigned char **pder)
// {
//     const OQSX_KEY *oqsxkey = vxkey;
//     unsigned char *keyblob, *buf;
//     int keybloblen, nid, buflen = 0;
//     ASN1_OCTET_STRING oct;
//     STACK_OF(ASN1_TYPE) *sk = NULL;
//     int ret = 0;

//     OQS_ENC_PRINTF("OQS ENC provider: oqsx_spki_pub_to_der called\n");

//     if (oqsxkey == NULL || oqsxkey->pubkey == NULL) {
//         ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
//         return 0;
//     }
//     if (oqsxkey->keytype != KEY_TYPE_CMP_SIG) {
// #ifdef USE_ENCODING_LIB
//         if (oqsxkey->oqsx_encoding_ctx.encoding_ctx != NULL
//             && oqsxkey->oqsx_encoding_ctx.encoding_impl != NULL) {
//             unsigned char *buf;
//             int buflen;
//             int ret = 0;
//             const OQSX_ENCODING_CTX *encoding_ctx = &oqsxkey->oqsx_encoding_ctx;
//             buflen = encoding_ctx->encoding_impl->crypto_publickeybytes;

//             buf = OPENSSL_secure_zalloc(buflen);
//             if (buf == NULL) {
//                 ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//                 return -1;
//             }
//             ret = qsc_encode(encoding_ctx->encoding_ctx,
//                              encoding_ctx->encoding_impl, oqsxkey->pubkey, &buf,
//                              0, 0, 1);
//             if (ret != QSC_ENC_OK)
//                 return -1;

//             *pder = buf;
//             return buflen;
//         } else {
// #endif
//             keyblob = OPENSSL_memdup(oqsxkey->pubkey, oqsxkey->pubkeylen);
//             if (keyblob == NULL) {
//                 ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//                 return 0;
//             }
//             *pder = keyblob;
//             return oqsxkey->pubkeylen;
// #ifdef USE_ENCODING_LIB
//         }
// #endif
//     } else {
//         if ((sk = sk_ASN1_TYPE_new_null()) == NULL)
//             return -1;
//         ASN1_TYPE **aType
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_TYPE *));
//         ASN1_BIT_STRING **aString
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_BIT_STRING *));
//         unsigned char **temp
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(unsigned char *));
//         size_t *templen = OPENSSL_malloc(oqsxkey->numkeys * sizeof(size_t));
//         int i;

//         for (i = 0; i < oqsxkey->numkeys; i++) {
//             aType[i] = ASN1_TYPE_new();
//             aString[i] = ASN1_BIT_STRING_new();
//             temp[i] = NULL;

//             buflen = oqsxkey->pubkeylen_cmp[i];
//             buf = OPENSSL_secure_malloc(buflen);
//             memcpy(buf, oqsxkey->comp_pubkey[i], buflen);

//             oct.data = buf;
//             oct.length = buflen;
//             oct.flags = 8;
//             templen[i] = i2d_ASN1_BIT_STRING(&oct, &temp[i]);
//             ASN1_STRING_set(aString[i], temp[i], templen[i]);
//             ASN1_TYPE_set1(aType[i], V_ASN1_SEQUENCE, aString[i]);

//             if (!sk_ASN1_TYPE_push(sk, aType[i])) {
//                 for (int j = 0; j <= i; j++) {
//                     OPENSSL_cleanse(aString[j]->data, aString[j]->length);
//                     ASN1_BIT_STRING_free(aString[j]);
//                     OPENSSL_cleanse(aType[j]->value.sequence->data,
//                                     aType[j]->value.sequence->length);
//                     OPENSSL_clear_free(temp[j], templen[j]);
//                 }

//                 sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//                 OPENSSL_secure_clear_free(buf, buflen);
//                 OPENSSL_free(aType);
//                 OPENSSL_free(aString);
//                 OPENSSL_free(temp);
//                 OPENSSL_free(templen);
//                 return -1;
//             }
//             OPENSSL_secure_clear_free(buf, buflen);
//         }
//         keybloblen = i2d_ASN1_SEQUENCE_ANY(sk, pder);

//         for (i = 0; i < oqsxkey->numkeys; i++) {
//             OPENSSL_cleanse(aString[i]->data, aString[i]->length);
//             ASN1_BIT_STRING_free(aString[i]);
//             OPENSSL_cleanse(aType[i]->value.sequence->data,
//                             aType[i]->value.sequence->length);
//             OPENSSL_clear_free(temp[i], templen[i]);
//         }

//         sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//         OPENSSL_free(aType);
//         OPENSSL_free(aString);
//         OPENSSL_free(temp);
//         OPENSSL_free(templen);

//         return keybloblen;
//     }
// }

// static int oqsx_pki_priv_to_der(const void *vxkey, unsigned char **pder)
// {
//     OQSX_KEY *oqsxkey = (OQSX_KEY *)vxkey;
//     unsigned char *buf = NULL;
//     int buflen = 0, privkeylen;
//     ASN1_OCTET_STRING oct;
//     int keybloblen, nid;
//     STACK_OF(ASN1_TYPE) *sk = NULL;
//     char *name;

//     OQS_ENC_PRINTF("OQS ENC provider: oqsx_pki_priv_to_der called\n");

//     // Encoding private _and_ public key concatenated ... seems unlogical and
//     // unnecessary, but is what oqs-openssl does, so we repeat it for interop...
//     // also from a security perspective not really smart to copy key material
//     // (side channel attacks, anyone?), but so be it for now (TBC).
//     if (oqsxkey == NULL || oqsxkey->privkey == NULL
// #ifndef NOPUBKEY_IN_PRIVKEY
//         || oqsxkey->pubkey == NULL
// #endif
//     ) {
//         ERR_raise(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER);
//         return 0;
//     }

//     // only concatenate private classic key (if any) and OQS private and public
//     // key NOT saving public classic key component (if any)
//     if (oqsxkey->keytype != KEY_TYPE_CMP_SIG) {
//         privkeylen = oqsxkey->privkeylen;
//         if (oqsxkey->numkeys > 1) { // hybrid
//             int actualprivkeylen;
//             DECODE_UINT32(actualprivkeylen, oqsxkey->privkey);
//             if (actualprivkeylen > oqsxkey->evp_info->length_private_key) {
//                 ERR_raise(ERR_LIB_USER, PKI_OSSL_OCSPROV_R_INVALID_ENCODING);
//                 return 0;
//             }
//             privkeylen
//                 -= (oqsxkey->evp_info->length_private_key - actualprivkeylen);
//         }
// #ifdef USE_ENCODING_LIB
//         if (oqsxkey->oqsx_encoding_ctx.encoding_ctx != NULL
//             && oqsxkey->oqsx_encoding_ctx.encoding_impl != NULL) {
//             const OQSX_ENCODING_CTX *encoding_ctx = &oqsxkey->oqsx_encoding_ctx;
//             int ret = 0;
// #    ifdef NOPUBKEY_IN_PRIVKEY
//             int withoptional = (encoding_ctx->encoding_ctx
//                                         ->raw_private_key_encodes_public_key
//                                     ? 1
//                                     : 0);
// #    else
//             int withoptional = 1;
// #    endif
//             buflen = (withoptional
//                           ? encoding_ctx->encoding_impl->crypto_secretkeybytes
//                           : encoding_ctx->encoding_impl
//                                 ->crypto_secretkeybytes_nooptional);
//             buf = OPENSSL_secure_zalloc(buflen);
//             if (buf == NULL) {
//                 ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//                 return -1;
//             }

//             ret = qsc_encode(encoding_ctx->encoding_ctx,
//                              encoding_ctx->encoding_impl,
//                              oqsxkey->comp_pubkey[oqsxkey->numkeys - 1], 0,
//                              oqsxkey->privkey, &buf, withoptional);
//             if (ret != QSC_ENC_OK)
//                 return -1;
//         } else {
// #endif
// #ifdef NOPUBKEY_IN_PRIVKEY
//             buflen = privkeylen;
//             buf = OPENSSL_secure_malloc(buflen);
//             if (buf == NULL) {
//                 ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//                 return -1;
//             }
//             OQS_ENC_PRINTF2("OQS ENC provider: saving privkey of length %d\n",
//                             buflen);
//             memcpy(buf, oqsxkey->privkey, privkeylen);
// #else
//         buflen = privkeylen + oqsx_key_get_oqs_public_key_len(oqsxkey);
//         buf = OPENSSL_secure_malloc(buflen);
//         if (buf == NULL) {
//             ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//             return -1;
//         }
//         OQS_ENC_PRINTF2("OQS ENC provider: saving priv+pubkey of length %d\n",
//                         buflen);
//         memcpy(buf, oqsxkey->privkey, privkeylen);
//         memcpy(buf + privkeylen, oqsxkey->comp_pubkey[oqsxkey->numkeys - 1],
//                oqsx_key_get_oqs_public_key_len(oqsxkey));
// #endif
// #ifdef USE_ENCODING_LIB
//         }
// #endif

//         oct.data = buf;
//         oct.length = buflen;
//         // more logical:
//         // oct.data = oqsxkey->privkey;
//         // oct.length = oqsxkey->privkeylen;
//         oct.flags = 0;

//         keybloblen = i2d_ASN1_OCTET_STRING(&oct, pder);
//         if (keybloblen < 0) {
//             ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
//             keybloblen = 0; // signal error
//         }
//         OPENSSL_secure_clear_free(buf, buflen);
//     } else {
//         ASN1_TYPE **aType
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_TYPE *));
//         ASN1_OCTET_STRING **aString
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(ASN1_OCTET_STRING *));
//         unsigned char **temp
//             = OPENSSL_malloc(oqsxkey->numkeys * sizeof(unsigned char *));
//         size_t *templen = OPENSSL_malloc(oqsxkey->numkeys * sizeof(size_t));
//         PKCS8_PRIV_KEY_INFO *p8inf_internal = NULL;
//         int i;

//         if ((sk = sk_ASN1_TYPE_new_null()) == NULL)
//             return -1;

//         for (i = 0; i < oqsxkey->numkeys; i++) {
//             aType[i] = ASN1_TYPE_new();
//             aString[i] = ASN1_OCTET_STRING_new();
//             p8inf_internal = PKCS8_PRIV_KEY_INFO_new();
//             temp[i] = NULL;
//             int nid, version;
//             void *pval;

//             if ((name = get_cmpname(OBJ_sn2nid(oqsxkey->tls_name), i))
//                 == NULL) {
//                 for (int j = 0; j <= i; j++) {
//                     OPENSSL_cleanse(aString[j]->data, aString[j]->length);
//                     ASN1_OCTET_STRING_free(aString[j]);
//                     OPENSSL_cleanse(aType[j]->value.sequence->data,
//                                     aType[j]->value.sequence->length);
//                     if (j < i)
//                         OPENSSL_clear_free(temp[j], templen[j]);
//                 }

//                 if (sk_ASN1_TYPE_num(sk) != -1)
//                     sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//                 else
//                     ASN1_TYPE_free(aType[i]);

//                 OPENSSL_free(aType);
//                 OPENSSL_free(aString);
//                 OPENSSL_free(temp);
//                 OPENSSL_free(templen);
//                 PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
//                 OPENSSL_free(name);
//                 return -1;
//             }

//             if (get_oqsname_fromtls(name) == 0) {

//                 nid = oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
//                           ->keytype;
//                 if (nid == EVP_PKEY_RSA) { // get the RSA real key size
//                     unsigned char *enc_len
//                         = OPENSSL_strndup(oqsxkey->comp_privkey[i], 4);
//                     OPENSSL_cleanse(enc_len, 2);
//                     DECODE_UINT32(buflen, enc_len);
//                     buflen += 4;
//                     OPENSSL_free(enc_len);
//                     if (buflen > oqsxkey->privkeylen_cmp[i]) {
//                         for (int j = 0; j <= i; j++) {
//                             OPENSSL_cleanse(aString[j]->data,
//                                             aString[j]->length);
//                             ASN1_OCTET_STRING_free(aString[j]);
//                             OPENSSL_cleanse(aType[j]->value.sequence->data,
//                                             aType[j]->value.sequence->length);
//                             if (j < i)
//                                 OPENSSL_clear_free(temp[j], templen[j]);
//                         }

//                         if (sk_ASN1_TYPE_num(sk) != -1)
//                             sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//                         else
//                             ASN1_TYPE_free(aType[i]);

//                         OPENSSL_free(aType);
//                         OPENSSL_free(aString);
//                         OPENSSL_free(temp);
//                         OPENSSL_free(templen);
//                         PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
//                         OPENSSL_free(name);
//                         return -1;
//                     }
//                 } else
//                     buflen = oqsxkey->privkeylen_cmp[i];
//             } else {
//                 nid = OBJ_sn2nid(name);
//                 buflen = oqsxkey->privkeylen_cmp[i] + oqsxkey->pubkeylen_cmp[i];
//             }

//             buf = OPENSSL_secure_malloc(buflen);
//             if (get_oqsname_fromtls(name)
//                 != 0) { // include pubkey in privkey for PQC
//                 memcpy(buf, oqsxkey->comp_privkey[i],
//                        oqsxkey->privkeylen_cmp[i]);
//                 memcpy(buf + oqsxkey->privkeylen_cmp[i],
//                        oqsxkey->comp_pubkey[i], oqsxkey->pubkeylen_cmp[i]);
//             } else {
//                 memcpy(buf, oqsxkey->comp_privkey[i], buflen);
//             }

//             if (nid == EVP_PKEY_EC) {
//                 version = V_ASN1_OBJECT;
//                 pval = OBJ_nid2obj(
//                     oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->nid);
//             } else {
//                 version = V_ASN1_UNDEF;
//                 pval = NULL;
//             }
//             if (!PKCS8_pkey_set0(p8inf_internal, OBJ_nid2obj(nid), 0, version,
//                                  pval, buf, buflen)) {
//                 for (int j = 0; j <= i; j++) {
//                     OPENSSL_cleanse(aString[j]->data, aString[j]->length);
//                     ASN1_OCTET_STRING_free(aString[j]);
//                     OPENSSL_cleanse(aType[j]->value.sequence->data,
//                                     aType[j]->value.sequence->length);
//                     OPENSSL_clear_free(temp[j], templen[j]);
//                 }

//                 sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//                 OPENSSL_free(name);
//                 OPENSSL_free(aType);
//                 OPENSSL_free(aString);
//                 OPENSSL_free(temp);
//                 OPENSSL_free(templen);
//                 OPENSSL_cleanse(buf, buflen);
//                 PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
//                 return -1;
//             }

//             templen[i] = i2d_PKCS8_PRIV_KEY_INFO(p8inf_internal, &temp[i]);
//             ASN1_STRING_set(aString[i], temp[i], templen[i]);
//             ASN1_TYPE_set1(aType[i], V_ASN1_SEQUENCE, aString[i]);

//             if (!sk_ASN1_TYPE_push(sk, aType[i])) {
//                 for (int j = 0; j <= i; j++) {
//                     OPENSSL_cleanse(aString[j]->data, aString[j]->length);
//                     ASN1_OCTET_STRING_free(aString[j]);
//                     OPENSSL_cleanse(aType[j]->value.sequence->data,
//                                     aType[j]->value.sequence->length);
//                     OPENSSL_clear_free(temp[j], templen[j]);
//                 }

//                 sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//                 OPENSSL_free(name);
//                 OPENSSL_free(aType);
//                 OPENSSL_free(aString);
//                 OPENSSL_free(temp);
//                 OPENSSL_free(templen);
//                 OPENSSL_cleanse(buf, buflen);
//                 PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
//                 return -1;
//             }
//             OPENSSL_free(name);

//             OPENSSL_cleanse(buf, buflen);
//             PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
//         }
//         keybloblen = i2d_ASN1_SEQUENCE_ANY(sk, pder);

//         for (i = 0; i < oqsxkey->numkeys; i++) {
//             OPENSSL_cleanse(aString[i]->data, aString[i]->length);
//             ASN1_OCTET_STRING_free(aString[i]);
//             OPENSSL_cleanse(aType[i]->value.sequence->data,
//                             aType[i]->value.sequence->length);
//             OPENSSL_clear_free(temp[i], templen[i]);
//         }

//         sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
//         OPENSSL_free(aType);
//         OPENSSL_free(aString);
//         OPENSSL_free(temp);
//         OPENSSL_free(templen);
//     }
//     return keybloblen;
// }

// #define oqsx_epki_priv_to_der oqsx_pki_priv_to_der

// /*
//  * OQSX only has PKCS#8 / SubjectPublicKeyInfo
//  * representation, so we don't define
//  * oqsx_type_specific_[priv,pub,params]_to_der.
//  */

// #define oqsx_check_key_type NULL

// // OQS provider uses NIDs generated at load time as EVP_type identifiers
// // so initially this must be 0 and set to a real value by OBJ_sn2nid later
// ///// OQS_TEMPLATE_FRAGMENT_ENCODER_DEFINES_START
// #define frodo640aes_evp_type   0
// #define frodo640aes_input_type "frodo640aes"
// #define frodo640aes_pem_type   "frodo640aes"