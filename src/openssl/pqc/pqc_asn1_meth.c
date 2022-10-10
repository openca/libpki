

#ifndef _LIBPKI_PQC_AMETH_LOCAL_H
#include "pqc_asn1_meth.h"
#endif

// ===========
// AMETH Tools
// ===========

int oqs_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    unsigned char *penc;
    size_t pubkey_len = 0, index = 0;
    // size_t max_classical_pubkey_len = 0, classical_pubkey_len = 0;
    if (!oqs_key || !oqs_key->s || !oqs_key->pubkey ) {
      ECerr(EC_F_OQS_PUB_ENCODE, EC_R_KEY_NOT_SET);
      return 0;
    }
    // int is_hybrid = (oqs_key->classical_pkey != NULL);

    /* determine the length of the key */
    pubkey_len = oqs_key->s->length_public_key;
    // if (is_hybrid) {
    //   max_classical_pubkey_len = (size_t) get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(oqs_key->nid));
    //   pubkey_len += (SIZE_OF_UINT32 + max_classical_pubkey_len);
    // }
    penc = OPENSSL_malloc(pubkey_len);
    if (penc == NULL) {
      ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
      return 0;
    }

  //   /* if hybrid, encode classical public key */
  //   if (is_hybrid) {
  //     unsigned char *classical_pubkey = penc + SIZE_OF_UINT32; /* i2d moves target pointer, so we copy into a temp var (leaving space for key len) */
  //     int actual_classical_pubkey_len = i2d_PublicKey(oqs_key->classical_pkey, &classical_pubkey);
  //     if (actual_classical_pubkey_len < 0 || actual_classical_pubkey_len > max_classical_pubkey_len) {
	// /* something went wrong, or we didn't allocate enough space */
	// OPENSSL_free(penc);
  //       ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_FATAL);
  //       return 0;
  //     }
  //     ENCODE_UINT32(penc, actual_classical_pubkey_len);
  //     classical_pubkey_len = SIZE_OF_UINT32 + (size_t) actual_classical_pubkey_len;
  //     index += classical_pubkey_len;
  //   }

    /* encode the pqc public key */
    memcpy(penc + index, oqs_key->pubkey, oqs_key->s->length_public_key);

    /* recalculate pub key len using actual classical key len */
    pubkey_len = /* classical_pubkey_len + */ oqs_key->s->length_public_key;

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                                V_ASN1_UNDEF, NULL, penc, (int) pubkey_len)) {
        OPENSSL_free(penc);
        ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen, max_pubkey_len;
    X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;
    // int is_hybrid = is_oqs_hybrid_alg(id);
    size_t index = 0;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        return 0;
    }
    if (p == NULL) {
      /* pklen is checked below, after we instantiate the oqs_key to learn the max len */
      ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
      return 0;
    }

    if (palg != NULL) {
      int ptype;

      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_OQS_PUB_DECODE, EC_R_PARAMETERS_MUST_BE_ABSENT);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 0)) {
      ECerr(EC_F_OQS_PUB_DECODE, EC_R_KEY_INIT_FAILED);
      return 0;
    }

    max_pubkey_len = (int) oqs_key->s->length_public_key;
    // if (is_hybrid) {
    //   max_pubkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(id)));
    // }

    if (pklen > max_pubkey_len) {
      ECerr(EC_F_OQS_PUB_DECODE, EC_R_WRONG_LENGTH);
      goto err;
    }

    // /* if hybrid, decode classical public key */
    // if (is_hybrid) {
    //   int classical_id = get_classical_nid(id);
    //   uint32_t actual_classical_pubkey_len;
    //   DECODE_UINT32(actual_classical_pubkey_len, p);
    //   if (is_EC_nid(classical_id)) {
    //     if (!decode_EC_key(KEY_TYPE_PUBLIC, classical_id, p + SIZE_OF_UINT32, (int) actual_classical_pubkey_len, oqs_key)) {
    //       ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
    //       goto err;
    //     }
    //   } else {
    //     const unsigned char* pubkey_temp = p + SIZE_OF_UINT32;
    //     oqs_key->classical_pkey = d2i_PublicKey(classical_id, &oqs_key->classical_pkey, &pubkey_temp, actual_classical_pubkey_len);
    //     if (oqs_key->classical_pkey == NULL) {
    //       ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
    //       goto err;
    //     }
    //   }

    //   index += (SIZE_OF_UINT32 + actual_classical_pubkey_len);
    // }
    /* decode PQC public key */
    memcpy(oqs_key->pubkey, (char *) (p + index), oqs_key->s->length_public_key);

    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const OQS_KEY *akey = (OQS_KEY*) a->pkey.ptr;
    const OQS_KEY *bkey = (OQS_KEY*) b->pkey.ptr;
    if (akey == NULL || bkey == NULL)
        return -2;

    // /* compare hybrid classical key if present */
    // if (akey->classical_pkey != NULL) {
    //   if (bkey->classical_pkey == NULL) {
	  //     return 0; /* both should be hybrid or not */
    //   }
    //   if (!EVP_PKEY_cmp(akey->classical_pkey, bkey->classical_pkey)) {
	  //     return 0;
    //   }
    // }

    /* compare PQC key */
    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, akey->s->length_public_key) == 0;
}

int oqs_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen, max_privkey_len;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;
    // int is_hybrid = is_oqs_hybrid_alg(id);
    int index = 0;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    /* oct contains first the private key, then the public key */
    if (palg != NULL) {
      int ptype;

      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 1)) {
      ECerr(EC_F_OQS_PRIV_DECODE, EC_R_KEY_INIT_FAILED);
      return 0;
    }

    max_privkey_len = (int) (oqs_key->s->length_secret_key + oqs_key->s->length_public_key);
    // if (is_hybrid) {
    //   max_privkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PRIVATE, get_classical_nid(oqs_key->nid)));
    // }

    if (plen > max_privkey_len) {
      ECerr(EC_F_OQS_PRIV_DECODE, EC_R_KEY_LENGTH_WRONG);
      goto err;
    }

    // /* if hybrid, decode classical private key */
    // if (is_hybrid) {
    //   int classical_id = get_classical_nid(id);
    //   size_t actual_classical_privkey_len;
    //   DECODE_UINT32(actual_classical_privkey_len, p);
    //   if (is_EC_nid(classical_id)) {
    //     if (!decode_EC_key(KEY_TYPE_PRIVATE, classical_id, p + SIZE_OF_UINT32, (int)actual_classical_privkey_len, oqs_key)) {
    //       ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
    //       goto err;
    //     }
    //   } else {
    //     const unsigned char* privkey_temp = p + SIZE_OF_UINT32;
    //     oqs_key->classical_pkey = d2i_PrivateKey(classical_id, &oqs_key->classical_pkey, &privkey_temp, (long) actual_classical_privkey_len);
    //     if (oqs_key->classical_pkey == NULL) {
    //       ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
    //       goto err;
    //     }
    //   }
    //   index += (int)(SIZE_OF_UINT32 + actual_classical_privkey_len);
    // }

    /* decode private key */
    memcpy(oqs_key->privkey, (char *)(p + index), oqs_key->s->length_secret_key);
    index += (int)oqs_key->s->length_secret_key;

    /* decode public key */
    memcpy(oqs_key->pubkey, p + index, oqs_key->s->length_public_key);

    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, oqs_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    uint32_t buflen;
    int penclen, index = 0;
    int rv = 0;

    // uint32_t max_classical_privkey_len = 0, classical_privkey_len = 0;

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey ) {
      ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
      return rv;
    }
    // int is_hybrid = (oqs_key->classical_pkey != NULL);

    /* determine the length of key */
    buflen = (uint32_t) (oqs_key->s->length_secret_key + oqs_key->s->length_public_key);
    // if (is_hybrid) {
    //   max_classical_privkey_len = (uint32_t) get_classical_key_len(KEY_TYPE_PRIVATE, get_classical_nid(oqs_key->nid));
    //   buflen += (SIZE_OF_UINT32 + max_classical_privkey_len);
    // }
    buf = OPENSSL_secure_malloc((size_t)buflen);
    if (buf == NULL) {
      ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
      return rv;
    }

    // /* if hybrid, encode classical private key */
    // if (is_hybrid) {
    //   unsigned char *classical_privkey = buf + SIZE_OF_UINT32; /* i2d moves the target pointer, so we copy into a temp var (leaving space for key len) */
    //   int actual_classical_privkey_len = i2d_PrivateKey(oqs_key->classical_pkey, &classical_privkey);
    //   if (actual_classical_privkey_len < 0 || (uint32_t) actual_classical_privkey_len > max_classical_privkey_len) {
    //     /* something went wrong, or we didn't allocate enough space */
    //     OPENSSL_free(buf);
    //     ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
    //     goto end;
    //   }
    //   ENCODE_UINT32(buf, actual_classical_privkey_len);
    //   classical_privkey_len = SIZE_OF_UINT32 + (uint32_t) actual_classical_privkey_len;
    //   index += (int) classical_privkey_len;
    // }

    /* encode the pqc private key */
    memcpy(buf + index, oqs_key->privkey, oqs_key->s->length_secret_key);
    index += (int)oqs_key->s->length_secret_key;

    /* encode the pqc public key */
    memcpy(buf + index, oqs_key->pubkey, oqs_key->s->length_public_key);

    /* recalculate pub key len using actual classical len */
    buflen = /* classical_privkey_len + */ (uint32_t) (oqs_key->s->length_secret_key + oqs_key->s->length_public_key);

    oct.data = buf;
    oct.length = (int) buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
        goto end;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_secure_clear_free(buf, (size_t) buflen);
        OPENSSL_clear_free(penc, (size_t)penclen);
        ECerr(EC_F_OQS_PRIV_ENCODE, EC_R_SETTING_PARAMETERS_FAILED);
        goto end;
    }
    rv = 1; /* success */

 end:
    OPENSSL_secure_clear_free(buf, (size_t) buflen);
    return rv;
}

int oqs_size(const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    if (oqs_key == NULL || oqs_key->s == NULL) {
        ECerr(EC_F_OQS_SIZE, EC_R_NOT_INITIALIZED);
        return 0;
    }
    size_t sig_len = oqs_key->s->length_signature;
    // if (is_oqs_hybrid_alg(oqs_key->nid)) {
    //   int classical_nid = get_classical_nid(oqs_key->nid);
    //   sig_len += (SIZE_OF_UINT32 + (size_t)get_classical_sig_len(classical_nid));
    // }
    return (int)sig_len;
}

int oqs_bits(const EVP_PKEY *pkey)
{
  OQS_KEY* oqs_key = (OQS_KEY*) pkey->pkey.ptr;
  size_t pubkey_len = oqs_key->s->length_public_key;
  // if (is_oqs_hybrid_alg(oqs_key->nid)) {
  //   pubkey_len += (SIZE_OF_UINT32 + (size_t) get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(oqs_key->nid)));
  // }
  /* return size in bits */
  return (int) (CHAR_BIT * pubkey_len);
}

int oqs_security_bits(const EVP_PKEY *pkey)
{
    return ((OQS_KEY*) pkey->pkey.ptr)->security_bits; /* already accounts for hybrid */
}

void oqs_free(EVP_PKEY *pkey)
{
    oqs_pkey_ctx_free((OQS_KEY*) pkey->pkey.ptr);
}

/* "parameters" are always equal */
int oqs_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}

int oqs_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx, oqs_key_type_t keytype)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    // int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    /* alg name to print, just keep the oqs part for hybrid */
    // const char *nm = OBJ_nid2ln(is_hybrid ? get_oqs_nid(oqs_key->nid) : pkey->ameth->pkey_id);
    const char *nm = OBJ_nid2ln(pkey->ameth->pkey_id);

    if (keytype == KEY_TYPE_PRIVATE) {
        if (oqs_key == NULL || oqs_key->privkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, oqs_key->privkey, oqs_key->s->length_secret_key,
                           indent + 4) == 0)
            return 0;
    } else {
        if (oqs_key == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }

        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;

    if (ASN1_buf_print(bp, oqs_key->pubkey, oqs_key->s->length_public_key,
                       indent + 4) == 0)
        return 0;
    return 1;
}

int oqs_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PRIVATE);
}

int oqs_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PUBLIC);
}

int oqs_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *str,
                           EVP_PKEY *pkey)
{
    const ASN1_OBJECT *obj;
    int ptype;
    int nid;

    /* Sanity check: make sure it is an OQS scheme with absent parameters */
    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    nid = OBJ_obj2nid(obj);
    if (
    (
///// OQS_TEMPLATE_FRAGMENT_CHECK_IF_KNOWN_NID_START
        nid != NID_dilithium2 &&
        nid != NID_p256_dilithium2 &&
        nid != NID_rsa3072_dilithium2 &&
        nid != NID_dilithium3 &&
        nid != NID_p384_dilithium3 &&
        nid != NID_dilithium5 &&
        nid != NID_p521_dilithium5 &&
        nid != NID_dilithium2_aes &&
        nid != NID_p256_dilithium2_aes &&
        nid != NID_rsa3072_dilithium2_aes &&
        nid != NID_dilithium3_aes &&
        nid != NID_p384_dilithium3_aes &&
        nid != NID_dilithium5_aes &&
        nid != NID_p521_dilithium5_aes &&
        nid != NID_falcon512 &&
        nid != NID_p256_falcon512 &&
        nid != NID_rsa3072_falcon512 &&
        nid != NID_falcon1024 &&
        nid != NID_p521_falcon1024 &&
        nid != NID_picnicl1full &&
        nid != NID_p256_picnicl1full &&
        nid != NID_rsa3072_picnicl1full &&
        nid != NID_picnic3l1 &&
        nid != NID_p256_picnic3l1 &&
        nid != NID_rsa3072_picnic3l1 &&
        nid != NID_rainbowVclassic &&
        nid != NID_p521_rainbowVclassic &&
        nid != NID_sphincsharaka128frobust &&
        nid != NID_p256_sphincsharaka128frobust &&
        nid != NID_rsa3072_sphincsharaka128frobust &&
        nid != NID_sphincssha256128frobust &&
        nid != NID_p256_sphincssha256128frobust &&
        nid != NID_rsa3072_sphincssha256128frobust &&
        nid != NID_sphincsshake256128frobust &&
        nid != NID_p256_sphincsshake256128frobust &&
        nid != NID_rsa3072_sphincsshake256128frobust &&
        1 /* This is just to faciliate templating. */
///// OQS_TEMPLATE_FRAGMENT_CHECK_IF_KNOWN_NID_END
        && nid != OBJ_sn2nid("DilithiumX") 
    ) || ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_OQS_ITEM_VERIFY, EC_R_UNKNOWN_NID);
        return 0;
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
        return 0;

    return 2;
}

int oqs_ameth_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2) {

   switch (op) {

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha512;
        return 1;
        break;

#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL) {
                return -1;
	          }
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef) {
                return -1;
            }
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey))) {
                return -1;
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;
        break;
#endif

   }
   ECerr(EC_F_PKEY_OQS_CTRL, ERR_R_FATAL);
   return 0;
}

// ==================================== PKEY ======================================

// DEFINE_OQS_EVP_METHODS(sphincsharaka128frobust, NID_sphincsharaka128frobust, "sphincsharaka128frobust", "OpenSSL SPHINCS+-Haraka-128f-robust algorithm")
// DEFINE_OQS_EVP_METHODS(sphincssha256128frobust, NID_sphincssha256128frobust, "sphincssha256128frobust", "OpenSSL SPHINCS+-SHA256-128f-robust algorithm")
// DEFINE_OQS_EVP_METHODS(sphincsshake256128frobust, NID_sphincsshake256128frobust, "sphincsshake256128frobust", "OpenSSL SPHINCS+-SHAKE256-128f-robust algorithm")
// ///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_EVP_METHS_END
