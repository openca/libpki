

#ifndef _LIBPKI_PQC_AMETH_LOCAL_H
#include "pqc_pkey_meth.h"
#endif

// =======================
// EVP PKEY Meth Functions
// =======================

int pkey_oqs_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    // nothing specific needed, but EVP depends on its presence
    return 1;
}

int pkey_oqs_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    OQS_KEY *oqs_key = NULL;
    int id = ctx->pmeth->pkey_id;
    int is_hybrid = is_oqs_hybrid_alg(id);
    int classical_id = 0;
    EVP_PKEY_CTX *param_ctx = NULL, *keygen_ctx = NULL;
    EVP_PKEY *param_pkey = NULL;
    const int rsa_size = 3072;
    int rv = 0;

    if (!oqs_key_init(&oqs_key, id, 1)) {
      ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
      goto end;
    }

    /* generate the classical key pair */
    if (is_hybrid) {
      classical_id = get_classical_nid(id);
      if (is_EC_nid(classical_id)) {
	if(!(param_ctx = EVP_PKEY_CTX_new_id(NID_X9_62_id_ecPublicKey, NULL)) ||
	   !EVP_PKEY_paramgen_init(param_ctx) ||
	   !EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, classical_id) ||
	   !EVP_PKEY_paramgen(param_ctx, &param_pkey)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
	}
      }
      /* Generate key */
      if (param_pkey != NULL) {
	keygen_ctx = EVP_PKEY_CTX_new( param_pkey, NULL );
	EVP_PKEY_free(param_pkey);
      } else {
	keygen_ctx = EVP_PKEY_CTX_new_id( classical_id, NULL );
      }
      if (!keygen_ctx ||
	  !EVP_PKEY_keygen_init(keygen_ctx)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, EC_R_KEY_INIT_FAILED);
	  goto end;
      };

      if ( classical_id == EVP_PKEY_RSA ) {
	if(!EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, rsa_size)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
	}
      }
      if(!EVP_PKEY_keygen(keygen_ctx, &oqs_key->classical_pkey)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
      }
      EVP_PKEY_CTX_free(keygen_ctx);
      keygen_ctx = NULL;
    }

    /* generate PQC key pair */
    if (OQS_SIG_keypair(oqs_key->s, oqs_key->pubkey, oqs_key->privkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_KEYGEN, EC_R_KEYGEN_FAILED);
      goto end;
    }

    EVP_PKEY_assign(pkey, id, oqs_key);
    rv = 1; /* success */

 end:
    if (keygen_ctx) EVP_PKEY_CTX_free(keygen_ctx);
    if (oqs_key && rv == 0) oqs_pkey_ctx_free(oqs_key);
    return rv;
}

int pkey_oqs_keygen_init() {
  return 1;
}

int pkey_oqs_sign_init(EVP_PKEY_CTX *ctx) {
   return 1;
}

int pkey_oqs_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
   printf("oqs sign without digest auto fail\n");
   return 0;
}

int pkey_oqs_verify_init(EVP_PKEY_CTX *ctx) {
   return 1;
}

int pkey_oqs_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen) {
	printf("oqs verify auto fail without digest\n");
	return 0;
}


int pkey_oqs_signctx_init (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, oqs_int_update);

    return 1;
}

int pkey_oqs_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) {
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(mctx)->pkey->pkey.ptr;
    unsigned char* tbs = NULL;
    unsigned int tbslen = 0;

    if (sig != NULL) {
      // support any digest requested:
      tbslen = (unsigned int) EVP_MD_CTX_size(oqs_key->digest);

      if (oqs_key->digest == NULL) { // error; ctrl not called?
        return 0;
      }

      if((tbs = (unsigned char *)OPENSSL_malloc((size_t) tbslen)) == NULL) {
        return 0;
      }

      if(EVP_DigestFinal(oqs_key->digest, tbs, &tbslen) <= 0) {
        return 0;
      }
    }

    int ret = pkey_oqs_digestsign(mctx, sig, siglen, tbs, tbslen);
    if (sig != NULL) { // cleanup only if it's not the empty setup call
       OPENSSL_free(tbs);
       EVP_MD_CTX_destroy(oqs_key->digest);
       oqs_key->digest = NULL;
    }
    if (ret <= 0) {
    }
    else {
       EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE); // don't go around again...
    }

   return ret;
}


int pkey_oqs_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

   EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
   EVP_MD_CTX_set_update_fn(mctx, oqs_int_update);
   EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE); // don't go around again...
   return 1;
}

int pkey_oqs_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx) {
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(mctx)->pkey->pkey.ptr;
    unsigned char* tbs = NULL;
    unsigned int tbslen = 0;

    if (sig != NULL) {
        // support any digest requested:
        tbslen = (unsigned int) EVP_MD_CTX_size(oqs_key->digest);

        if (oqs_key->digest == NULL) { // error; ctrl not called?
                return 0;
        }

        if((tbs = (unsigned char *)OPENSSL_malloc(tbslen)) == NULL) {
                return 0;
        }

        if(EVP_DigestFinal(oqs_key->digest, tbs, &tbslen) <= 0) {
                return 0;
        }

    }

    int ret = pkey_oqs_digestverify(mctx, sig, (size_t) siglen, tbs, tbslen); 
    if (sig != NULL) { // cleanup only if it's not the empty setup call
       OPENSSL_free(tbs);
       EVP_MD_CTX_destroy(oqs_key->digest);
       oqs_key->digest = NULL;
    }
    if (ret <= 0) {
    }
    else {
       EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE); // don't go around again...
    }

   return ret;
}


int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_PKEY_CTX_get0_pkey(ctx)->pkey.ptr;

    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* NULL allowed as digest */
        if (p2 == NULL) {
            return 1;
	}

	if (oqs_key->digest == NULL) { // allocate fitting digest engine
        	if ((oqs_key->digest = EVP_MD_CTX_create()) == NULL) {
           		return 0;
		}

	        if (EVP_DigestInit_ex(oqs_key->digest, EVP_get_digestbynid(*(int*)p2), NULL) <= 0) {
           		return 0;
        	}
		
	}
	return 1; // accept any digest


    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;

    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;
    }
    ECerr(EC_F_PKEY_OQS_CTRL, ERR_R_FATAL);
    return -2;
}

int pkey_oqs_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    EVP_PKEY_CTX *classical_ctx_sign = NULL;

    int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    int classical_id = 0;
    size_t max_sig_len = oqs_key->s->length_signature;
    size_t classical_sig_len = 0, oqs_sig_len = 0;
    size_t actual_classical_sig_len = 0;
    size_t index = 0;
    int rv = 0;

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey || (is_hybrid && !oqs_key->classical_pkey)) {
      ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_NO_PRIVATE_KEY);
      return rv;
    }
    if (is_hybrid) {
      classical_id = get_classical_nid(oqs_key->nid);
      actual_classical_sig_len = (size_t) get_classical_sig_len(classical_id);
      max_sig_len += (SIZE_OF_UINT32 + actual_classical_sig_len);
    }

    if (sig == NULL) {
      /* we only return the sig len */
      *siglen = max_sig_len;
      return 1;
    }
    if (*siglen < max_sig_len) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_BUFFER_LENGTH_WRONG);
        return rv;
    }

    if (is_hybrid) {
      const EVP_MD *classical_md;
      int digest_len;
      unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

      if ((classical_ctx_sign = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL ||
	  EVP_PKEY_sign_init(classical_ctx_sign) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
        goto end;
      }
      if (classical_id == EVP_PKEY_RSA) {
	if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign, RSA_PKCS1_PADDING) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
        goto end;
	}
      }

      /* classical schemes can't sign arbitrarily large data; we hash it first */
      switch (oqs_key->s->claimed_nist_level) {
      case 1:
	classical_md = EVP_sha256();
	digest_len = SHA256_DIGEST_LENGTH;
	SHA256(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 2:
      case 3:
	classical_md = EVP_sha384();
	digest_len = SHA384_DIGEST_LENGTH;
	SHA384(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 4:
      case 5:
      default:
	classical_md = EVP_sha512();
	digest_len = SHA512_DIGEST_LENGTH;
	SHA512(tbs, tbslen, (unsigned char*) &digest);
	break;
      }
      if (EVP_PKEY_CTX_set_signature_md(classical_ctx_sign, classical_md) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
	goto end;
      }
      if (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32, &actual_classical_sig_len, digest, (size_t)digest_len) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_SIGNING_FAILED);
        goto end;
      }
      if (actual_classical_sig_len > (size_t) get_classical_sig_len(classical_id)) {
	/* sig is bigger than expected! */
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_BUFFER_LENGTH_WRONG);
        goto end;
      }
      ENCODE_UINT32(sig, actual_classical_sig_len);
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
    }

    if (OQS_SIG_sign(oqs_key->s, sig + index, &oqs_sig_len, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_SIGNING_FAILED);
      return 0;
    }
    *siglen = classical_sig_len + oqs_sig_len;

    rv = 1; /* success */

 end:
    if (classical_ctx_sign) {
      EVP_PKEY_CTX_free(classical_ctx_sign);
    }
    return rv;
}

int pkey_oqs_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    int classical_id = 0;
    size_t classical_sig_len = 0;
    size_t index = 0;

    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || (is_hybrid && !oqs_key->classical_pkey) ||
	sig == NULL || tbs == NULL) {
      ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_WRONG_PARAMETERS);
      return 0;
    }

    if (is_hybrid) {
      classical_id = get_classical_nid(oqs_key->nid);
    }

    if (is_hybrid) {
      EVP_PKEY_CTX *ctx_verify = NULL;
      const EVP_MD *classical_md;
      size_t actual_classical_sig_len = 0;
      int digest_len;
      unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

      if ((ctx_verify = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL ||
	  EVP_PKEY_verify_init(ctx_verify) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	EVP_PKEY_CTX_free(ctx_verify);
	return 0;
      }
      if (classical_id == EVP_PKEY_RSA) {
	if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING) <= 0) {
	  ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	  EVP_PKEY_CTX_free(ctx_verify);
	  return 0;
	}
      }
      DECODE_UINT32(actual_classical_sig_len, sig);
      /* classical schemes can't sign arbitrarily large data; we hash it first */
      switch (oqs_key->s->claimed_nist_level) {
      case 1:
	classical_md = EVP_sha256();
	digest_len = SHA256_DIGEST_LENGTH;
	SHA256(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 2:
      case 3:
	classical_md = EVP_sha384();
	digest_len = SHA384_DIGEST_LENGTH;
	SHA384(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 4:
      case 5:
      default:
	classical_md = EVP_sha512();
	digest_len = SHA512_DIGEST_LENGTH;
	SHA512(tbs, tbslen, (unsigned char*) &digest);
	break;
      }
      if (EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	return 0;
      }
      if (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32, actual_classical_sig_len, digest, (size_t)digest_len) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_VERIFICATION_FAILED);
	return 0;
      }
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
      EVP_PKEY_CTX_free(ctx_verify);
    }

    if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig + index, siglen - classical_sig_len, oqs_key->pubkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_VERIFICATION_FAILED);
      return 0;
    }

    return 1;
}

int pkey_oqs_digestcustom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
   return 1;
}

// ///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_EVP_METHS_START
// DEFINE_OQS_EVP_METHODS(DILITHIUMX, NID_dilithium3, "dilithiumX", "OpenSSL DilithiumX algorithm")
// DEFINE_OQS_EVP_METHODS(dilithium3, NID_dilithium3, "dilithium3", "OpenSSL Dilithium3 algorithm")
// DEFINE_OQS_EVP_METHODS(dilithium5, NID_dilithium5, "dilithium5", "OpenSSL Dilithium5 algorithm")
// DEFINE_OQS_EVP_METHODS(dilithium2_aes, NID_dilithium2_aes, "dilithium2_aes", "OpenSSL Dilithium2_AES algorithm")
// DEFINE_OQS_EVP_METHODS(dilithium3_aes, NID_dilithium3_aes, "dilithium3_aes", "OpenSSL Dilithium3_AES algorithm")
// DEFINE_OQS_EVP_METHODS(dilithium5_aes, NID_dilithium5_aes, "dilithium5_aes", "OpenSSL Dilithium5_AES algorithm")
// DEFINE_OQS_EVP_METHODS(falcon512, NID_falcon512, "falcon512", "OpenSSL Falcon-512 algorithm")
// DEFINE_OQS_EVP_METHODS(falcon1024, NID_falcon1024, "falcon1024", "OpenSSL Falcon-1024 algorithm")
// DEFINE_OQS_EVP_METHODS(picnic3l1, NID_picnic3l1, "picnic3l1", "OpenSSL Picnic3 L1 algorithm")
// DEFINE_OQS_EVP_METHODS(rainbowVclassic, NID_rainbowVclassic, "rainbowVclassic", "OpenSSL Rainbow-V-Classic algorithm")
// DEFINE_OQS_EVP_METHODS(sphincsharaka128frobust, NID_sphincsharaka128frobust, "sphincsharaka128frobust", "OpenSSL SPHINCS+-Haraka-128f-robust algorithm")
// DEFINE_OQS_EVP_METHODS(sphincssha256128frobust, NID_sphincssha256128frobust, "sphincssha256128frobust", "OpenSSL SPHINCS+-SHA256-128f-robust algorithm")
// DEFINE_OQS_EVP_METHODS(sphincsshake256128frobust, NID_sphincsshake256128frobust, "sphincsshake256128frobust", "OpenSSL SPHINCS+-SHAKE256-128f-robust algorithm")
// ///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_EVP_METHS_END
