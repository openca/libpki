// Local Include
#include "pqc_tools.h"

// =========
// Functions
// =========

int oqssl_sig_nids_list[] = {
///// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_NIDS_START
        NID_dilithium2,
        NID_p256_dilithium2,
        NID_rsa3072_dilithium2,
        NID_dilithium3,
        NID_p384_dilithium3,
        NID_dilithium5,
        NID_p521_dilithium5,
        NID_dilithium2_aes,
        NID_p256_dilithium2_aes,
        NID_rsa3072_dilithium2_aes,
        NID_dilithium3_aes,
        NID_p384_dilithium3_aes,
        NID_dilithium5_aes,
        NID_p521_dilithium5_aes,
        NID_falcon512,
        NID_p256_falcon512,
        NID_rsa3072_falcon512,
        NID_falcon1024,
        NID_p521_falcon1024,
        NID_picnicl1full,
        NID_p256_picnicl1full,
        NID_rsa3072_picnicl1full,
        NID_picnic3l1,
        NID_p256_picnic3l1,
        NID_rsa3072_picnic3l1,
        NID_rainbowVclassic,
        NID_p521_rainbowVclassic,
        NID_sphincsharaka128frobust,
        NID_p256_sphincsharaka128frobust,
        NID_rsa3072_sphincsharaka128frobust,
        NID_sphincssha256128frobust,
        NID_p256_sphincssha256128frobust,
        NID_rsa3072_sphincssha256128frobust,
        NID_sphincsshake256128frobust,
        NID_p256_sphincsshake256128frobust,
        NID_rsa3072_sphincsshake256128frobust,
/////// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_NIDS_END
};

int oqssl_kem_nids_list[] = {
///// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_START
        NID_frodo640aes,
        NID_frodo640shake,
        NID_frodo976aes,
        NID_frodo976shake,
        NID_frodo1344aes,
        NID_frodo1344shake,
        NID_kyber512,
        NID_kyber768,
        NID_kyber1024,
        NID_ntru_hps2048509,
        NID_ntru_hps2048677,
        NID_ntru_hps4096821,
        NID_ntru_hrss701,
        NID_lightsaber,
        NID_saber,
        NID_firesaber,
        NID_kyber90s512,
        NID_kyber90s768,
        NID_kyber90s1024,
        NID_hqc128,
        NID_hqc192,
        NID_hqc256,
        NID_ntrulpr653,
        NID_ntrulpr761,
        NID_ntrulpr857,
        NID_sntrup653,
        NID_sntrup761,
        NID_sntrup857,
/////// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_END
};

int* sig_nid_list = NULL;
int* kem_nid_list = NULL;

int* _get_oqssl_sig_nids() {
   if (!sig_nid_list) {
      sig_nid_list = OPENSSL_malloc(sizeof(oqssl_sig_nids_list));
      memcpy(sig_nid_list, oqssl_sig_nids_list, sizeof(oqssl_sig_nids_list));
   }
   return sig_nid_list;
}

int* _get_oqssl_kem_nids() {
   if (!kem_nid_list) {
      kem_nid_list = OPENSSL_malloc(sizeof(oqssl_kem_nids_list));
      memcpy(kem_nid_list, oqssl_kem_nids_list, sizeof(oqssl_kem_nids_list));
   }
   return kem_nid_list;
}

/*
 * Maps OpenSSL NIDs to OQS IDs
 */
char* _get_oqs_alg_name(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_START
    case NID_dilithium2:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return OQS_SIG_alg_dilithium_2;
    case NID_dilithium3:
    case NID_p384_dilithium3:
      return OQS_SIG_alg_dilithium_3;
    case NID_dilithium5:
    case NID_p521_dilithium5:
      return OQS_SIG_alg_dilithium_5;
    case NID_dilithium2_aes:
    case NID_p256_dilithium2_aes:
    case NID_rsa3072_dilithium2_aes:
      return OQS_SIG_alg_dilithium_2_aes;
    case NID_dilithium3_aes:
    case NID_p384_dilithium3_aes:
      return OQS_SIG_alg_dilithium_3_aes;
    case NID_dilithium5_aes:
    case NID_p521_dilithium5_aes:
      return OQS_SIG_alg_dilithium_5_aes;
    case NID_falcon512:
    case NID_p256_falcon512:
    case NID_rsa3072_falcon512:
      return OQS_SIG_alg_falcon_512;
    case NID_falcon1024:
    case NID_p521_falcon1024:
      return OQS_SIG_alg_falcon_1024;
    case NID_picnicl1full:
    case NID_p256_picnicl1full:
    case NID_rsa3072_picnicl1full:
      return OQS_SIG_alg_picnic_L1_full;
    case NID_picnic3l1:
    case NID_p256_picnic3l1:
    case NID_rsa3072_picnic3l1:
      return OQS_SIG_alg_picnic3_L1;
    case NID_rainbowVclassic:
    case NID_p521_rainbowVclassic:
      return OQS_SIG_alg_rainbow_V_classic;
    case NID_sphincsharaka128frobust:
    case NID_p256_sphincsharaka128frobust:
    case NID_rsa3072_sphincsharaka128frobust:
      return OQS_SIG_alg_sphincs_haraka_128f_robust;
    case NID_sphincssha256128frobust:
    case NID_p256_sphincssha256128frobust:
    case NID_rsa3072_sphincssha256128frobust:
      return OQS_SIG_alg_sphincs_sha256_128f_robust;
    case NID_sphincsshake256128frobust:
    case NID_p256_sphincsshake256128frobust:
    case NID_rsa3072_sphincsshake256128frobust:
      return OQS_SIG_alg_sphincs_shake256_128f_robust;
    case NID_frodo640aes:
    case NID_p256_frodo640aes:
      return OQS_KEM_alg_frodokem_640_aes;
    case NID_frodo640shake:
    case NID_p256_frodo640shake:
      return OQS_KEM_alg_frodokem_640_shake;
    case NID_frodo976aes:
    case NID_p384_frodo976aes:
      return OQS_KEM_alg_frodokem_976_aes;
    case NID_frodo976shake:
    case NID_p384_frodo976shake:
      return OQS_KEM_alg_frodokem_976_shake;
    case NID_frodo1344aes:
    case NID_p521_frodo1344aes:
      return OQS_KEM_alg_frodokem_1344_aes;
    case NID_frodo1344shake:
    case NID_p521_frodo1344shake:
      return OQS_KEM_alg_frodokem_1344_shake;
    case NID_kyber512:
    case NID_p256_kyber512:
      return OQS_KEM_alg_kyber_512;
    case NID_kyber768:
    case NID_p384_kyber768:
      return OQS_KEM_alg_kyber_768;
    case NID_kyber1024:
    case NID_p521_kyber1024:
      return OQS_KEM_alg_kyber_1024;
    case NID_ntru_hps2048509:
    case NID_p256_ntru_hps2048509:
      return OQS_KEM_alg_ntru_hps2048509;
    case NID_ntru_hps2048677:
    case NID_p384_ntru_hps2048677:
      return OQS_KEM_alg_ntru_hps2048677;
    case NID_ntru_hps4096821:
    case NID_p521_ntru_hps4096821:
      return OQS_KEM_alg_ntru_hps4096821;
    case NID_ntru_hrss701:
    case NID_p384_ntru_hrss701:
      return OQS_KEM_alg_ntru_hrss701;
    case NID_lightsaber:
    case NID_p256_lightsaber:
      return OQS_KEM_alg_saber_lightsaber;
    case NID_saber:
    case NID_p384_saber:
      return OQS_KEM_alg_saber_saber;
    case NID_firesaber:
    case NID_p521_firesaber:
      return OQS_KEM_alg_saber_firesaber;
    case NID_kyber90s512:
    case NID_p256_kyber90s512:
      return OQS_KEM_alg_kyber_512_90s;
    case NID_kyber90s768:
    case NID_p384_kyber90s768:
      return OQS_KEM_alg_kyber_768_90s;
    case NID_kyber90s1024:
    case NID_p521_kyber90s1024:
      return OQS_KEM_alg_kyber_1024_90s;
    case NID_hqc128:
    case NID_p256_hqc128:
      return OQS_KEM_alg_hqc_128;
    case NID_hqc192:
    case NID_p384_hqc192:
      return OQS_KEM_alg_hqc_192;
    case NID_hqc256:
    case NID_p521_hqc256:
      return OQS_KEM_alg_hqc_256;
    case NID_ntrulpr653:
    case NID_p256_ntrulpr653:
      return OQS_KEM_alg_ntruprime_ntrulpr653;
    case NID_ntrulpr761:
      return OQS_KEM_alg_ntruprime_ntrulpr761;
    case NID_ntrulpr857:
    case NID_p384_ntrulpr857:
      return OQS_KEM_alg_ntruprime_ntrulpr857;
    case NID_sntrup653:
    case NID_p256_sntrup653:
      return OQS_KEM_alg_ntruprime_sntrup653;
    case NID_sntrup761:
      return OQS_KEM_alg_ntruprime_sntrup761;
    case NID_sntrup857:
    case NID_p384_sntrup857:
      return OQS_KEM_alg_ntruprime_sntrup857;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_END
    default:
      return NULL;
  }
}

int is_oqs_hybrid_alg(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_START
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
    case NID_p384_dilithium3:
    case NID_p521_dilithium5:
    case NID_p256_dilithium2_aes:
    case NID_rsa3072_dilithium2_aes:
    case NID_p384_dilithium3_aes:
    case NID_p521_dilithium5_aes:
    case NID_p256_falcon512:
    case NID_rsa3072_falcon512:
    case NID_p521_falcon1024:
    case NID_p256_picnicl1full:
    case NID_rsa3072_picnicl1full:
    case NID_p256_picnic3l1:
    case NID_rsa3072_picnic3l1:
    case NID_p521_rainbowVclassic:
    case NID_p256_sphincsharaka128frobust:
    case NID_rsa3072_sphincsharaka128frobust:
    case NID_p256_sphincssha256128frobust:
    case NID_rsa3072_sphincssha256128frobust:
    case NID_p256_sphincsshake256128frobust:
    case NID_rsa3072_sphincsshake256128frobust:
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_END
      return 1;
    default:
      return 0;
  }
}


int get_classical_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_START
    case NID_rsa3072_dilithium2:
    case NID_rsa3072_dilithium2_aes:
    case NID_rsa3072_falcon512:
    case NID_rsa3072_picnicl1full:
    case NID_rsa3072_picnic3l1:
    case NID_rsa3072_sphincsharaka128frobust:
    case NID_rsa3072_sphincssha256128frobust:
    case NID_rsa3072_sphincsshake256128frobust:
      return NID_rsaEncryption;
    case NID_p256_dilithium2:
    case NID_p256_dilithium2_aes:
    case NID_p256_falcon512:
    case NID_p256_picnicl1full:
    case NID_p256_picnic3l1:
    case NID_p256_sphincsharaka128frobust:
    case NID_p256_sphincssha256128frobust:
    case NID_p256_sphincsshake256128frobust:
      return NID_X9_62_prime256v1;
    case NID_p384_dilithium3:
    case NID_p384_dilithium3_aes:
      return NID_secp384r1;
    case NID_p521_dilithium5:
    case NID_p521_dilithium5_aes:
    case NID_p521_falcon1024:
    case NID_p521_rainbowVclassic:
      return NID_secp521r1;///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_END
    default:
      return 0;
  }
}

int get_oqs_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_OQS_NID_START
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return NID_dilithium2;
    case NID_p384_dilithium3:
      return NID_dilithium3;
    case NID_p521_dilithium5:
      return NID_dilithium5;
    case NID_p256_dilithium2_aes:
    case NID_rsa3072_dilithium2_aes:
      return NID_dilithium2_aes;
    case NID_p384_dilithium3_aes:
      return NID_dilithium3_aes;
    case NID_p521_dilithium5_aes:
      return NID_dilithium5_aes;
    case NID_p256_falcon512:
    case NID_rsa3072_falcon512:
      return NID_falcon512;
    case NID_p521_falcon1024:
      return NID_falcon1024;
    case NID_p256_picnicl1full:
    case NID_rsa3072_picnicl1full:
      return NID_picnicl1full;
    case NID_p256_picnic3l1:
    case NID_rsa3072_picnic3l1:
      return NID_picnic3l1;
    case NID_p521_rainbowVclassic:
      return NID_rainbowVclassic;
    case NID_p256_sphincsharaka128frobust:
    case NID_rsa3072_sphincsharaka128frobust:
      return NID_sphincsharaka128frobust;
    case NID_p256_sphincssha256128frobust:
    case NID_rsa3072_sphincssha256128frobust:
      return NID_sphincssha256128frobust;
    case NID_p256_sphincsshake256128frobust:
    case NID_rsa3072_sphincsshake256128frobust:
      return NID_sphincsshake256128frobust;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_OQS_NID_END
    default:
      return 0;
  }
}

int get_classical_key_len(oqs_key_type_t keytype, int classical_id) {
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return (keytype == KEY_TYPE_PRIVATE) ? 1770 : 398;
    case NID_X9_62_prime256v1:
      return (keytype == KEY_TYPE_PRIVATE) ? 121 : 65;
    case NID_secp384r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 167 : 97;
    case NID_secp521r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 223 : 133;
    default:
      return 0;
    }
}

int get_classical_sig_len(int classical_id)
{
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return 384;
    case NID_X9_62_prime256v1:
      return 72;
    case NID_secp384r1:
      return 104;
    case NID_secp521r1:
      return 141;
    default:
      return 0;
    }
}

/*
 * Initializes a OQS_KEY, given an OpenSSL NID. This function only initializes
 * the post-quantum key, not the classical one (for hybrid schemes)
 */
int oqs_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype) {
    OQS_KEY *oqs_key = NULL;
    const char* oqs_alg_name = get_oqs_alg_name(nid);

    oqs_key = OPENSSL_zalloc(sizeof(*oqs_key));
    if (oqs_key == NULL) {
      ECerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    oqs_key->nid = nid;
    if (!OQS_SIG_alg_is_enabled(oqs_alg_name))
      fprintf(stderr, "Warning: OQS algorithm '%s' not enabled.\n", oqs_alg_name);
    oqs_key->s = OQS_SIG_new(oqs_alg_name);
    if (oqs_key->s == NULL) {
      /* TODO: Perhaps even check if the alg is available earlier in the stack. */
      ECerr(EC_F_OQS_KEY_INIT, EC_R_NO_SUCH_OQS_ALGORITHM);
      goto err;
    }
    oqs_key->pubkey = OPENSSL_malloc(oqs_key->s->length_public_key);
    if (oqs_key->pubkey == NULL) {
      ECerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    /* Optionally allocate the private key */
    if (keytype == KEY_TYPE_PRIVATE) {
      oqs_key->privkey = OPENSSL_secure_malloc(oqs_key->s->length_secret_key);
      if (oqs_key->privkey == NULL) {
        ECerr(EC_F_OQS_KEY_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
      }
    }
    oqs_key->security_bits = get_oqs_security_bits(nid);
    *p_oqs_key = oqs_key;
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

/*
 * Returns the security level in bits for an OQS alg.
 */
int get_oqs_security_bits(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_GET_SIG_SECURITY_BITS_START
    case NID_dilithium2:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return 128;
    case NID_dilithium3:
    case NID_p384_dilithium3:
      return 192;
    case NID_dilithium5:
    case NID_p521_dilithium5:
      return 256;
    case NID_dilithium2_aes:
    case NID_p256_dilithium2_aes:
    case NID_rsa3072_dilithium2_aes:
      return 128;
    case NID_dilithium3_aes:
    case NID_p384_dilithium3_aes:
      return 192;
    case NID_dilithium5_aes:
    case NID_p521_dilithium5_aes:
      return 256;
    case NID_falcon512:
    case NID_p256_falcon512:
    case NID_rsa3072_falcon512:
      return 128;
    case NID_falcon1024:
    case NID_p521_falcon1024:
      return 256;
    case NID_picnicl1full:
    case NID_p256_picnicl1full:
    case NID_rsa3072_picnicl1full:
      return 128;
    case NID_picnic3l1:
    case NID_p256_picnic3l1:
    case NID_rsa3072_picnic3l1:
      return 128;
    case NID_rainbowVclassic:
    case NID_p521_rainbowVclassic:
      return 256;
    case NID_sphincsharaka128frobust:
    case NID_p256_sphincsharaka128frobust:
    case NID_rsa3072_sphincsharaka128frobust:
      return 128;
    case NID_sphincssha256128frobust:
    case NID_p256_sphincssha256128frobust:
    case NID_rsa3072_sphincssha256128frobust:
      return 128;
    case NID_sphincsshake256128frobust:
    case NID_p256_sphincsshake256128frobust:
    case NID_rsa3072_sphincsshake256128frobust:
      return 128;
///// OQS_TEMPLATE_FRAGMENT_GET_SIG_SECURITY_BITS_END
    default:
      return 0;
  }
}

/*
 * Frees the OQS_KEY, including its keys.
 */
void oqs_pkey_ctx_free(OQS_KEY* key) {
  size_t privkey_len = 0;
  if (key == NULL) {
    return;
  }
  if (key->s) {
    privkey_len = key->s->length_secret_key;
    OQS_SIG_free(key->s);
  }
  if (key->privkey) {
    OPENSSL_secure_clear_free(key->privkey, privkey_len);
  }
  if (key->pubkey) {
    OPENSSL_free(key->pubkey);
  }
  if (key->classical_pkey) {
    EVP_PKEY_free(key->classical_pkey);
  }
  OPENSSL_free(key);
}

/*
 * Returns options when running OQS KEM, e.g., in openssl speed
 */
const char *OQSKEM_options(void)
{
    size_t offset;
// TODO: Revisit which OQS_COMPILE_FLAGS to show
#ifdef OQS_COMPILE_CFLAGS
    const char* OQSKEMALGS = "OQS KEM build : ";
    char* result =  OPENSSL_zalloc(strlen(OQS_COMPILE_CFLAGS)+OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
    memcpy(result+offset, OQS_COMPILE_CFLAGS, strlen(OQS_COMPILE_CFLAGS));
    offset += strlen(OQS_COMPILE_CFLAGS);
#else 
    const char* OQSKEMALGS = "";
    char* result =  OPENSSL_zalloc(OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
#endif

    result[offset++]='-';
    int i;
    for (i=0; i<OQS_OPENSSL_KEM_algs_length;i++) {
       const char* name = OBJ_nid2sn(oqssl_kem_nids_list[i]);
       if (OQS_KEM_alg_is_enabled(get_oqs_alg_name(oqssl_kem_nids_list[i]))) {
           unsigned long l = strlen(name);
           memcpy(result+offset, name, l);
           if (i<OQS_OPENSSL_KEM_algs_length-1) {
              result[offset+l]=',';
              offset = offset+l+1;
           }
       }
    }
    return result;
}

/*
 * Returns options when running OQS SIG, e.g., in openssl speed
 */
const char *OQSSIG_options(void)
{
    size_t offset;
// TODO: Revisit which OQS_COMPILE_FLAGS to show
#ifdef OQS_COMPILE_CFLAGS
    const char* OQSSIGALGS = "OQS SIG build : ";
    char* result =  OPENSSL_zalloc(strlen(OQS_COMPILE_CFLAGS)+OQS_OPENSSL_SIG_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSSIGALGS, offset = strlen(OQSSIGALGS));
    memcpy(result+offset, OQS_COMPILE_CFLAGS, strlen(OQS_COMPILE_CFLAGS));
    offset += strlen(OQS_COMPILE_CFLAGS);
#else
    const char* OQSSIGALGS = "";
    char* result =  OPENSSL_zalloc(OQS_OPENSSL_SIG_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    offset = strlen(OQSSIGALGS);
    memcpy(result, OQSSIGALGS, offset);
#endif

    result[offset++]='-';
    int i;
    for (i=0; i<OQS_OPENSSL_SIG_algs_length;i++) {
       const char* name = OBJ_nid2sn(oqssl_sig_nids_list[i]);
       if (OQS_SIG_alg_is_enabled(get_oqs_alg_name(oqssl_sig_nids_list[i]))) {
           size_t l = strlen(name);
           memcpy(result+offset, name, l);
           if (i<OQS_OPENSSL_SIG_algs_length-1) {
              result[offset+l]=',';
              offset = offset+l+1;
           }
       }
    }
    return result;
}

int is_EC_nid(int nid) {
  return (nid == NID_X9_62_prime256v1 || nid == NID_secp384r1 || nid == NID_secp521r1);
}

int decode_EC_key(oqs_key_type_t keytype, int nid, const unsigned char* encoded_key, int key_len, OQS_KEY* oqs_key) {
  EC_GROUP *ecgroup = NULL;
  EC_KEY *ec_key = NULL;
  const unsigned char* p_encoded_key = encoded_key;
  int rv = 0;

  /* I can't figure out how to import the EC key with the high-level EVP API: the d2i_* functions complain
     that the EC group is missing. If I set it manually (creating a group and using EC_KEY_set_group to set
     it on a EC_KEY and assign it to a EVP_PKEY, the group gets erased by EVP_PKEY_set_type inside the d2i_*
     functions. I therefore use lower-level functions for EC algs.
  */
  if ((ecgroup = EC_GROUP_new_by_curve_name(nid)) == NULL) {
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  if ((ec_key = EC_KEY_new()) == NULL ||
      !EC_KEY_set_group(ec_key, ecgroup)){
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  if (keytype == KEY_TYPE_PRIVATE) {
    if (d2i_ECPrivateKey(&ec_key, &p_encoded_key, key_len) == NULL) {
      ECerr(0, ERR_R_FATAL);
      goto end;
    }
  } else {
    if (o2i_ECPublicKey(&ec_key, &p_encoded_key, key_len) == NULL) {
      ECerr(0, ERR_R_FATAL);
      goto end;
    }
  }

  if ((oqs_key->classical_pkey = EVP_PKEY_new()) == NULL ||
      !EVP_PKEY_set_type(oqs_key->classical_pkey, NID_X9_62_id_ecPublicKey) ||
      !EVP_PKEY_assign_EC_KEY(oqs_key->classical_pkey, ec_key)) {
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  rv = 1; /* success */

 end:
  if (rv == 0 && ecgroup) EC_GROUP_free(ecgroup);
  if (rv == 0 && ec_key) EC_KEY_free(ec_key);
  return rv;
}

int oqs_int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;

    /* chose SHA512 as default digest if none other explicitly set */
    if (oqs_key->digest == NULL) {
       	if ((oqs_key->digest = EVP_MD_CTX_create()) == NULL) {
       		return 0;
	}

        if (EVP_DigestInit_ex(oqs_key->digest, EVP_sha512(), NULL) <= 0) {
       		return 0;
       	}
    }

    if(EVP_DigestUpdate(oqs_key->digest, data, count)<=0) {
	return 0;
    }
    return 1;
}
