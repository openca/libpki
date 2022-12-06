
#ifndef _LIBPKI_LOG_H
#include <libpki/pki_log.h>
#endif

#ifndef _LIBPKI_ERR_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_PQC_DEFS_H
#include <libpki/openssl/pqc/pqc_defs.h>
#endif

#ifndef LIBPKI_X509_DATA_ST_H
#include "../internal/x509_data_st.h"
#endif

#ifndef _LIBPKI_PQC_INIT_H
#include <libpki/openssl/pqc/pqc_init.h>
#endif

#ifndef _LIBPKI_PQC_PKEY_METH_LOCAL_H
#include "pqc_pkey_meth.h"
#endif

#ifndef _LIBPKI_PQC_AMETH_LOCAL_H
#include "pqc_asn1_meth.h"
#endif


#define PKI_REGISTER_PKEY_METH(ALG, OID)                            \
	PKI_PQC_asn1_meth_set_id(&ALG##_ASN1_METH, OBJ_txt2nid(OID)); 	  \
	if (EVP_PKEY_meth_add0(&ALG##_PKEY_METH)) {                       \
    EVP_PKEY_asn1_add0(&ALG##_ASN1_METH);                           \
  } else {                                                          \
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add PKEY method");      \
  }

// ====
// Data
// ====

#ifdef ENABLE_OQS

// Dilithium
DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium2)
// DEFINE_OQS_ITEM_SIGN(dilithium3, OBJ_sn2nid("dilithium2"))
// DEFINE_OQS_SIGN_INFO_SET(dilithium3, OBJ_sn2nid("dilithium2"))

DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium3)
DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium5)

// Falcon
DEFINE_ITEM_SIGN_AND_INFO_SET(falcon512)
DEFINE_ITEM_SIGN_AND_INFO_SET(falcon1024)

// Experimental
DEFINE_ITEM_SIGN_AND_INFO_SET(dilithiumX)

#endif

// // Composite Crypto
// // #ifdef ENABLE_COMPOSITE
// // DEFINE_OQS_ITEM_SIGN(composite, OBJ_sn2nid("COMPOSITE"))
// // #endif

// // Multikey Crypto
// #ifdef ENABLE_COMBINED
// DEFINE_OQS_ITEM_SIGN(combined, OBJ_sn2nid("MULTIKEY"))
// #endif

// =========
// Functions
// =========

int PKI_PQC_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id) {

  // Input Check
  if (!pkey_ameth || pkey_id <= 0) return 0;

  // Assigns the generated IDs
	pkey_ameth->pkey_id = pkey_id;
	pkey_ameth->pkey_base_id = pkey_id;
	pkey_ameth->pkey_id = pkey_id;

  // All Done
  return 1;
};

EVP_PKEY_METHOD * PKI_PQC_PKEY_METH_new(int nid, int flags) {

  // Input check
  if (nid <= 0) {
    PKI_ERROR(PKI_ERR_PARAM_RANGE, "Out-of-Range NID for PKEY method");
    return NULL;
  }

  // Initializes the PKEY method first
  EVP_PKEY_METHOD * pkey_meth = EVP_PKEY_meth_new(nid, flags);
  if (!pkey_meth) {
    PKI_ERROR(PKI_ERR_ALGOR_SET, "Cannot create a new PKEY method");
    return NULL;
  }

  // ------------------------------
  // PKEY Let's add all the methods
  // ------------------------------
  
  // Copy
  EVP_PKEY_meth_set_copy(pkey_meth, pkey_oqs_copy);

  // Key Generation
  EVP_PKEY_meth_set_keygen(pkey_meth, NULL, pkey_oqs_keygen);

  // Sign & Sign Init
  EVP_PKEY_meth_set_sign(pkey_meth, pkey_oqs_sign_init, pkey_oqs_sign);

  // // Verify & Verify Init
  EVP_PKEY_meth_set_verify(pkey_meth, pkey_oqs_verify_init, pkey_oqs_verify);

  // // SignCTX and SignCTX Init
  EVP_PKEY_meth_set_signctx(pkey_meth, pkey_oqs_signctx_init, pkey_oqs_signctx);

  // // VerifyCTX and VerifyCTX Init
  EVP_PKEY_meth_set_verifyctx(pkey_meth, pkey_oqs_verifyctx_init, pkey_oqs_verifyctx);

  // // CTRL & CTRL str
  EVP_PKEY_meth_set_ctrl(pkey_meth, pkey_oqs_ctrl, NULL);

  // // Digest Sign
  EVP_PKEY_meth_set_digestsign(pkey_meth, pkey_oqs_digestsign);

  // // Digest Verify
  EVP_PKEY_meth_set_digestverify(pkey_meth, pkey_oqs_digestverify);

  // // Digest Custom
  EVP_PKEY_meth_set_digest_custom(pkey_meth, pkey_oqs_digestcustom);

  // All Done
  return pkey_meth;
}

EVP_PKEY_ASN1_METHOD * PKI_PQC_PKEY_ASN1_METH_new(int                nid, 
                                                  int                flags, 
                                                  const char * const pem_str, 
                                                  const char * const info) {

  if (nid <= 0) {
    PKI_ERROR(PKI_ERR_PARAM_RANGE, "Out-of-Range NID for ASN1 PKEY creation");
    return NULL;
  }

  // Generates a new ASN1 PKEY method
  EVP_PKEY_ASN1_METHOD * a_meth = EVP_PKEY_asn1_new(nid,
                                                    flags,
                                                    pem_str ? pem_str : OBJ_nid2sn(nid),
                                                    info);

  // We need to add all the different methods

  // Sets the Public Key methods
  EVP_PKEY_asn1_set_public(a_meth,
                           oqs_pub_decode,
                           oqs_pub_encode,
                           oqs_pub_cmp,
                           oqs_pub_print,
                           oqs_size_lcl,
                           oqs_bits
                          );

  // Sets the Private Key methods
  EVP_PKEY_asn1_set_private(a_meth,
                            oqs_priv_decode,
                            oqs_priv_encode,
                            oqs_priv_print
                           );

  // Sets the Param
  EVP_PKEY_asn1_set_param(a_meth, 
                          NULL, // oqs_param_decode,
                          NULL, // oqs_param_encode,
                          NULL, // oqs_param_missing,
                          NULL, // oqs_param_copy,
                          NULL, // oqs_param_cmp,
                          NULL  // oqs_param_print)
                         );

  EVP_PKEY_asn1_set_free(a_meth, oqs_free);

  EVP_PKEY_asn1_set_ctrl(a_meth, oqs_ameth_pkey_ctrl);

  // Need to check this one
  EVP_PKEY_asn1_set_security_bits(a_meth, oqs_security_bits);

  // item_sign and set_siginfo are algorithm-dependent
  // therefore we select the right functions based on
  // the nid value
  int (*fnc_item_sign)(EVP_MD_CTX *ctx,
                        const ASN1_ITEM *it,
                        void *asn,
                        X509_ALGOR *alg1,
                        X509_ALGOR *alg2,
                        ASN1_BIT_STRING *sig) = NULL;

  int (*fnc_set_siginfo)(X509_SIG_INFO *siginf,
                         const X509_ALGOR *alg,
                         const ASN1_STRING *sig) = NULL;

  if (OBJ_sn2nid("dilithium2") == nid) {
    fnc_item_sign = oqs_item_sign_dilithium2;
    fnc_set_siginfo = oqs_sig_info_set_dilithium2;
  } else if (OBJ_sn2nid("dilithium3") == nid) {
    fnc_item_sign = oqs_item_sign_dilithium3;
    fnc_set_siginfo = oqs_sig_info_set_dilithium3;
  } else if (OBJ_sn2nid("dilithium5") == nid) {
    fnc_item_sign = oqs_item_sign_dilithium5;
    fnc_set_siginfo = oqs_sig_info_set_dilithium5;
  } else if (OBJ_sn2nid("falcon512") == nid) {
    fnc_item_sign = oqs_item_sign_falcon512;
    fnc_set_siginfo = oqs_sig_info_set_falcon512;
  } else if (OBJ_sn2nid("falcon1024") == nid) {
    fnc_item_sign = oqs_item_sign_falcon1024;
    fnc_set_siginfo = oqs_sig_info_set_falcon1024;
  } else if (OBJ_sn2nid("DilithiumX") == nid ||
             OBJ_sn2nid("dilithiumX") == nid) {
    fnc_item_sign = oqs_item_sign_dilithiumX;
    fnc_set_siginfo = oqs_sig_info_set_dilithiumX;
  } else {
    fprintf(stderr, "Unsupported NID: %d\n", nid);
    fflush(stderr);
    // PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Unsupported NID %d (%s)", nid, OBJ_nid2sn(nid));
    return NULL;
  }

  // Sets the algorithm-dependent functions
  EVP_PKEY_asn1_set_item(a_meth, oqs_item_verify, fnc_item_sign);
  EVP_PKEY_asn1_set_siginf(a_meth, fnc_set_siginfo);

  // Unused methods
  EVP_PKEY_asn1_set_check(a_meth, NULL);
  EVP_PKEY_asn1_set_public_check(a_meth, NULL);
  EVP_PKEY_asn1_set_param_check(a_meth, NULL);

  EVP_PKEY_asn1_set_set_priv_key(a_meth, NULL);
  EVP_PKEY_asn1_set_set_pub_key(a_meth, NULL);
  EVP_PKEY_asn1_set_get_priv_key(a_meth, NULL);
  EVP_PKEY_asn1_set_get_pub_key(a_meth, NULL);

  // All Done
  return a_meth;
};

int PKI_PQC_ALG_new(const char * name, int flags) {

  // Input Check
  if (!name || strlen(name) <= 0) return PKI_ERR;

  // Retrieves the NID associated with the algorithm
  int nid = OBJ_sn2nid(name);
  if (nid == NID_undef) {
    PKI_ERROR(PKI_ERR_OBJECT_TYPE_UNKNOWN, "Cannot find the ID for %s algorithm", name);
    return PKI_ERR;
  }

  // Checks the input flags
  if (flags < 0) flags = EVP_PKEY_FLAG_SIGCTX_CUSTOM;

  // ----------------------------------
  // Generates and Adds the PKEY method
  // ----------------------------------

  EVP_PKEY_METHOD * p_meth = PKI_PQC_PKEY_METH_new(nid, flags);
  if (!p_meth) {
    PKI_ERROR(PKI_ERR_ALGOR_PKEY_METHOD_NEW, "Cannot generate the PKEY method for %d (%s)\n", nid, name);
    return PKI_ERR;
  }

  // Adds the Method
  if (!EVP_PKEY_meth_add0(p_meth)) {
    PKI_ERROR(PKI_ERR_ALGOR_PKEY_METHOD_ADD, "Cannot Add the PKEY Method for %d (%s)", nid, name);
    if (p_meth) EVP_PKEY_meth_free(p_meth);
    return PKI_ERR;
  }

  // Checks that the new method is added correctly
  const EVP_PKEY_METHOD * tmp_p_meth = EVP_PKEY_meth_find(nid);
  if (!tmp_p_meth) {
    PKI_ERROR(PKI_ERR_ALGOR_PKEY_ASN1_METHOD_NEW, "Cannot find the PKEY method just added (%d)!\n", nid);
    return PKI_ERR;
  }

  // ----------------------------------
  // Now we need to add the ASN1 method
  // ----------------------------------

  EVP_PKEY_ASN1_METHOD * a_meth = PKI_PQC_PKEY_ASN1_METH_new(nid, 0, name, name);
  if (!a_meth) {
    PKI_ERROR(PKI_ERR_ALGOR_SET, "Cannot generate the PKEY ASN1 method for %d (%s)\n", nid, name);
    fflush(stderr);
    return PKI_ERR;
  }

  // Adds the ASN1 method to the list of available ones
  if (1 != EVP_PKEY_asn1_add0(a_meth)) {
    PKI_ERROR(PKI_ERR_ALGOR_SET, "Cannot Set the ASN1 PKEY method for %d (%s)", nid, name);
    if (a_meth) EVP_PKEY_asn1_free(a_meth);
    return PKI_ERR;
  }

  // All Done
  return PKI_OK;
};

int PKI_PQC_init() {

  // Let's initialize our own implementation of Dilithium5
  // that we call "DilithiumX" (Test for initialization of
  // Post-Quantum cryptography from our own pool)
  if (PKI_PQC_ALG_new("DilithiumX", -1) == PKI_OK) {
    // Reports the Error
    PKI_ERROR(PKI_ERR_ALGOR_ADD, "DilithiumX");
  } else {
    // Debugging
    PKI_DEBUG("PQC Algorithm Added: DilithiumX");
  }

  // All Done
  return PKI_OK;
};