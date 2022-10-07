
#ifndef _LIBPKI_PQC_METH_H
#include <libpki/openssl/pqc/pqc_meth.h>
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

#include "pqc_pkey_meth.h"
#include "pqc_asn1_meth.h"

#ifndef _LIBPKI_ERRORS_H
#include <libpki/pki_err.h>
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
  if (flags == -1) flags = EVP_PKEY_FLAG_SIGCTX_CUSTOM;

  // Initializes the PKEY method first
  EVP_PKEY_METHOD * pkey_meth = EVP_PKEY_meth_new(nid, flags);
  if (!pkey_meth) {
    PKI_ERROR(PKI_ERR_ALGOR_SET, "Cannot create a new PKEY method");
    return PKI_ERR;
  }

  // Let's add all the methods
  
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

  return PKI_OK;
};

int PKI_PQC_PKEY_ASN1_METH_new(int nid) {
  PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
  return PKI_ERR;
};

int PKI_PQC_init() {
  
  // PKI_PQC_asn1_meth_set_id(&DILITHIUMX_ASN1_METH, OBJ_txt2nid(OPENCA_ALG_PKEY_PQC_DILITHIUMX_OID));
	
  // if (EVP_PKEY_meth_add0(&DILITHIUMX_PKEY_METH)) {
  //   EVP_PKEY_asn1_add0(&DILITHIUMX_ASN1_METH);
  // } else {
  //   PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot add PKEY method");
  // }

  // // PKI_REGISTER_PKEY_METH(DILITHIUMX, OPENCA_ALG_PKEY_PQC_DILITHIUMX_OID);

  // fprintf(stderr,"***** DdddddDDDDDd ****\n");
  // fprintf(stderr,"************************************\n");

  if (PKI_PQC_ALG_new("DilithiumX", -1) == PKI_OK) {
    fprintf(stderr, "ALGORITHM dilithiumX added successfully\n");
  } else {
    fprintf(stderr, "Cannot Add dilithiumX PKEY!\n");
  }
  fflush(stderr);


  return PKI_OK;
};