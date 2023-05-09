
// ===============
// Public Includes
// ===============

#ifndef _LIBPKI_COMPOSITE_INIT_H
#include <libpki/openssl/composite/composite_init.h>
#endif

// ==============
// Local Includes
// ==============

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_PQC_DEFS_H
#include <libpki/openssl/pqc/pqc_defs.h>
#endif

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#include <libpki/openssl/composite/composite_utils.h>
#endif

#ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#include <libpki/openssl/composite/composite_pmeth.h>
#endif

#ifndef _LIBPKI_LOG_H
#include <libpki/pki_log.h>
#endif

#ifndef LIBPKI_X509_DATA_ST_H
#include "../internal/x509_data_st.h"
#endif

#ifndef _LIBPKI_COMPOSITE_ASN1_METH_H
#include "composite_ameth_lcl.h"
#endif

// Composite Methods
extern EVP_PKEY_ASN1_METHOD composite_asn1_meth;
extern EVP_PKEY_METHOD composite_pkey_meth;

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

// Explicit Composite Combinations Functions

// // Dilithium
// DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium2)

// DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium3)
// DEFINE_ITEM_SIGN_AND_INFO_SET(dilithium5)

// // Falcon
// DEFINE_ITEM_SIGN_AND_INFO_SET(falcon512)
// DEFINE_ITEM_SIGN_AND_INFO_SET(falcon1024)

// // Experimental
// DEFINE_ITEM_SIGN_AND_INFO_SET(dilithiumX)

#endif

// static int _init_generic_composite() {

// 	// TODO:
// 	// =====
// 	//
// 	// Update the way we add the composite ASN1 method. Currently we use the
// 	// auxillary function (see composite_ameth.c) to set the method's pkey id.
// 	//
// 	// The Right way to add a new method would be to first generate a new
// 	// one and then set the different callbacks, such as:
// 	//
// 	//   composite_asn1_method = EVP_PKEY_asn1_meth_new(NID_composite);
// 	//   EVP_PKEY_asn1_meth_set_XXX(composite_asn1_method, .... );

// 	// Retrieves the COMPOSITE id
// 	int composite_id = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID);

// 	// Assigns the generated IDs
// 	EVP_PKEY_asn1_meth_set_id(&composite_asn1_meth, composite_id);

// 	// Assigns the PKEY ID
// 	EVP_PKEY_meth_set_id(&composite_pkey_meth, composite_id, -1); // EVP_PKEY_FLAG_SIGCTX_CUSTOM

// 	// We also Need to initialize the PKEY method for the algorithm
// 	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
// 	if (!EVP_PKEY_meth_add0(&composite_pkey_meth)) return 0;

// 	// We Need to initialize the ASN1 conversion method
// 	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
// 	if (!EVP_PKEY_asn1_add0(&composite_asn1_meth)) return 0;
	
// 	// All Done, Success.
// 	return 1;
// }

// static int _init_explicit_composite() {

// 	// Here we initialize PKEYs to handle the explicit
// 	// composite combinations

// 	// TODO: madwolf: Enable the Instantiation of Explicit Combinations

// 	// Debugging
// 	// PKI_DEBUG("TODO: Add Explicit Composite Combinations.");

// 	// char * methods_oids[] = {
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_OID,
// 	//  	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ECDSA_P256_OID,
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_OID,
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ECDSA_P256_OID,
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_OID,
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_ECDSA_P521_OID,
// 	// 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_OID,
// 	// 	NULL,
// 	// };

// 	// for (int i = 0; methods_oids[i] != NULL; i++ ) {

// 	// 	// Retrieves the ID for the Explicit PKEY
// 	// 	int explicit_comp_id = OBJ_txt2nid(methods_oids[i]);

// 	// 	// Debugging
// 	// 	PKI_DEBUG("Adding Explicit Composite Combination %d (%s)", 
// 	// 		explicit_comp_id, methods_oids[i]);

// 	// 	// // Assigns the generated IDs
// 	// 	// EVP_PKEY_asn1_meth_set_id(&composite_asn1_meth, explicit_comp_id);

// 	// 	// // Assigns the PKEY ID
// 	// 	// EVP_PKEY_meth_set_id(&composite_pkey_meth, explicit_comp_id, -1); // EVP_PKEY_FLAG_SIGCTX_CUSTOM

// 	// 	// // We also Need to initialize the PKEY method for the algorithm
// 	// 	// // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
// 	// 	// if (!EVP_PKEY_meth_add0(&composite_pkey_meth)) return 0;

// 	// 	// // We Need to initialize the ASN1 conversion method
// 	// 	// // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
// 	// 	// if (!EVP_PKEY_asn1_add0(&composite_asn1_meth)) return 0;
// 	// }
	
// 	// All Done, Success.
// 	return 1;
// }

// ================
// Local Prototypes
// ================

int PKI_COMPOSITE_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id);

EVP_PKEY_METHOD * PKI_COMPOSITE_PKEY_METH_new(int nid, int flags);

EVP_PKEY_ASN1_METHOD * PKI_COMPOSITE_PKEY_ASN1_METH_new(int                nid, 
                                                        int                flags, 
                                                        const char * const pem_str, 
                                                        const char * const info);

int PKI_COMPOSITE_ALG_new(const char * name, int flags);

// =========
// Functions
// =========

int PKI_COMPOSITE_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id) {

  // Input Check
  if (!pkey_ameth || pkey_id <= 0) return 0;

  // Assigns the generated IDs
	pkey_ameth->pkey_id = pkey_id;
	pkey_ameth->pkey_base_id = pkey_id;
	pkey_ameth->pkey_id = pkey_id;

  // All Done
  return 1;
};

EVP_PKEY_METHOD * PKI_COMPOSITE_PKEY_METH_new(int nid, int flags) {

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
  
  // // Copy
  // EVP_PKEY_meth_set_copy(pkey_meth, pkey_oqs_copy);

  // // Key Generation
  // EVP_PKEY_meth_set_keygen(pkey_meth, NULL, pkey_oqs_keygen);

  // // Sign & Sign Init
  // EVP_PKEY_meth_set_sign(pkey_meth, pkey_oqs_sign_init, pkey_oqs_sign);

  // // // Verify & Verify Init
  // EVP_PKEY_meth_set_verify(pkey_meth, pkey_oqs_verify_init, pkey_oqs_verify);

  // // // SignCTX and SignCTX Init
  // EVP_PKEY_meth_set_signctx(pkey_meth, pkey_oqs_signctx_init, pkey_oqs_signctx);

  // // // VerifyCTX and VerifyCTX Init
  // EVP_PKEY_meth_set_verifyctx(pkey_meth, pkey_oqs_verifyctx_init, pkey_oqs_verifyctx);

  // // // CTRL & CTRL str
  // EVP_PKEY_meth_set_ctrl(pkey_meth, pkey_oqs_ctrl, NULL);

  // // // Digest Sign
  // EVP_PKEY_meth_set_digestsign(pkey_meth, pkey_oqs_digestsign);

  // // // Digest Verify
  // EVP_PKEY_meth_set_digestverify(pkey_meth, pkey_oqs_digestverify);

  // // // Digest Custom
  // EVP_PKEY_meth_set_digest_custom(pkey_meth, pkey_oqs_digestcustom);

  // All Done
  return pkey_meth;
}

EVP_PKEY_ASN1_METHOD * PKI_COMPOSITE_PKEY_ASN1_METH_new(int                nid, 
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

  // // We need to add all the different methods

  // // // Sets the Public Key methods
  // EVP_PKEY_asn1_set_public(a_meth,
  //                          oqs_pub_decode,
  //                          oqs_pub_encode,
  //                          oqs_pub_cmp,
  //                          oqs_pub_print,
  //                          oqs_size_lcl,
  //                          oqs_bits
  //                         );

  // // Sets the Private Key methods
  // EVP_PKEY_asn1_set_private(a_meth,
  //                           oqs_priv_decode,
  //                           oqs_priv_encode,
  //                           oqs_priv_print
  //                          );

  // // Sets the Param
  // EVP_PKEY_asn1_set_param(a_meth, 
  //                         NULL, // oqs_param_decode,
  //                         NULL, // oqs_param_encode,
  //                         NULL, // oqs_param_missing,
  //                         NULL, // oqs_param_copy,
  //                         NULL, // oqs_param_cmp,
  //                         NULL  // oqs_param_print)
  //                        );

  // EVP_PKEY_asn1_set_free(a_meth, oqs_free);

  // EVP_PKEY_asn1_set_ctrl(a_meth, oqs_ameth_pkey_ctrl);

  // // Need to check this one
  // EVP_PKEY_asn1_set_security_bits(a_meth, oqs_security_bits);

  // // item_sign and set_siginfo are algorithm-dependent
  // // therefore we select the right functions based on
  // // the nid value
  // int (*fnc_item_sign)(EVP_MD_CTX *ctx,
  //                       const ASN1_ITEM *it,
  //                       void *asn,
  //                       X509_ALGOR *alg1,
  //                       X509_ALGOR *alg2,
  //                       ASN1_BIT_STRING *sig) = NULL;

  // int (*fnc_set_siginfo)(X509_SIG_INFO *siginf,
  //                        const X509_ALGOR *alg,
  //                        const ASN1_STRING *sig) = NULL;

  // // Here we need to assign the functions dynamically
  // // so that the right algorithm OID is used when
  // // signing and setting the sig info

  // if (OBJ_sn2nid("dilithium2") == nid) {
  //   fnc_item_sign = oqs_item_sign_dilithium2;
  //   fnc_set_siginfo = oqs_sig_info_set_dilithium2;
  // } else if (OBJ_sn2nid("dilithium3") == nid) {
  //   fnc_item_sign = oqs_item_sign_dilithium3;
  //   fnc_set_siginfo = oqs_sig_info_set_dilithium3;
  // } else if (OBJ_sn2nid("dilithium5") == nid) {
  //   fnc_item_sign = oqs_item_sign_dilithium5;
  //   fnc_set_siginfo = oqs_sig_info_set_dilithium5;
  // } else if (OBJ_sn2nid("falcon512") == nid) {
  //   fnc_item_sign = oqs_item_sign_falcon512;
  //   fnc_set_siginfo = oqs_sig_info_set_falcon512;
  // } else if (OBJ_sn2nid("falcon1024") == nid) {
  //   fnc_item_sign = oqs_item_sign_falcon1024;
  //   fnc_set_siginfo = oqs_sig_info_set_falcon1024;
  // } else if (OBJ_sn2nid("DilithiumX3") == nid ||
  //            OBJ_sn2nid("dilithiumX3") == nid) {
  //   fnc_item_sign = oqs_item_sign_dilithiumX;
  //   fnc_set_siginfo = oqs_sig_info_set_dilithiumX;
  // } else {
  //   fprintf(stderr, "Unsupported NID: %d\n", nid);
  //   fflush(stderr);
  //   // PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Unsupported NID %d (%s)", nid, OBJ_nid2sn(nid));
  //   return NULL;
  // }

  // // Sets the algorithm-dependent functions
  // EVP_PKEY_asn1_set_item(a_meth, oqs_item_verify, fnc_item_sign);
  // EVP_PKEY_asn1_set_siginf(a_meth, fnc_set_siginfo);

  // // Unused methods
  // EVP_PKEY_asn1_set_check(a_meth, NULL);
  // EVP_PKEY_asn1_set_public_check(a_meth, NULL);
  // EVP_PKEY_asn1_set_param_check(a_meth, NULL);

  // EVP_PKEY_asn1_set_set_priv_key(a_meth, NULL);
  // EVP_PKEY_asn1_set_set_pub_key(a_meth, NULL);
  // EVP_PKEY_asn1_set_get_priv_key(a_meth, NULL);
  // EVP_PKEY_asn1_set_get_pub_key(a_meth, NULL);

  // All Done
  return a_meth;
};

int PKI_COMPOSITE_ALG_new(const char * name, int flags) {

  // Input Check
  if (!name || strlen(name) <= 0) return PKI_ERR;

  // Retrieves the NID associated with the algorithm
  int nid = OBJ_sn2nid(name);
  if (nid == NID_undef) {
    PKI_DEBUG("Cannot find the ID for %s algorithm", name);
    return PKI_ERR;
  }

  // Checks the input flags
  if (flags < 0) flags = EVP_PKEY_FLAG_SIGCTX_CUSTOM;

  // ----------------------------------
  // Generates and Adds the PKEY method
  // ----------------------------------

  EVP_PKEY_METHOD * p_meth = PKI_COMPOSITE_PKEY_METH_new(nid, flags);
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

  EVP_PKEY_ASN1_METHOD * a_meth = PKI_COMPOSITE_PKEY_ASN1_METH_new(nid, 0, name, name);
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

int PKI_COMPOSITE_init() {

  // Retrieves the COMPOSITE id
	int composite_id = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID);

  EVP_PKEY_ASN1_METHOD * dyn_asn1_meth = PKI_Malloc(sizeof(EVP_PKEY_ASN1_METHOD));
    // The dynamically allocated ASN1 method

  EVP_PKEY_METHOD * dyn_pkey_meth = PKI_Malloc(sizeof(EVP_PKEY_METHOD));
    // The dynamically allocated PKEY method
  
  // Checks that the memory has been allocated
  if (!dyn_asn1_meth || !dyn_pkey_meth) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    if (dyn_asn1_meth) PKI_Free(dyn_asn1_meth);
    if (dyn_pkey_meth) PKI_Free(dyn_pkey_meth);
    return PKI_ERR;
  }

  // Copies our templates
  memcpy(dyn_asn1_meth, &composite_asn1_meth, sizeof(EVP_PKEY_ASN1_METHOD));
  memcpy(dyn_pkey_meth, &composite_pkey_meth, sizeof(EVP_PKEY_METHOD));

	// Assigns the generated IDs
	EVP_PKEY_asn1_meth_set_id(dyn_asn1_meth, composite_id);

	// Assigns the PKEY ID
	EVP_PKEY_meth_set_id(dyn_pkey_meth, composite_id, -1); // EVP_PKEY_FLAG_SIGCTX_CUSTOM

// We also Need to initialize the PKEY method for the algorithm
    // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
    if (!EVP_PKEY_meth_add0(dyn_pkey_meth)) {
      PKI_DEBUG("ERROR::EVP_PKEY_meth_add0 (%s)", OPENCA_ALG_PKEY_EXP_COMP_OID);
      PKI_Free(dyn_asn1_meth);
      PKI_Free(dyn_pkey_meth);
      return PKI_ERR;
    }

    // We Need to initialize the ASN1 conversion method
    // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
    if (!EVP_PKEY_asn1_add0(dyn_asn1_meth)) {
      PKI_DEBUG("ERROR::EVP_PKEY_asn1_add0 (%s)",OPENCA_ALG_PKEY_EXP_COMP_OID);
      PKI_Free(dyn_asn1_meth);
      PKI_Free(dyn_pkey_meth);
      return PKI_ERR;
    }

  // All Done
  return PKI_OK;
};

int PKI_EXPLICIT_COMPOSITE_init() {


  char * methods_oids[] = {
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID,
	 	OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID,
		OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID,
		OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID,
		OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID,
		OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID,
		OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_OID,
    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_OID,
		NULL,
	};

	for (int i = 0; methods_oids[i] != NULL; i++ ) {

		// Retrieves the ID for the Explicit PKEY
		int explicit_comp_id = OBJ_txt2nid(methods_oids[i]);

    EVP_PKEY_ASN1_METHOD * dyn_asn1_meth = PKI_Malloc(sizeof(EVP_PKEY_ASN1_METHOD));
    // The dynamically allocated ASN1 method

    EVP_PKEY_METHOD * dyn_pkey_meth = PKI_Malloc(sizeof(EVP_PKEY_METHOD));
      // The dynamically allocated PKEY method
  
    // Checks that the memory has been allocated
    if (!dyn_asn1_meth || !dyn_pkey_meth) {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      if (dyn_asn1_meth) PKI_Free(dyn_asn1_meth);
      if (dyn_pkey_meth) PKI_Free(dyn_pkey_meth);
      return PKI_ERR;
    }

    // Copies our templates
    memcpy(dyn_asn1_meth, &composite_asn1_meth, sizeof(EVP_PKEY_ASN1_METHOD));
    memcpy(dyn_pkey_meth, &composite_pkey_meth, sizeof(EVP_PKEY_METHOD));

    // Assigns the generated IDs
    EVP_PKEY_asn1_meth_set_id(dyn_asn1_meth, explicit_comp_id);

    // Assigns the PKEY ID
    EVP_PKEY_meth_set_id(dyn_pkey_meth, explicit_comp_id, -1); // EVP_PKEY_FLAG_SIGCTX_CUSTOM

    // We also Need to initialize the PKEY method for the algorithm
    // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
    if (!EVP_PKEY_meth_add0(dyn_pkey_meth)) {
      PKI_DEBUG("ERROR::EVP_PKEY_meth_add0 (%s)", methods_oids[i]);
      PKI_Free(dyn_asn1_meth);
      PKI_Free(dyn_pkey_meth);
      continue;
    }

    // We Need to initialize the ASN1 conversion method
    // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
    if (!EVP_PKEY_asn1_add0(dyn_asn1_meth)) {
      PKI_DEBUG("ERROR::EVP_PKEY_asn1_add0 (%s)", methods_oids[i]);
      PKI_Free(dyn_asn1_meth);
      PKI_Free(dyn_pkey_meth);
      continue;
    }

	}

  // All Done
  return PKI_OK;
};