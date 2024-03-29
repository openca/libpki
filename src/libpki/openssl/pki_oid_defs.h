/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_OID_DEFS_H
#define _LIBPKI_OID_DEFS_H

// Library configuration
#include <libpki/libpki_enables.h>

#ifdef ENABLE_OQS
# ifndef OQS_H
#  include <oqs/oqs.h>
# endif
#endif

BEGIN_C_DECLS

// =======================
// Initialization Function
// =======================

int PKI_X509_OID_init();

// ===============
// General Defines
// ===============

// GENERAL
# define LEVEL_OF_ASSURANCE_OID   		    "1.3.6.1.4.1.18227.50.1"
# define LEVEL_OF_ASSURANCE_NAME            "levelOfAssurance"
# define LEVEL_OF_ASSURANCE_DESC            "Level Of Assurance"

# define CERTIFICATE_USAGE_OID   		    "1.3.6.1.4.1.18227.50.2"
# define CERTIFICATE_USAGE_NAME             "certificateUsage"
# define CERTIFICATE_USAGE_DESC             "Certificate Usage"

# define CERTIFICATE_TEMPLATE_OID   		"1.3.6.1.4.1.18227.50.3"
# define CERTIFICATE_TEMPLATE_NAME          "certificateTemplate"
# define CERTIFICATE_TEMPLATE_DESC          "Certificate Template"

// PEN
# define OPENCA_OID							"1.3.6.1.4.1.18227"
# define OPENCA_NAME                        "OpenCA"
# define OPENCA_DESC                        "OpenCA Labs Private Enterprise Number"

// GENERIC
# define OPENCA_ALG_OID				            OPENCA_OID ".2"
# define OPENCA_ALG_PKEY_OID		            OPENCA_ALG_OID ".1"
# define OPENCA_ALG_SIGS_OID		            OPENCA_ALG_OID ".2"
# define OPENCA_ALG_KEMS_OID		            OPENCA_ALT_OID ".3"
# define OPENCA_ALG_HASH_OID		            OPENCA_ALT_OID ".4"
# define OPENCA_ALG_HMAC_OID		            OPENCA_ALT_OID ".5"
# define OPENCA_ALG_SYM_OID 		            OPENCA_ALT_OID ".6"

// =====================
// Public Key Algorithms
// =====================

// PKEY - EXP
# define OPENCA_ALG_PKEY_EXP_OID                OPENCA_ALG_PKEY_OID ".999"

// PKEY - COMPOSITE KEY
# define OPENCA_ALG_PKEY_EXP_COMP_OID           "2.16.840.1.114027.80.4.1"
# define OPENCA_ALG_PKEY_EXP_COMP_NAME          "COMPOSITE"
# define OPENCA_ALG_PKEY_EXP_COMP_DESC          "Composite Key"

// PKEY - EXP - ALT KEY
# define OPENCA_ALG_PKEY_EXP_ALT_OID  	        OPENCA_ALG_PKEY_EXP_OID ".2"
# define OPENCA_ALG_PKEY_EXP_ALT_NAME           "MULTIKEY"
# define OPENCA_ALG_PKEY_EXP_ALT_DESC           "Multiple Key"

// PKEY - EXP - DILITHIUM X
# define OPENCA_ALG_PKEY_EXP_DILITHIUMX_OID     OPENCA_ALG_PKEY_EXP_OID ".3"
# define OPENCA_ALG_PKEY_EXP_DILITHIUMX_NAME    "DilithiumX3"
# define OPENCA_ALG_PKEY_EXP_DILITHIUMX_DESC    "DilithiumX3"

// PKEY - PQC
# define OPENCA_ALG_PKEY_PQC_OID    	        OPENCA_ALG_PKEY_OID ".1"

// PKEY - PQC - FALCON
# define OPENCA_ALG_PKEY_PQC_FALCON_OID    	    OPENCA_ALG_PKEY_PQC_OID ".1"
# define OPENCA_ALG_PKEY_PQC_FALCON_NAME   	    "Falcon"
# define OPENCA_ALG_PKEY_PQC_FALCON_DESC   	    "Falcon Lattice-Based Crypto Scheme"

// # define OPENCA_ALG_PKEY_PQC_FALCON512_OID    	"1.3.9999.3.1"
# define OPENCA_ALG_PKEY_PQC_FALCON512_OID    	"1.3.9999.3.6"
# define OPENCA_ALG_PKEY_PQC_FALCON512_NAME     "falcon512"
# define OPENCA_ALG_PKEY_PQC_FALCON512_DESC    	"falcon512"

// # define OPENCA_ALG_PKEY_PQC_FALCON1024_OID     "1.3.9999.3.4"
# define OPENCA_ALG_PKEY_PQC_FALCON1024_OID     "1.3.9999.3.9"
# define OPENCA_ALG_PKEY_PQC_FALCON1024_NAME    "falcon1024"
# define OPENCA_ALG_PKEY_PQC_FALCON1024_DESC    "falcon1024"

// PKEY - PQC - DILITHIUM
# define OPENCA_ALG_PKEY_PQC_DILITHIUM_OID    	OPENCA_ALG_PKEY_PQC_OID ".2"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM_NAME     "dilithium"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM_DESC     "dilithium Lattice-Based Crypto Scheme"

# define OPENCA_ALG_PKEY_PQC_DILITHIUM2_OID    	"1.3.6.1.4.1.2.267.7.4.4"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME    "dilithium2"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM2_DESC    "dilithium2"

# define OPENCA_ALG_PKEY_PQC_DILITHIUM3_OID    	"1.3.6.1.4.1.2.267.7.6.5"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME    "dilithium3"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM3_DESC    "dilithium3"

# define OPENCA_ALG_PKEY_PQC_DILITHIUM5_OID    	"1.3.6.1.4.1.2.267.7.8.7"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME    "dilithium5"
# define OPENCA_ALG_PKEY_PQC_DILITHIUM5_DESC    "dilithium5"

// PKEY - PQC - SPHINCS

# define OPENCA_ALG_PKEY_PQC_SPHINCS_OID    	OPENCA_ALG_PKEY_PQC_OID ".3"
# define OPENCA_ALG_PKEY_PQC_SPHINCS_NAME    	"sphincs"
# define OPENCA_ALG_PKEY_PQC_SPHINCS_DESC    	"sphincs Lattice-Based Crypto Scheme"

# define OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_OID "1.3.9999.6.4.13"
# define OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_NAME "sphincssha2128fsimple"
# define OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_DESC "sphincs128f"

# define OPENCA_ALG_PKEY_PQC_SPHINCS128_S_SIMPLE_OID "1.3.9999.6.4.16"
# define OPENCA_ALG_PKEY_PQC_SPHINCS128_S_SIMPLE_NAME "sphincs128s"
# define OPENCA_ALG_PKEY_PQC_SPHINCS128_S_SIMPLE_DESC "sphincs128s"

# define OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_OID "1.3.9999.6.5.10"
# define OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_NAME "sphincssha2192fsimple"
# define OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_DESC "sphincs192f"

// PKEY - PQC - KYBER

# define OPENCA_ALG_PKEY_PQC_KYBER512_OID    	OPENCA_ALG_PKEY_PQC_OID ".50"
# define OPENCA_ALG_PKEY_PQC_KYBER512_NAME      "Kyber512"
# define OPENCA_ALG_PKEY_PQC_KYBER512_DESC      "Kyber512"

# define OPENCA_ALG_PKEY_PQC_KYBER768_OID    	OPENCA_ALG_PKEY_PQC_OID ".51"
# define OPENCA_ALG_PKEY_PQC_KYBER768_NAME      "Kyber768"
# define OPENCA_ALG_PKEY_PQC_KYBER768_DESC      "Kyber768"

# define OPENCA_ALG_PKEY_PQC_KYBER1024_OID    	OPENCA_ALG_PKEY_PQC_OID ".52"
# define OPENCA_ALG_PKEY_PQC_KYBER1024_NAME     "Kyber1024"
# define OPENCA_ALG_PKEY_PQC_KYBER1024_DESC     "Kyber1024"

// ====================
// Composite Signatures
// ====================

// PKEY - COMPOSITE

# define OPENCA_ALG_SIGS_COMP_OID		        OPENCA_ALG_SIGS_OID ".1"
// # define OPENCA_ALG_SIGS_COMP_OID		        OPENCA_ALG_OID ".1"
// # define OPENCA_ALG_SIGS_COMP_OID		        OPENCA_ALG_PKEY_EXP_COMP_OID
# define OPENCA_ALG_SIGS_COMP_DESC		        "CompositeWithNoHash"
# define OPENCA_ALG_SIGS_COMP_NAME		        "COMPOSITE-NULL"

# define OPENCA_ALG_SIGS_COMP_SHA1_OID	        OPENCA_ALG_SIGS_COMP_OID ".1"
# define OPENCA_ALG_SIGS_COMP_SHA1_DESC		    "CompositeWithSha1"
# define OPENCA_ALG_SIGS_COMP_SHA1_NAME		    "COMPOSITE-SHA1"

# define OPENCA_ALG_SIGS_COMP_SHA256_OID	    OPENCA_ALG_SIGS_COMP_OID ".2"
# define OPENCA_ALG_SIGS_COMP_SHA256_DESC		"CompositeWithSha256"
# define OPENCA_ALG_SIGS_COMP_SHA256_NAME		"COMPOSITE-SHA256"

# define OPENCA_ALG_SIGS_COMP_SHA384_OID	    OPENCA_ALG_SIGS_COMP_OID ".3"
# define OPENCA_ALG_SIGS_COMP_SHA384_DESC		"CompositeWithSha384"
# define OPENCA_ALG_SIGS_COMP_SHA384_NAME		"COMPOSITE-SHA384"

# define OPENCA_ALG_SIGS_COMP_SHA512_OID	    OPENCA_ALG_SIGS_COMP_OID ".4"
# define OPENCA_ALG_SIGS_COMP_SHA512_DESC		"CompositeWithSha512"
# define OPENCA_ALG_SIGS_COMP_SHA512_NAME		"COMPOSITE-SHA512"

# define OPENCA_ALG_SIGS_COMP_SHA3_256_OID	    OPENCA_ALG_SIGS_COMP_OID ".5"
# define OPENCA_ALG_SIGS_COMP_SHA3_256_DESC		"CompositeWithSha3At256"
# define OPENCA_ALG_SIGS_COMP_SHA3_256_NAME		"COMPOSITE-SHA3_256"

# define OPENCA_ALG_SIGS_COMP_SHA3_384_OID	    OPENCA_ALG_SIGS_COMP_OID ".6"
# define OPENCA_ALG_SIGS_COMP_SHA3_384_DESC		"CompositeWithSha3At384"
# define OPENCA_ALG_SIGS_COMP_SHA3_384_NAME		"COMPOSITE-SHA3_384"

# define OPENCA_ALG_SIGS_COMP_SHA3_512_OID	    OPENCA_ALG_SIGS_COMP_OID ".7"
# define OPENCA_ALG_SIGS_COMP_SHA3_512_DESC		"CompositeWithSha3At512"
# define OPENCA_ALG_SIGS_COMP_SHA3_512_NAME		"COMPOSITE-SHA3_512"

# define OPENCA_ALG_SIGS_COMP_SHAKE128_OID	    OPENCA_ALG_SIGS_COMP_OID ".8"
# define OPENCA_ALG_SIGS_COMP_SHAKE128_DESC		"CompositeWithShake128"
# define OPENCA_ALG_SIGS_COMP_SHAKE128_NAME		"COMPOSITE-SHAKE128"

# define OPENCA_ALG_SIGS_COMP_SHAKE256_OID	    OPENCA_ALG_SIGS_COMP_OID ".9"
# define OPENCA_ALG_SIGS_COMP_SHAKE256_DESC		"CompositeWithShake256"
# define OPENCA_ALG_SIGS_COMP_SHAKE256_NAME		"COMPOSITE-SHAKE256"

// // ======================
// // Alternative Signatures
// // ======================

// // PKEY - MULTIKEY
// // # define OPENCA_ALG_SIGS_ALT_OID		            OPENCA_ALG_SIGS_OID ".2"
// # define OPENCA_ALG_SIGS_ALT_OID		            OPENCA_ALG_OID ".2"
// # define OPENCA_ALG_SIGS_ALT_DESC		            "MultikeyWithNoHash"
// # define OPENCA_ALG_SIGS_ALT_NAME		            "MULTIKEY-NULL"

// # define OPENCA_ALG_SIGS_ALT_SHA1_OID		        OPENCA_ALG_SIGS_ALT_OID ".1"
// # define OPENCA_ALG_SIGS_ALT_SHA1_DESC		        "MultikeyWithSha1"
// # define OPENCA_ALG_SIGS_ALT_SHA1_NAME		        "MULTIKEY-SHA1"

// # define OPENCA_ALG_SIGS_ALT_SHA256_OID		        OPENCA_ALG_SIGS_ALT_OID ".2"
// # define OPENCA_ALG_SIGS_ALT_SHA256_DESC		    "MultikeyWithSha256"
// # define OPENCA_ALG_SIGS_ALT_SHA256_NAME		    "MULTIKEY-SHA256"

// # define OPENCA_ALG_SIGS_ALT_SHA384_OID		        OPENCA_ALG_SIGS_ALT_OID ".3"
// # define OPENCA_ALG_SIGS_ALT_SHA384_DESC		    "MultikeyWithSha384"
// # define OPENCA_ALG_SIGS_ALT_SHA384_NAME		    "MULTIKEY-SHA384"

// # define OPENCA_ALG_SIGS_ALT_SHA512_OID		        OPENCA_ALG_SIGS_ALT_OID ".4"
// # define OPENCA_ALG_SIGS_ALT_SHA512_DESC		    "MultikeyWithSha512"
// # define OPENCA_ALG_SIGS_ALT_SHA512_NAME		    "MULTIKEY-SHA512"

// # define OPENCA_ALG_SIGS_ALT_SHA3_256_OID		    OPENCA_ALG_SIGS_ALT_OID ".5"
// # define OPENCA_ALG_SIGS_ALT_SHA3_256_DESC		    "MultikeyWithSha3At256"
// # define OPENCA_ALG_SIGS_ALT_SHA3_256_NAME		    "MULTIKEY-SHA3_256"

// # define OPENCA_ALG_SIGS_ALT_SHA3_384_OID		    OPENCA_ALG_SIGS_ALT_OID ".6"
// # define OPENCA_ALG_SIGS_ALT_SHA3_384_DESC		    "MultikeyWithSha3At384"
// # define OPENCA_ALG_SIGS_ALT_SHA3_384_NAME		    "MULTIKEY-SHA3_384"

// # define OPENCA_ALG_SIGS_ALT_SHA3_512_OID		    OPENCA_ALG_SIGS_ALT_OID ".7"
// # define OPENCA_ALG_SIGS_ALT_SHA3_512_DESC		    "MultikeyWithSha3At512"
// # define OPENCA_ALG_SIGS_ALT_SHA3_512_NAME		    "MULTIKEY-SHA3_512"

// # define OPENCA_ALG_SIGS_ALT_SHAKE128_OID		    OPENCA_ALG_SIGS_ALT_OID ".8"
// # define OPENCA_ALG_SIGS_ALT_SHAKE128_DESC		    "MultikeyWithShake128"
// # define OPENCA_ALG_SIGS_ALT_SHAKE128_NAME		    "MULTIKEY-SHAKE128"

// # define OPENCA_ALG_SIGS_ALT_SHAKE256_OID		    OPENCA_ALG_SIGS_ALT_OID ".9"
// # define OPENCA_ALG_SIGS_ALT_SHAKE256_DESC		    "MultikeyWithShake256"
// # define OPENCA_ALG_SIGS_ALT_SHAKE256_NAME		    "MULTIKEY-SHAKE256"

// =======================
// Experimental
// =======================

// SIGS - EXP
# define OPENCA_ALG_SIGS_EXP_OID                        OPENCA_ALG_SIGS_OID ".998"

// SIGS - EXP - DILITHIUM
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX_OID             OPENCA_ALG_SIGS_EXP_OID ".1"

// SIGS - EXP - DILITHIUM - DILITHIUMX
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID            OPENCA_ALG_SIGS_EXP_DILITHIUMX_OID ".1"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_DESC           "DilithiumX3NoHash"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_NAME           "DILITHIUMX3-NULL"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_OID     OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".2"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_DESC    "DilithiumX3WithSha256"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_NAME    "DILITHIUMX3-SHA256"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_OID     OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".3"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_DESC    "DilithiumX3WithSha384"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_NAME    "DILITHIUMX3-SHA384"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_OID     OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".4"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_DESC    "DilithiumX3WithSha512"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_NAME    "DILITHIUMX3-SHA512"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_OID   OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".5"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_DESC  "DilithiumX3WithSha3At256"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_NAME  "DILITHIUMX3-SHA3_256"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_OID   OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".6"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_DESC  "DilithiumX3WithSha3At384"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_NAME  "DILITHIUMX3-SHA3_384"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_OID   OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".7"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_DESC  "DilithiumX3WithSha3At512"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_NAME  "DILITHIUMX3-SHA3_512"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_OID   OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".8"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_DESC  "DilithiumX3WithShake128"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_NAME  "DILITHIUMX3-SHAKE128"

# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_OID   OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID ".9"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_DESC  "DilithiumX3WithShake256"
# define OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_NAME  "DILITHIUMX3-SHAKE256"

// =======================
// Post-Quantum Signatures
// =======================

// # define OPENCA_ALG_SIGS_PQC_OID                        OPENCA_ALG_SIGS_OID ".999"
# define OPENCA_ALG_SIGS_PQC_OID                        OPENCA_OID ".999"

// Dilithium3 and Dilithium5
// -------------------------
# define OPENCA_ALG_SIGS_PQC_DILITHIUM_OID              OPENCA_ALG_SIGS_PQC_OID ".1"

// Dilithium Level 3

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID         OPENCA_ALG_SIGS_PQC_DILITHIUM_OID ".1"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_OID             "1.3.6.1.4.1.2.267.7.4.4"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_DESC            "Dilithium2" "WithNoHash"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_NAME            "Dilithium2"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA256_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".1"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA256_DESC     "Dilithium2" "WithSha256"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA256_NAME     "DILITHIUM2-SHA256"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA384_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".2"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA384_DESC     "Dilithium2" "WithSha384"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA384_NAME     "DILITHIUM2-SHA384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA512_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".3"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA512_DESC     "Dilithium2" "WithSha512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA512_NAME     "DILITHIUM2-SHA512"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".4"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_256_DESC   "Dilithium2" "WithSha3At256"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_256_NAME   "DILITHIUM2-SHA3_256"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_384_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".5"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_384_DESC   "Dilithium2" "WithSha3At384"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_384_NAME   "DILITHIUM2-SHA3_384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_512_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".6"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_512_DESC   "Dilithium2" "WithSha3At512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHA3_512_NAME   "DILITHIUM2-SHA3_512"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE128_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".7"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE128_DESC   "Dilithium2" "WithShake128"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE128_NAME   "DILITHIUM2-SHAKE128"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM2_EXT_OID ".8"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE256_DESC   "Dilithium2" "WithShake256"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM2_SHAKE256_NAME   "DILITHIUM2-SHAKE256"

// Dilithium Level 3

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID         OPENCA_ALG_SIGS_PQC_DILITHIUM_OID ".2"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_OID             "1.3.6.1.4.1.2.267.7.6.5"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_DESC            "Dilithium3"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_NAME            "Dilithium3"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".1"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_DESC     "Dilithium3" "WithSha256"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_NAME     "DILITHIUM3-SHA256"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".2"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_DESC     "Dilithium3" "WithSha384"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_NAME     "DILITHIUM3-SHA384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".3"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_DESC     "Dilithium3" "WithSha512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_NAME     "DILITHIUM3-SHA512"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".4"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_DESC   "Dilithium3" "WithSha3At256"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_NAME   "DILITHIUM3-SHA3_256"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".5"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_DESC   "Dilithium3" "WithSha3At384"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_NAME   "DILITHIUM3-SHA3_384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".6"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_DESC   "Dilithium3" "WithSha3At512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_NAME   "DILITHIUM3-SHA3_512"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".7"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_DESC   "Dilithium3" "WithShake128"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_NAME   "DILITHIUM3-SHAKE128"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM3_EXT_OID ".8"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_DESC   "Dilithium3" "WithShake256"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_NAME   "DILITHIUM3-SHAKE256"

// Dilithium Level 5

# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID         OPENCA_ALG_SIGS_PQC_DILITHIUM_OID ".3"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_OID             "1.3.6.1.4.1.2.267.7.8.7"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_DESC            "Dilithium5" "WithNoHash"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_NAME            "DILITHIUM5"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".1"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_DESC     "Dilithium5" "WithSha256"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_NAME     "DILITHIUM5-SHA256"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".2"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_DESC     "Dilithium5" "WithSha384"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_NAME     "DILITHIUM5-SHA384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_OID      OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".3"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_DESC     "Dilithium5" "WithSha512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_NAME     "DILITHIUM5-SHA512"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".4"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_DESC   "Dilithium5" "WithSha3At256"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_NAME   "DILITHIUM5-SHA3_256"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".5"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_DESC   "Dilithium5" "WithSha3At384"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_NAME   "DILITHIUM5-SHA3_384"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".6"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_DESC   "Dilithium5" "WithSha3At512"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_NAME   "DILITHIUM5-SHA3_512"

// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".7"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_DESC   "Dilithium5" "WithShake128"
// # define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_NAME   "DILITHIUM5-SHAKE128"

# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_OID    OPENCA_ALG_SIGS_PQC_DILITHIUM5_EXT_OID ".8"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_DESC   "Dilithium5" "WithShake256"
# define OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_NAME   "DILITHIUM5-SHAKE256"

// Falcon512 and Falcon1024
// ------------------------

# define OPENCA_ALG_SIGS_PQC_FALCON_OID                 OPENCA_ALG_SIGS_PQC_OID ".2"

// Falcon Level 512

# define OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID          OPENCA_ALG_SIGS_PQC_FALCON_OID ".1"

# define OPENCA_ALG_SIGS_PQC_FALCON512_OID              "1.3.9999.3.6"
# define OPENCA_ALG_SIGS_PQC_FALCON512_DESC             "Falcon512"
# define OPENCA_ALG_SIGS_PQC_FALCON512_NAME             "Falcon512" // Was "Falcon-512"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_OID       OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".1.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_DESC      "Falcon512WithSha256"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_NAME      "FALCON512-SHA256"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_OID       OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".2.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_DESC      "Falcon512WithSha384"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_NAME      "FALCON512-SHA384"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_OID       OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".3.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_DESC      "Falcon512WithSha512"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_NAME      "FALCON512-SHA512"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_OID     OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".4.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_DESC    "Falcon512WithSha3At256"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_NAME    "FALCON512-SHA3_256"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_OID     OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".5.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_DESC    "Falcon512WithSha3At384"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_NAME    "FALCON512-SHA3_384"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_OID     OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".6.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_DESC    "Falcon512WithSha3At512"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_NAME    "FALCON512-SHA3_512"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_OID     OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".7.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_DESC    "Falcon512WithShake128"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_NAME    "FALCON512-SHAKE128"

# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_OID     OPENCA_ALG_SIGS_PQC_FALCON512_EXT_OID ".8.1"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_DESC    "Falcon512WithShake256"
# define OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_NAME    "FALCON512-SHAKE256"

// Falcon Level 1024

# define OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID         OPENCA_ALG_SIGS_PQC_FALCON_OID ".2"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_OID             "1.3.9999.3.9"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_NAME            "Falcon1024WithNoHash"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_DESC            "FALCON1024"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_OID      OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".1.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_DESC     "Falcon1024WithSha256"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_NAME     "FALCON1024-SHA256"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_OID      OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".2.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_DESC     "Falcon1024WithSha384"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_NAME     "FALCON1024-SHA384"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_OID      OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".3.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_DESC     "Falcon1024WithSha512"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_NAME     "FALCON1024-SHA512"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_OID    OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".4.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_DESC   "Falcon1024WithSha3At256"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_NAME   "FALCON1024-SHA3_256"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_OID    OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".5.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_DESC   "Falcon1024WithSha3At384"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_NAME   "FALCON1024-SHA3_384"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_OID    OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".6.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_DESC   "Falcon1024WithSha3At512"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_NAME   "FALCON1024-SHA3_512"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_OID    OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".7.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_DESC   "Falcon1024WithShake128"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_NAME   "FALCON1024-SHAKE128"

# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_OID    OPENCA_ALG_SIGS_PQC_FALCON1024_EXT_OID ".8.1"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_DESC   "Falcon1024WithShake256"
# define OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_NAME   "FALCON1024-SHAKE256"

// Sphincs+ 128 and Sphincs+ 192
// -----------------------------

# define OPENCA_ALG_SIGS_PQC_SPHINCS_F_SIMPLE_OID       OPENCA_ALG_SIGS_PQC_OID ".3"

// Sphincs+ 128

# define OPENCA_ALG_SIGS_PQC_SPHINCS128_F_SIMPLE_EXT_OID   OPENCA_ALG_SIGS_PQC_SPHINCS_F_SIMPLE_OID ".1"

# define OPENCA_ALG_SIGS_PQC_SPHINCS128_F_SIMPLE_OID    "1.3.9999.6.4.13"
# define OPENCA_ALG_SIGS_PQC_SPHINCS128_F_SIMPLE_NAME   "Sphincs128FWithNoHash"
# define OPENCA_ALG_SIGS_PQC_SPHINCS128_F_SIMPLE_DESC   "SPHINCS128F"

// Sphincs+ 192

# define OPENCA_ALG_SIGS_PQC_SPHINCS192_F_SIMPLE_EXT_OID   OPENCA_ALG_SIGS_PQC_SPHINCS_F_SIMPLE_OID ".2"

# define OPENCA_ALG_SIGS_PQC_SPHINCS192_F_SIMPLE_OID    "1.3.9999.6.5.10"
# define OPENCA_ALG_SIGS_PQC_SPHINCS192_F_SIMPLE_NAME   "Sphincs192FWithNoHash"
# define OPENCA_ALG_SIGS_PQC_SPHINCS192_F_SIMPLE_DESC   "SPHINCS192F"

// =======
// Aliases
// =======

// Composite Key Alias
# define OPENCA_ALG_PKEY_EXP_COMP_OID_ENTRUST           OPENCA_ALG_PKEY_EXP_COMP_OID                    
# define OPENCA_ALG_PKEY_EXP_COMP_DESC_ENTRUST          OPENCA_ALG_PKEY_EXP_COMP_NAME
# define OPENCA_ALG_PKEY_EXP_COMP_NAME_ENTRUST          OPENCA_ALG_PKEY_EXP_COMP_DESC

// Explicit Composite Key Alias

#define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID                            "2.16.840.1.114027.80.5.1"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID            OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_DESC           "id-Dilithium3-RSA-PKCS15-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME           "DILITHIUM3-RSA-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID           OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".2"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_DESC          "id-Dilithium3-ECDSA-P256-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME          "DILITHIUM3-P256-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID   OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".3"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_DESC  "id-Dilithium3-ECDSA-BrainpoolP256r1-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME  "DILITHIUM3-BRAINPOOL256-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID        OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".4"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_DESC       "id-Dilithium3-Ed25519"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME       "DILITHIUM3-ED25519"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID           OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".5"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_DESC          "id-Dilithium5-ECDSA-P384-SHA384"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME          "DILITHIUM5-P384-SHA384"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID   OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".6"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_DESC  "id-Dilithium5-ECDSA-BrainpoolP384r1-SHA384"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME  "DILITHIUM5-BRAINPOOL384-SHA384"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID          OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".7"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_DESC         "id-Dilithium5-Ed448"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME         "DILITHIUM5-ED448"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID            OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".8.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_DESC           "id-Falcon512-P256-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME           "FALCON512-P256-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".9.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_DESC   "id-Falcon512-Brainpool256r1-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME   "FALCON512-BRAINPOOL256-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID         OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".10.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_DESC        "id-Falcon512-Ed25519"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME        "FALCON512-ED25519"

// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID           OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".11"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_DESC          "id-Sphincs256-ECDSA-P256-SHA256"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME          "SPHINCS256-P256-SHA256"

// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID   OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".12"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_DESC  "id-Sphincs256-ECDSA-BrainpoolP256r1-SHA256"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME  "SPHINCS256-BRAINPOOL256-SHA256"

// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID        OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".13"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_DESC       "id-Sphincs256-Ed25519"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME       "SPHINCS256-ED25519"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID         OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".14"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_DESC        "id-Dilithium3-RSAPSS-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME        "DILITHIUM3-RSAPSS-SHA256"

// Non-ID Combinations
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID             OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".20.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_DESC            "id-Falcon512-RSA-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME            "FALCON512-RSA-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID    OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".21.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_DESC   "id-Dilithium5-Falcon1024-P521-SHA512"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME   "DILITHIUM5-FALCON1024-P512-SHA512"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_OID     OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".22.1"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_DESC    "id-Dilithium5-Falcon1024-RSA-SHA256"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME    "DILITHIUM5-FALCON1024-RSA-SHA256"

// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_OID            OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_OID ".30"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_DESC           "id-Sphincs256-RSA-SHA256"
// # define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_NAME           "SPHINCS256-RSA-SHA256"

# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_KEMKEY_OID                    "2.16.840.1.114027.80.999"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_KEMKEY_DESC                   "id-Composite-KEM"
# define OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_KEMKEY_NAME                   "COMPOSITE-KEM"

// // Explicit Composite Signatures

// #define OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID                     "2.16.840.1.114027.80.5.3"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_RSA_SHA256_OID            OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".1"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_RSA_SHA256_DESC           "Sha256WithDilithium3AndRSA"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_RSA_SHA256_NAME           "DILITHIUM3-RSA-SHA256"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ECDSA_SHA256_OID          OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".2"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ECDSA_SHA256_DESC         "Sha256WithDilithium3AndECDSA"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ECDSA_SHA256_NAME         "DILITHIUM3-SHA256-ECDSA"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ED25519_OID               OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".4"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ED25519_DESC              "Dilithium3AndEd25519"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM3_ED25519_NAME              "DILITHIUM3-ED25519-NULL"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ECDSA_SHA384_OID          OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".5"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ECDSA_SHA384_DESC         "Sha384WithDilithium5AndECDSA"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ECDSA_SHA384_NAME         "DILITHIUM5-P384-SHA384"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_BRAINPOOL384_SHA384_OID   OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".6"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_BRAINPOOL384_SHA384_DESC  "Sha384WithDilithium5AndECDSA"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_BRAINPOOL384_SHA384_NAME  "DILITHIUM5-BRAINPOOL384-SHA384"

// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ED448_OID                 OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".7"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ED448_DESC                "Dilithium5-Ed448"
// # define OPENCA_ALG_SIGS_EXP_DILITHIUM5_ED448_NAME                "DILITHIUM5-ED448-NULL"

// # define OPENCA_ALG_SIGS_EXP_FALCON512_SHA256_ECDSA_OID           OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".8"
// # define OPENCA_ALG_SIGS_EXP_FALCON512_SHA256_ECDSA_DESC          "Sha256WithFalcon512AndECDSA"
// # define OPENCA_ALG_SIGS_EXP_FALCON512_SHA256_ECDSA_NAME          "FALCON512-ECDSA-SHA256"

// # define OPENCA_ALG_SIGS_EXP_FALCON512_ED25519_OID                OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".10"
// # define OPENCA_ALG_SIGS_EXP_FALCON512_ED25519_DESC               "Falcon512-ED25519"
// # define OPENCA_ALG_SIGS_EXP_FALCON512_ED25519_NAME               "FALCON512-ED25519-NULL"

// # define OPENCA_ALG_SIGS_EXP_SPHINCS256_SHA256_ECDSA_OID          OPENCA_ALG_SIGS_EXP_COMP_EXPLICIT_OID ".11"
// # define OPENCA_ALG_SIGS_EXP_SPHINCS256_SHA256_ECDSA_DESC         "Sha256WithSphincs256sAndECDSA"
// # define OPENCA_ALG_SIGS_EXP_SPHINCS256_SHA256_ECDSA_NAME         "SPHINCS256-SHA256-ECDSA"

END_C_DECLS

#endif // End of _LIBPKI_POST_QUANTUM_SIGS_H
