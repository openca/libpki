/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_HEADER_OPENSSL_DATA_ST_H
#define _LIBPKI_HEADER_OPENSSL_DATA_ST_H

#include <openssl/engine.h>

/*
typedef struct ENGINE 		PKI_OPENSSL_ENGINE;
typedef struct EVP_PKEY 	PKI_OPENSSL_KEYPAIR;

#define  PKI_OPENSSL_DIGEST_ALG		EVP_MD
#define	 PKI_OPENSSL_ALGOR 		X509_ALGOR

// typedef struct X509_NAME 	PKI_X509_NAME;
#define PKI_OPENSSL_X509_NAME		X509_NAME

#define PKI_OPENSSL_DIGEST_ALG_NULL  	NULL
#define PKI_OPENSSL_DIGEST_ALG_SHA1	EVP_sha1()
#define PKI_OPENSSL_DIGEST_ALG_MD5	EVP_md5()
#define PKI_OPENSSL_DIGEST_ALG_MD2	EVP_md2()
#ifdef ENABLE_ECDSA
#define PKI_OPENSSL_DIGEST_ALG_DSS1	EVP_dss1()
#else
#define PKI_OPENSSL_DIGEST_ALG_DSS1	NULL
#endif

#define PKI_OPENSSL_ALGOR_UNKNOWN	NID_undef
#define PKI_OPENSSL_ALGOR_RSA_MD5	NID_md5WithRSAEncryption
#define PKI_OPENSSL_ALGOR_RSA_MD2	NID_md2WithRSAEncryption
#define PKI_OPENSSL_ALGOR_RSA_SHA1	NID_sha1WithRSAEncryption
#define PKI_OPENSSL_ALGOR_DSA_SHA1	NID_dsaWithSHA1_2
#ifdef ENABLE_ECDSA
#define PKI_OPENSSL_ALGOR_ECDSA_SHA1	NID_ecdsa_with_SHA1
#else
#define PKI_OPENSSL_ALGOR_ECDSA_SHA1	NID_undef
#endif

#define PKI_OPENSSL_OID			ASN1_OBJECT
#define PKI_OPENSSL_X509_EXTENSION	X509_EXTENSION

typedef int			PKI_OPENSSL_ALGOR_ID;
typedef struct X509 		PKI_OPENSSL_X509_CERT;
typedef struct X509_REQ 	PKI_OPENSSL_X509_REQ;
typedef struct X509_CRL 	PKI_OPENSSL_X509_CRL;
*/

typedef struct pki_openssl_store_st {
        void	*store_ptr;
} PKI_OPENSSL_STORE;

/*
#include <libpki/hsm_st.h>
#include <libpki/token_st.h>
*/

/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
