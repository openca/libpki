/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_KMF_HEADER_DATA_ST_H
#define _LIBPKI_KMF_HEADER_DATA_ST_H

#include <kmfapi.h>

typedef struct kmf_pkey_st {
	KMF_KEY_HANDLE *priv_key;
	KMF_KEY_HANDLE *pub_key;
	char *tmp_name;
} PKI_KMF_KEYPAIR;

typedef struct kmf_engine_st {
	KMF_STORECERT_PARAMS  scert_params;
	KMF_FINDCERT_PARAMS   fcert_params;
	KMF_DELETECERT_PARAMS dcert_params;
	KMF_IMPORTCERT_PARAMS icert_params;
	
	KMF_STOREKEY_PARAMS   skey_params;
	KMF_FINDKEY_PARAMS    fkey_params;
	KMF_DELETEKEY_PARAMS  dkey_params;

} PKI_KMF_ENGINE;

typedef struct KMF_ALGORITHM_INDEX PKI_DIGEST_ALGOR;
typedef struct KMF_ALGORITHM_INDEX PKI_ALGOR;
typedef struct KMF_X509_NAME PKI_X509_NAME;

#define PKI_KMF_DIGEST_ALG_NULL  	KMF_ALGID_NONE
#define PKI_KMF_DIGEST_ALG_SHA1	KMF_ALGID_SHA1
#define PKI_KMF_DIGEST_ALG_MD5	KMF_ALGID_MD5

#define PKI_KMF_ALGOR_NULL  	KMF_ALGID_NONE
#define PKI_KMF_ALGOR_UNKNOWN       KMF_ALGID_CUSTOM
#define PKI_KMF_ALGOR_RSA_MD5       KMF_ALGID_MD5WithRSA
#define PKI_KMF_ALGOR_RSA_MD2       KMF_ALGID_MD2WithRSA
#define PKI_KMF_ALGOR_RSA_SHA1      KMF_ALGID_SHA1WithRSA
#define PKI_KMF_ALGOR_DSA_SHA1      KMF_ALGID_SHA1WithDSA

#define PKI_KMF_ALGOR_ECDSA_SHA1    KMF_ALGOID_UNKNOWN

#define PKI_KMF_OID			KMF_OID
#define PKI_KMF_X509_EXTENSION	KMF_X509_EXTENSION

typedef struct _libpki_kmf_cert_st {
	int is_signed;

	KMF_X509_CERTIFICATE *tbs;
	KMF_DATA *data;
} PKI_KMF_X509_CERT;

// typedef struct KMF_X509_CERTIFICATE PKI_X509;

typedef struct _libpki_kmf_csr_st {
	int is_signed;

	KMF_CSR_DATA	*tbs;
	KMF_DATA	*data;
} PKI_KMF_X509_REQ;

// typedef struct X509_CRL PKI_X509_CRL;

typedef struct pki_kmf_store_st {
	// KMF_HANDLE_T 	store_ptr;
	void * 	store_ptr;
} PKI_KMF_STORE;

/* 
#include <libpki/hsm_st.h>
#include <libpki/token_st.h>
*/

/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
