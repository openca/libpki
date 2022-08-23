/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_HEADER_DATA_ST_H
#define _LIBPKI_HEADER_DATA_ST_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/ocsp.h>
#include <openssl/objects.h>
#include <openssl/hmac.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/cms.h>

#ifdef ENABLE_ECDSA
#include <openssl/ec.h>
#endif

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
# define DECLARE_STACK_OF DEFINE_STACK_OF
#endif

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

// EVP_MD_CTX Interface
# define EVP_MD_CTX_new EVP_MD_CTX_create
# define EVP_MD_CTX_free EVP_MD_CTX_destroy
# define EVP_MD_CTX_reset EVP_MD_CTX_cleanup

// HMAC Interface
# define HMAC_CTX_reset HMAC_CTX_cleanup
#endif

typedef ASN1_BIT_STRING	PKI_X509_SIGNATURE;

/* Some useful Key definitions */
#define PKI_RSA_KEY		RSA
#define PKI_DSA_KEY		DSA

#ifdef ENABLE_ECDSA
#define PKI_EC_KEY		EC_KEY
#endif

#define  PKI_ID						int
#define  PKI_ID_UNKNOWN		NID_undef

#define  PKI_DIGEST_ALG				EVP_MD
// #define	 PKI_ALGOR        X509_ALGOR
// #define	 PKI_ALGORITHM		X509_ALGOR
#define  PKI_X509_ALGOR_VALUE X509_ALGOR
#define  PKI_CIPHER       		EVP_CIPHER

#define PKI_X509_NAME		X509_NAME

#define PKI_DIGEST_ALG_NULL  	(PKI_DIGEST_ALG *) NULL
#define PKI_DIGEST_ALG_UNKNOWN 	(PKI_DIGEST_ALG *) NULL

// #define PKI_ALGOR_MD2		NID_md2
// #define PKI_DIGEST_ALG_MD2	(PKI_DIGEST_ALG *) EVP_md2()
#ifndef OPENSSL_FIPS
#ifdef NID_md4
#define ENABLE_MD4
#define PKI_ALGOR_MD4       NID_md4
#define PKI_ALGOR_ID_MD4    NID_md4
#define PKI_DIGEST_ALG_MD4	(PKI_DIGEST_ALG *) EVP_md4()
#else
#define PKI_ALGOR_MD4       NID_undef
#define PKI_ALGOR_ID_MD4    NID_undef
#define PKI_DIGEST_ALG_MD4	(PKI_DIGEST_ALG *) NULL;
#endif
#endif // FIPS_MODE

// Support for MD5
#ifdef NID_md5
#define ENABLE_MD5
#define PKI_ALGOR_MD5		    NID_md5
#define PKI_ALGOR_ID_MD5		NID_md5
#define PKI_DIGEST_ALG_MD5	(PKI_DIGEST_ALG *) EVP_md5()
#else
#define PKI_ALGOR_MD5       NID_undef
#define PKI_ALGOR_ID_MD5    NID_undef
#define PKI_DIGEST_ALG_MD5  (PKI_DIGEST_ALG *) NULL
#endif
#define PKI_DIGEST_ALG_MD5_SIZE 16

// Support for SHA1
#ifdef NID_sha1
#define ENABLE_SHA1
#define PKI_ALGOR_SHA1		  NID_sha1
#define PKI_ALGOR_ID_SHA1		NID_sha1
#define PKI_DIGEST_ALG_SHA1	(PKI_DIGEST_ALG *) EVP_sha1()
#else
#define PKI_ALGOR_SHA1      NID_undef
#define PKI_ALGOR_ID_SHA1   NID_undef
#define PKI_DIGEST_ALG_SHA1 (PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_SHA1_SIZE	20

// Support for SHA-224
#ifdef NID_sha224
#define ENABLE_SHA_2
#define ENABLE_SHA224
#define PKI_ALGOR_SHA224	    NID_sha224
#define PKI_ALGOR_ID_SHA224	  NID_sha224
#define PKI_DIGEST_ALG_SHA224	(PKI_DIGEST_ALG *) EVP_sha224()
#else
#define PKI_ALGOR_SHA224	    NID_undef
#define PKI_ALGOR_ID_SHA224	  NID_undef
#define PKI_DIGEST_ALG_SHA224	(PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_SHA224_SIZE	28

// Support for SHA-256
#ifdef NID_sha256
#define ENABLE_SHA256
#define PKI_ALGOR_SHA256	    NID_sha256
#define PKI_ALGOR_ID_SHA256	  NID_sha256
#define PKI_DIGEST_ALG_SHA256	(PKI_DIGEST_ALG *) EVP_sha256()
#else
#define PKI_ALGOR_SHA256	    NID_undef
#define PKI_ALGOR_ID_SHA256	  NID_undef
#define PKI_DIGEST_ALG_SHA256	(PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_SHA256_SIZE	32

// Support for SHA-384
#ifdef NID_sha384
#define ENABLE_SHA384
#define PKI_ALGOR_SHA384	    NID_sha384
#define PKI_ALGOR_ID_SHA384   NID_sha384
#define PKI_DIGEST_ALG_SHA384	(PKI_DIGEST_ALG *) EVP_sha384()
#else
#define PKI_ALGOR_SHA384	NID_undef
#define PKI_DIGEST_ALG_SHA384	(PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_SHA384_SIZE	48

// Support for SHA-512
#ifdef NID_sha512
#define ENABLE_SHA512
#define PKI_ALGOR_SHA512	    NID_sha512
#define PKI_ALGOR_ID_SHA512	  NID_sha512
#define PKI_DIGEST_ALG_SHA512	(PKI_DIGEST_ALG *) EVP_sha512()
#else
#define PKI_ALGOR_SHA512	    NID_undef
#define PKI_ALGOR_ID_SHA512	  NID_undef
#define PKI_DIGEST_ALG_SHA512	(PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_SHA512_SIZE	64

#ifdef NID_ripemd128
#define ENABLE_RIPEMD128
#define PKI_ALGOR_RIPEMD128       NID_ripemd128
#define PKI_ALGOR_ID_RIPEMD128    NID_ripemd128
#define PKI_DIGEST_ALG_RIPEMD128  (PKI_DIGEST_ALG *) EVP_ripemd128()
#else
#define PKI_ALGOR_RIPEMD128       NID_undef
#define PKI_ALGOR_ID_RIPEMD128    NID_undef
#define PKI_DIGEST_ALG_RIPEMD128  (PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_RIPEMD128_SIZE   16

#ifdef NID_ripemd160
#define ENABLE_RIPEMD160
#define PKI_ALGOR_RIPEMD160	      NID_ripemd160
#define PKI_ALGOR_ID_RIPEMD160	  NID_ripemd160
#define PKI_DIGEST_ALG_RIPEMD160	(PKI_DIGEST_ALG *) EVP_ripemd160()
#else
#define PKI_ALGOR_RIPEMD160	      NID_undef
#define PKI_ALGOR_ID_RIPEMD160	  NID_undef
#define PKI_DIGEST_ALG_RIPEMD160	(PKI_DIGEST_ALG *) NULL
#endif
#define PKI_ALGOR_RIPEMD160_SIZE	20


#ifdef ENABLE_ECDSA
#define PKI_DIGEST_ALG_ECDSA_SHA1	(PKI_DIGEST_ALG *)EVP_ecdsa()
#define PKI_DIGEST_ALG_ECDSA_DSS1	(PKI_DIGEST_ALG *)EVP_ecdsa()
#else
#define PKI_DIGEST_ALG_ECDSA_DSS1	NULL
#define PKI_DIGEST_ALG_ECDSA_SHA1	NULL
#endif

#define PKI_ALGOR_NULL            NULL

#define PKI_ALGOR_ID              int
#define PKI_ALGOR_ID_UNKNOWN      -1

// #define PKI_ALGOR_RSA_MD2	NID_md2WithRSAEncryption
#define PKI_ALGOR_RSA_MD5     NID_md5WithRSAEncryption
#define PKI_ALGOR_ID_RSA_MD5  NID_md5WithRSAEncryption
#define PKI_ALGOR_RSA_MD4	    NID_md4WithRSAEncryption
#define PKI_ALGOR_ID_RSA_MD4  NID_md4WithRSAEncryption
#define PKI_ALGOR_RSA_SHA1    NID_sha1WithRSAEncryption
#define PKI_ALGOR_ID_RSA_SHA1 NID_sha1WithRSAEncryption

#ifdef NID_sha224WithRSAEncryption
#define ENABLE_RSA_SHA_2
#endif

#ifdef ENABLE_SHA224
#define PKI_ALGOR_RSA_SHA224	  NID_sha224WithRSAEncryption
#define PKI_ALGOR_ID_RSA_SHA224	NID_sha224WithRSAEncryption
#else
#define PKI_ALGOR_RSA_SHA224	  NID_undef
#define PKI_ALGOR_ID_RSA_SHA224	NID_undef
#endif

#ifdef ENABLE_SHA256
#define PKI_DIGEST_ALG_RSA_DEFAULT PKI_DIGEST_ALG_SHA256
#define PKI_ALGOR_RSA_SHA256	     NID_sha256WithRSAEncryption
#define PKI_ALGOR_ID_RSA_SHA256	   NID_sha256WithRSAEncryption
#else
#define PKI_DIGEST_ALG_RSA_DEFAULT PKI_DIGEST_ALG_SHA1
#define PKI_ALGOR_RSA_SHA256	     NID_undef
#define PKI_ALGOR_ID_RSA_SHA256	   NID_undef
#endif

#ifdef ENABLE_SHA384
#define PKI_ALGOR_RSA_SHA384	  NID_sha384WithRSAEncryption
#define PKI_ALGOR_ID_RSA_SHA384	NID_sha384WithRSAEncryption
#else
#define PKI_ALGOR_RSA_SHA384	  NID_undef
#define PKI_ALGOR_ID_RSA_SHA384	NID_undef
#endif

#ifdef ENABLE_SHA512
#define PKI_ALGOR_RSA_SHA512	  NID_sha512WithRSAEncryption
#define PKI_ALGOR_ID_RSA_SHA512	NID_sha512WithRSAEncryption
#else
#define PKI_ALGOR_RSA_SHA512	  NID_undef
#define PKI_ALGOR_ID_RSA_SHA512	NID_undef
#endif

#ifdef ENABLE_RIPEMD128
#define PKI_ALGOR_RSA_RIPEMD128    NID_ripemd128WithRSA
#define PKI_ALGOR_ID_RSA_RIPEMD128 NID_ripemd128WithRSA
#else
#define PKI_ALGOR_RSA_RIPEMD128    NID_undef
#define PKI_ALGOR_ID_RSA_RIPEMD128 NID_undef
#endif

#ifdef ENABLE_RIPEMD160
#define PKI_ALGOR_RSA_RIPEMD160	   NID_ripemd160WithRSA
#define PKI_ALGOR_ID_RSA_RIPEMD160 NID_ripemd160WithRSA
#else
#define PKI_ALGOR_RSA_RIPEMD160	    NID_undef
#define PKI_ALGOR_ID_RSA_RIPEMD160	NID_undef
#endif

/* Old DSS1 Algorithm - not needed in OpenSSL v1.0.0+ */
#if OPENSSL_VERSION_NUMBER < 0x1000000fL
#define PKI_ALGOR_DSS1          60000
#define PKI_ALGOR_ID_DSS1       60000
#define PKI_ALGOR_ECDSA_DSS1	  60001
#define PKI_ALGOR_ID_ECDSA_DSS1 60001
#define PKI_DIGEST_ALG_DSS1	    (PKI_DIGEST_ALG *) EVP_dss1()
#else
#define PKI_ALGOR_DSS1          NID_undef
#define PKI_ALGOR_ID_DSS1       NID_undef
#define PKI_ALGOR_ECDSA_DSS1    NID_undef
#define PKI_ALGOR_ID_ECDSA_DSS1 NID_undef
#define PKI_DIGEST_ALG_DSS1     NULL
#endif

/* Begin - NID_dsaWithSHA1 */
#ifdef NID_dsaWithSHA1
#define ENABLE_DSA
#define ENABLE_DSA_SHA_1
#define PKI_ALGOR_DSA_SHA1	  NID_dsaWithSHA1
#define PKI_ALGOR_ID_DSA_SHA1	NID_dsaWithSHA1
#else
#define PKI_ALGOR_DSA_SHA1	  NID_undef
#define PKI_ALGOR_ID_DSA_SHA1	NID_undef
#endif
/* End - NID_dsaWithSHA1 */

/* Begin - NID_dsa_with_SHA224 */
#ifdef NID_dsa_with_SHA224 
#define ENABLE_DSA
#define ENABLE_DSA_SHA224
#define PKI_ALGOR_DSA_SHA224	  NID_dsa_with_SHA224
#define PKI_ALGOR_ID_DSA_SHA224	NID_dsa_with_SHA224
#else
#define PKI_ALGOR_DSA_SHA224	  NID_undef
#define PKI_ALGOR_ID_DSA_SHA224	NID_undef
#endif 
/* End - NID_dsa_with_SHA224 */

/* Begin - NID_dsa_with_SHA256 */
#ifdef NID_dsa_with_SHA256 
#define ENABLE_DSA_SHA256
#define PKI_DIGEST_ALG_DSA_DEFAULT PKI_DIGEST_ALG_SHA256
#define PKI_ALGOR_DSA_SHA256	     NID_dsa_with_SHA256
#define PKI_ALGOR_ID_DSA_SHA256	   NID_dsa_with_SHA256
#else
#define PKI_DIGEST_ALG_DSA_DEFAULT PKI_DIGEST_ALG_SHA1
#define PKI_ALGOR_DSA_SHA256	     NID_undef
#define PKI_ALGOR_ID_DSA_SHA256	   NID_undef
#endif 
/* End - NID_dsa_with_SHA256 */

/* Begin - NID_dsa_with_SHA384 */
#ifdef NID_dsa_with_SHA384
#define ENABLE_DSA_SHA384
#define PKI_ALGOR_DSA_SHA384    NID_dsa_with_SHA384
#define PKI_ALGOR_ID_DSA_SHA384 NID_dsa_with_SHA384
#else
#define PKI_ALGOR_DSA_SHA384    NID_undef
#define PKI_ALGOR_ID_DSA_SHA384 NID_undef
#endif 
/* End - NID_dsa_with_SHA384 */

/* Begin - NID_dsa_with_SHA512 */
#ifdef NID_dsa_with_SHA512 
#define ENABLE_DSA_SHA512
#define PKI_ALGOR_DSA_SHA512    NID_dsa_with_SHA512
#define PKI_ALGOR_ID_DSA_SHA512 NID_dsa_with_SHA512
#else
#define PKI_ALGOR_DSA_SHA512    NID_undef
#define PKI_ALGOR_ID_DSA_SHA512 NID_undef
#endif 
/* End - NID_dsa_with_SHA256 */

/* Begin - NID_ecdsa_with_SHA1 */
#ifdef NID_ecdsa_with_SHA1
#define ENABLE_ECDSA_SHA1
#define PKI_ALGOR_ECDSA_SHA1	  NID_ecdsa_with_SHA1
#define PKI_ALGOR_ID_ECDSA_SHA1 NID_ecdsa_with_SHA1
#else
#define PKI_ALGOR_ECDSA_SHA1	  NID_undef
#define PKI_ALGOR_ID_ECDSA_SHA1 NID_undef
#endif 
/* End - NID_ecdsa_with_SHA1 */

/* Begin - NID_ecdsa_with_224 */
#ifdef NID_ecdsa_with_SHA224
#define ENABLE_ECDSA_SHA_2
#define PKI_ALGOR_ECDSA_SHA224    NID_ecdsa_with_SHA224
#define PKI_ALGOR_ID_ECDSA_SHA224 NID_ecdsa_with_SHA224
#else
#define PKI_ALGOR_ECDSA_SHA224    NID_undef
#define PKI_ALGOR_ID_ECDSA_SHA224 NID_undef
#endif
/* End - NID_ecdsa_with_SHA224 */

/* Begin - NID_ecdsa_with_SHA256 */
#ifdef NID_ecdsa_with_SHA256 
#define PKI_DIGEST_ALG_ECDSA_DEFAULT PKI_DIGEST_ALG_SHA256
#define PKI_ALGOR_ECDSA_SHA256       NID_ecdsa_with_SHA256
#define PKI_ALGOR_ID_ECDSA_SHA256    NID_ecdsa_with_SHA256
#else
#define PKI_DIGEST_ALG_ECDSA_DEFAULT PKI_DIGEST_ALG_DSS1
#define PKI_ALGOR_ECDSA_SHA256	     NID_undef
#define PKI_ALGOR_ID_ECDSA_SHA256	   NID_undef
#endif
/* End - NID_ecdsa_with_SHA256 */

/* Begin - NID_ecdsa_with_384 */
#ifdef NID_ecdsa_with_SHA384
#define PKI_ALGOR_ECDSA_SHA384	  NID_ecdsa_with_SHA384
#define PKI_ALGOR_ID_ECDSA_SHA384	NID_ecdsa_with_SHA384
#else
#define PKI_ALGOR_ECDSA_SHA384	  NID_undef
#define PKI_ALGOR_ID_ECDSA_SHA384	NID_undef
#endif
/* End - NID_ecdsa_with_SHA384 */

/* Begin - NID_ecdsa_with_512 */
#ifdef NID_ecdsa_with_SHA512
#define PKI_ALGOR_ECDSA_SHA512	  NID_ecdsa_with_SHA512
#define PKI_ALGOR_ID_ECDSA_SHA512	NID_ecdsa_with_SHA512
#else
#define PKI_ALGOR_ECDSA_SHA512	  NID_undef
#define PKI_ALGOR_ID_ECDSA_SHA512	NID_undef
#endif
/* End - NID_ecdsa_with_SHA512 */

// ======================= //
// Post Quantum Algorithms //
// ======================= //

/* Begin - NID_falcon512 - open-quantum-safe */
#ifdef NID_falcon512
#define PKI_ALGOR_FALCON512      NID_falcon512
#define PKI_ALGOR_ID_FALCON512   NID_falcon512
#else
#define PKI_ALGOR_FALCON512      NID_undef
#define PKI_ALGOR_ID_FALCON512   NID_undef
#endif
/* End - NID_falcon512 - open-quantum-safe */

/* Begin - NID_falcon512 - open-quantum-safe */
#ifdef NID_falcon1024
#define PKI_ALGOR_FALCON1024     NID_falcon1024
#define PKI_ALGOR_ID_FALCON1024  NID_falcon1024
#else
#define PKI_ALGOR_FALCON1024     NID_undef
#define PKI_ALGOR_ID_FALCON1024  NID_undef
#endif
/* End - NID_falcon512 - open-quantum-safe */

/* Begin - NID_dilithium2 - open-quantum-safe */
#ifdef NID_dilithium2
#define PKI_ALGOR_DILITHIUM2     NID_dilithium2
#define PKI_ALGOR_ID_DILITHIUM2  NID_dilithium2
#else
#define PKI_ALGOR_DILITHIUM2     NID_undef
#define PKI_ALGOR_ID_DILITHIUM2  NID_undef
#endif
/* End - NID_dilithium2 - open-quantum-safe */

/* Begin - NID_dilithium3 - open-quantum-safe */
#ifdef NID_dilithium3
#define PKI_ALGOR_DILITHIUM3     NID_dilithium3
#define PKI_ALGOR_ID_DILITHIUM3  NID_dilithium3
#else
#define PKI_ALGOR_DILITHIUM3     NID_undef
#define PKI_ALGOR_ID_DILITHIUM3  NID_undef
#endif
/* End - NID_dilithium3 - open-quantum-safe */

/* Begin - NID_dilithium5_aes - open-quantum-safe */
#ifdef NID_dilithium5
#define PKI_ALGOR_DILITHIUM5     NID_dilithium5
#define PKI_ALGOR_ID_DILITHIUM5  NID_dilithium5
#else
#define PKI_ALGOR_DILITHIUM5     NID_undef
#define PKI_ALGOR_ID_DILITHIUM5  NID_undef
#endif
/* End - NID_dilithium5 - open-quantum-safe */

/* Begin - NID_dilithium2_aes - open-quantum-safe */
#ifdef NID_dilithium2_aes
#define PKI_ALGOR_DILITHIUM2_AES     NID_dilithium2_aes
#define PKI_ALGOR_ID_DILITHIUM2_AES  NID_dilithium2_aes
#else
#define PKI_ALGOR_DILITHIUM2_AES     NID_undef
#define PKI_ALGOR_ID_DILITHIUM2_AES  NID_undef
#endif
/* End - NID_dilithium2_aes - open-quantum-safe */

/* Begin - NID_dilithium3_aes - open-quantum-safe */
#ifdef NID_dilithium3_aes
#define PKI_ALGOR_DILITHIUM3_AES     NID_dilithium3_aes
#define PKI_ALGOR_ID_DILITHIUM3_AES  NID_dilithium3_aes
#else
#define PKI_ALGOR_DILITHIUM3_AES     NID_undef
#define PKI_ALGOR_ID_DILITHIUM3_AES  NID_undef
#endif
/* End - NID_dilithium3_aes - open-quantum-safe */

/* Begin - NID_dilithium5_aes - open-quantum-safe */
#ifdef NID_dilithium5_aes
#define PKI_ALGOR_DILITHIUM5_AES     NID_dilithium5_aes
#define PKI_ALGOR_ID_DILITHIUM5_AES  NID_dilithium5_aes
#else
#define PKI_ALGOR_DILITHIUM5_AES     NID_undef
#define PKI_ALGOR_ID_DILITHIUM5_AES  NID_undef
#endif
/* End - NID_dilithium5_aes - open-quantum-safe */

/* Begin - NID_sphincssha256128frobust - open-quantum-safe */
#ifdef NID_sphincssha256128frobust
#define PKI_ALGOR_SPHINCS_SHA256_128_R     NID_sphincssha256128frobust
#define PKI_ALGOR_ID_SPHINCS_SHA256_128_R  NID_sphincssha256128frobust
#else
#define PKI_ALGOR_SPHINCS_SHA256_128_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHA256_128_R  NID_undef
#endif
/* End - NID_sphincssha256128frobust - open-quantum-safe */

/* Begin - NID_sphincssha256192frobust - open-quantum-safe */
#ifdef NID_sphincssha256192frobust
#define PKI_ALGOR_SPHINCS_SHA256_192_R     NID_sphincssha256192frobust
#define PKI_ALGOR_ID_SPHINCS_SHA256_192_R  NID_sphincssha256192frobust
#else
#define PKI_ALGOR_SPHINCS_SHA256_192_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHA256_192_R  NID_undef
#endif
/* End - NID_sphincssha256192frobust - open-quantum-safe */

/* Begin - NID_sphincssha256192frobust - open-quantum-safe */
#ifdef NID_sphincssha256256frobust
#define PKI_ALGOR_SPHINCS_SHA256_256_R     NID_sphincssha256256frobust
#define PKI_ALGOR_ID_SPHINCS_SHA256_256_R  NID_sphincssha256256frobust
#else
#define PKI_ALGOR_SPHINCS_SHA256_256_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHA256_256_R  NID_undef
#endif
/* End - NID_sphincssha256192frobust - open-quantum-safe */

/* Begin - NID_sphincsshake256128frobust - open-quantum-safe */
#ifdef NID_sphincsshake256128frobust
#define PKI_ALGOR_SPHINCS_SHAKE256_128_R     NID_sphincsshake256128frobust
#define PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R  NID_sphincsshake256128frobust
#else
#define PKI_ALGOR_SPHINCS_SHAKE256_128_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R  NID_undef
#endif
/* End - NID_sphincsshake256128frobust - open-quantum-safe */

/* Begin - NID_sphincsshake256192frobust - open-quantum-safe */
// NOT IMPLEMENTED
/*
#ifdef NID_sphincsshake256192frobust
#define PKI_ALGOR_SPHINCS_SHAKE256_192_R     NID_sphincsshake256192frobust
#define PKI_ALGOR_ID_SPHINCS_SHAKE256_192_R  NID_sphincsshake256192frobust
#else
#define PKI_ALGOR_SPHINCS_SHAKE256_192_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHAKE25_192_R   NID_undef
#endif
*/
/* End - NID_sphincsshake256192frobust - open-quantum-safe */

/* Begin - NID_sphincsshake256256frobust - open-quantum-safe */
// NOT IMPLEMENTED
/*
#ifdef NID_sphincsshake256256frobust
#define PKI_ALGOR_SPHINCS_SHAKE256_256_R     NID_sphincsshake256256frobust
#define PKI_ALGOR_ID_SPHINCS_SHAKE256_256_R  NID_sphincsshake256256frobust
#else
#define PKI_ALGOR_SPHINCS_SHAKE256_256_R     NID_undef
#define PKI_ALGOR_ID_SPHINCS_SHAKE256_256_R  NID_undef
#endif
*/
/* End - NID_sphincsshake256256frobust - open-quantum-safe */


// ============================================ //
// Composite Crypto and Post Quantum Algorithms //
// ============================================ //

/* Begin - NID_rsa3072_falcon512 - open-quantum-safe */
#ifdef NID_rsa3072_falcon512
#define PKI_ALGOR_COMPOSITE_RSA_FALCON512      NID_rsa3072_falcon512
#define PKI_ALGOR_ID_COMPOSITE_RSA_FALCON512   NID_rsa3072_falcon512
#else
#define PKI_ALGOR_COMPOSITE_RSA_FALCON512     NID_undef
#define PKI_ALGOR_ID_COMPOSITE_RSA_FALCON512  NID_undef
#endif
/* End - NID_rsa3072_falcon512 - open-quantum-safe */

/* Begin - NID_p256_falcon512 - open-quantum-safe */
#ifdef NID_p256_falcon512
#define PKI_ALGOR_COMPOSITE_ECDSA_FALCON512      NID_p256_falcon512
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON512   NID_p256_falcon512
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_FALCON512     NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON512  NID_undef
#endif
/* End - NID_p256_falcon512 - open-quantum-safe */

/* Begin - NID_p521_falcon1024 - open-quantum-safe */
#ifdef NID_p521_falcon1024
#define PKI_ALGOR_COMPOSITE_ECDSA_FALCON1024     NID_p521_falcon1024
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON1024  NID_p521_falcon1024
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_FALCON1024     NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON1024  NID_undef
#endif
/* End - NID_p521_falcon1024 - open-quantum-safe */

/* Begin - NID_rsa3072_dilithium2 - open-quantum-safe */
#ifdef NID_rsa3072_dilithium2
#define PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2      NID_rsa3072_dilithium2
#define PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2   NID_rsa3072_dilithium2
#else
#define PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2   NID_undef
#endif
/* End - NID_rsa3072_dilithium2 - open-quantum-safe */

/* Begin - NID_rsa3072_dilithium2_aes - open-quantum-safe */
#ifdef NID_rsa3072_dilithium2_aes
#define PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2_AES      NID_rsa3072_dilithium2_aes
#define PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2_AES   NID_rsa3072_dilithium2_aes
#else
#define PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2_AES      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2_AES   NID_undef
#endif
/* End - NID_rsa3072_dilithium2_aes - open-quantum-safe */

/* Begin - NID_p256_dilithium2 - open-quantum-safe */
#ifdef NID_p256_dilithium2
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2      NID_p256_dilithium2
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2   NID_p256_dilithium2
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2   NID_undef
#endif
/* End - NID_p256_dilithium2 - open-quantum-safe */

/* Begin - NID_p384_dilithium3 - open-quantum-safe */
#ifdef NID_p384_dilithium3
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3      NID_p384_dilithium3
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3   NID_p384_dilithium3
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3   NID_undef
#endif
/* End - NID_p384_dilithium3 - open-quantum-safe */

/* Begin - NID_p521_dilithium5 - open-quantum-safe */
#ifdef NID_p521_dilithium5
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5      NID_p521_dilithium5
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5   NID_p521_dilithium5
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5   NID_undef
#endif
/* End - NID_p521_dilithium5 - open-quantum-safe */

/* Begin - NID_p256_dilithium2_aes - open-quantum-safe */
#ifdef NID_p256_dilithium2_aes
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2_AES      NID_p256_dilithium2_aes
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2_AES   NID_p256_dilithium2_aes
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2_AES      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2_AES   NID_undef
#endif
/* End - NID_p256_dilithium2_aes - open-quantum-safe */

/* Begin - NID_p384_dilithium3_aes - open-quantum-safe */
#ifdef NID_p384_dilithium3_aes
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3_AES      NID_p384_dilithium3_aes
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3_AES   NID_p384_dilithium3_aes
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3_AES      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3_AES   NID_undef
#endif
/* End - NID_p384_dilithium3_aes - open-quantum-safe */

/* Begin - NID_p521_dilithium5_aes - open-quantum-safe */
#ifdef NID_p521_dilithium5_aes
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5_AES      NID_p521_dilithium5_aes
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5_AES   NID_p521_dilithium5_aes
#else
#define PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5_AES      NID_undef
#define PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5_AES   NID_undef
#endif
/* End - NID_p521_dilithium5_aes - open-quantum-safe */

/* Begin - NID_p256_sphincssha256128frobust - open-quantum-safe */
#ifdef NID_p256_sphincssha256128frobust
#define PKI_ALGOR_COMPOSITE_P256_SPHINCS_SHA256     NID_p256_sphincssha256128frobust
#define PKI_ALGOR_ID_COMPOSITE_P256_SPHINCS_SHA256  NID_p256_sphincssha256128frobust
#else
#define PKI_ALGOR_COMPOSITE_P256_SPHINCS_SHA256     NID_undef
#define PKI_ALGOR_ID_COMPOSITE_P256_SPHINCS_SHA256  NID_undef
#endif
/* End - NID_p256_sphincssha256128frobust - open-quantum-safe */

/* Begin - NID_p256_sphincsshake256128frobust - open-quantum-safe */
#ifdef NID_p256_sphincsshake256128frobust
#define PKI_ALGOR_COMPOSITE_P256_SPHINCS_SHAKE256     NID_p256_sphincsshake256128frobust
#define PKI_ALGOR_ID_COMPOSITE_P256_SPHINCS_SHAKE256  NID_p256_sphincsshake256128frobust
#else
#define PKI_ALGOR_P256_COMPOSITE_SPHINCS_SHAKE256     NID_undef
#define PKI_ALGOR_ID_P256_COMPOSITE_SPHINCS_SHAKE256  NID_undef
#endif
/* End - NID_p256_sphincsshake256128frobust - open-quantum-safe */

// ======================================== //
// Composite Crypto and Composite_OR Crypto //
// ======================================== //

/* Begin - NID_composite */
#ifdef NID_composite
#define PKI_ALGOR_COMPOSITE      NID_composite
#define PKI_ALGOR_ID_COMPOSITE   NID_composite
#else
#define PKI_ALGOR_COMPOSITE     NID_undef
#define PKI_ALGOR_ID_COMPOSITE  NID_undef
#endif
/* End - NID_rsa3072_falcon512 */

/* Begin - NID_composite_or */
#ifdef NID_compositeOr
#define PKI_ALGOR_COMPOSITE_OR     NID_compositeOr
#define PKI_ALGOR_ID_COMPOSITE_OR  NID_compositeOr
#else
#define PKI_ALGOR_COMPOSITE_OR     NID_undef
#define PKI_ALGOR_ID_COMPOSITE_OR  NID_undef
#endif
/* End - NID_rsa3072_falcon512 */

/* Default DIGEST algorithm */
#ifdef ENABLE_SHA256
#define PKI_DIGEST_ALG_DEFAULT		PKI_DIGEST_ALG_SHA256
#define PKI_DIGEST_ALG_ID_DEFAULT	PKI_ALGOR_ID_SHA256
#define PKI_ALGOR_DEFAULT		      PKI_ALGOR_ID_RSA_SHA256
#define PKI_ALGOR_ID_DEFAULT		  PKI_ALGOR_ID_RSA_SHA256
#else
#define PKI_DIGEST_ALG_DEFAULT		PKI_DIGEST_ALG_SHA1
#define PKI_DIGEST_ALG_ID_DEFAULT	PKI_ALGOR_ID_SHA1
#define PKI_ALGOR_DEFAULT         PKI_ALGOR_ID_RSA_SHA1
#define PKI_ALGOR_ID_DEFAULT      PKI_ALGOR_ID_RSA_SHA1
#endif

#define PKI_OID				    ASN1_OBJECT
#define PKI_TIME			    ASN1_GENERALIZEDTIME
#define PKI_INTEGER			  ASN1_INTEGER
#define PKI_OCTET_STRING  ASN1_OCTETSTRING

/* This should capture all the EVP_CIPHERS available, for example
 * for des, use PKI_CIPHER(des, ede, cbc), for 3des use
 * PKI_CIPHER(des,ede3,cbc). For AES, instead, use the  */
// #define PKI_CIPHER(name,bits,mode)	EVP_ ##name _ ##bits _ ##mode()

/* Empty - Does nothing */
#define PKI_CIPHER_NULL			EVP_enc_null()

/* This should capture all the AES ciphers */
#define PKI_CIPHER_AES(bits,mode)	PKI_CIPHER_AES_##bits (mode)
#define PKI_CIPHER_AES_128(mode)	EVP_aes_128_ ##mode ()
#define PKI_CIPHER_AES_192(mode)	EVP_aes_192_ ##mode ()
#define PKI_CIPHER_AES_256(mode)	EVP_aes_256_ ##mode ()

/* This should capture all the DESX ciphers */
#define PKI_CIPHER_DESX(mode)		EVP_desx_##mode ()

/* This should capture all the DES ciphers */
#define PKI_CIPHER_DES(mode)		EVP_des_##mode ()

/* This should capture all the DESX ciphers */
#define PKI_CIPHER_3DES(mode)		EVP_des_ede3_##mode ()

/* This should capture all the DESX ciphers */
#define PKI_CIPHER_IDEA(mode)		EVP_idea_##mode ()

/* This should capture all the DESX ciphers */
#define PKI_CIPHER_CAST5(mode)		EVP_cast5_##mode ()

/* This should capture all the CAMELLIA ciphers */
#define PKI_CIPHER_CAMELLIA(bits,mode)	PKI_CIPHER_CAMELLIA_##bits (mode)
#define PKI_CIPHER_CAMELLIA_128(mode)	EVP_camellia_128_##mode ()
#define PKI_CIPHER_CAMELLIA_192(mode)	EVP_camellia_192_##mode ()
#define PKI_CIPHER_CAMELLIA_256(mode)	EVP_camellia_256_##mode ()


/* Old Ciphers */
#define PKI_CIPHER_RC5(mode)		EVP_rc5_##mode ()
#define PKI_CIPHER_RC2(mode)		EVP_rc2_##mode ()

/* ECDSA - NIST curves easy identifiers */
/* prime field curves */
#define NID_P192	NID_X9_62_prime192v1
#define NID_P224	NID_secp224r1
#define NID_P256	NID_X9_62_prime256v1
#define NID_P384	NID_secp384r1
#define NID_P521	NID_secp521r1
/* characteristic two field curves */
#define NID_K163	NID_sect163k1
#define NID_K233	NID_sect233k1
#define NID_K283	NID_sect283k1
#define NID_K409	NID_sect409k1
#define NID_K571	NID_sect571k1

#define NID_B163	NID_sect163r2
#define NID_B233	NID_sect233r1
#define NID_B283	NID_sect283r1
#define NID_B409	NID_sect409r1
#define NID_B571	NID_sect571r1

#ifdef ENABLE_ECDSA
#define PKI_EC_KEY_CURVE_DEFAULT		NID_P256
#else
#define PKI_EC_KEY_CURVE_DEFAULT		NID_undef
#endif

/* Directly Supported Relative Distinguished Name Types (RDN) */

typedef enum {
	PKI_X509_NAME_TYPE_NONE	=	NID_undef,
	PKI_X509_NAME_TYPE_UNKNOWN =	NID_undef,
	PKI_X509_NAME_TYPE_DC	=	NID_domainComponent ,
	PKI_X509_NAME_TYPE_O	=	NID_organizationName ,
	PKI_X509_NAME_TYPE_OU	=	NID_organizationalUnitName ,
	PKI_X509_NAME_TYPE_C	=	NID_countryName,
	PKI_X509_NAME_TYPE_ST	=	NID_stateOrProvinceName ,
	PKI_X509_NAME_TYPE_L	=	NID_localityName ,
	PKI_X509_NAME_TYPE_CN	=	NID_commonName,
	PKI_X509_NAME_TYPE_EMAIL=	NID_pkcs9_emailAddress ,
#ifdef NID_uniqueIdentifier
	PKI_X509_NAME_TYPE_UID	=	NID_uniqueIdentifier ,
#else
	PKI_X509_NAME_TYPE_UID	=	102 ,
#endif
	PKI_X509_NAME_TYPE_SN	=	NID_serialNumber ,
	// Strange Types - do not use them... :D
	PKI_X509_NAME_TYPE_S	=	NID_surname ,
	PKI_X509_NAME_TYPE_G	=	NID_givenName ,
	PKI_X509_NAME_TYPE_I	=	NID_initials ,
	PKI_X509_NAME_TYPE_T	=	NID_title ,
	PKI_X509_NAME_TYPE_D	=	NID_description ,
	PKI_X509_NAME_TYPE_name	=	NID_name ,
	PKI_X509_NAME_TYPE_dnQualifier	=	NID_dnQualifier ,
	PKI_X509_NAME_TYPE_DATA	=	NID_data ,
	PKI_X509_NAME_TYPE_SERIALNUMBER	=	NID_serialNumber ,
} PKI_X509_NAME_TYPE;

// PKI_X509_NAME_RDN - useful when getting specific parts of a DN only

typedef struct pki_x509_name_rdn {
	PKI_X509_NAME_TYPE type;
	char * value;
} PKI_X509_NAME_RDN;

// PKI_X509_EXTENSION

typedef struct pki_x509_extension_st {
	PKI_OID *oid;
	int critical;
	void *value;
} PKI_X509_EXTENSION;

#define PKI_X509_EXTENSION_VALUE	X509_EXTENSION

typedef enum {
	PKI_EC_KEY_FORM_UNKNOWN		=	0,
	PKI_EC_KEY_FORM_COMPRESSED	=	POINT_CONVERSION_COMPRESSED,
	PKI_EC_KEY_FORM_UNCOMPRESSED	=	POINT_CONVERSION_UNCOMPRESSED,
	PKI_EC_KEY_FORM_HYBRID		=	POINT_CONVERSION_HYBRID,
} PKI_EC_KEY_FORM;

#define PKI_EC_KEY_FORM_DEFAULT			PKI_EC_KEY_FORM_COMPRESSED

typedef enum {
	PKI_EC_KEY_ASN1_SPECIFIED_CURVE	=	0,
	PKI_EC_KEY_ASN1_NAMED_CURVE,
	PKI_EC_KEY_ASN1_IMPLICIT_CURVE	=	-1
} PKI_EC_KEY_ASN1;

#define PKI_EC_KEY_ASN1_DEFAULT			PKI_EC_KEY_ASN1_NAMED_CURVE

typedef struct pki_keyparams_st {
	int bits;
	PKI_SCHEME_ID scheme;
	// RSA scheme parameters
	struct {
		int exponent;
	} rsa;
	// DSA scheme parameters

#ifdef OPENSSL_NO_DSA
	struct {} dsa;
#endif

#ifdef ENABLE_ECDSA
	// EC scheme parameters
	struct {
		int curve;
		PKI_EC_KEY_FORM form;
		int asn1flags;
	} ec;
#endif // ENABLE_ECDSA

#ifdef ENABLE_OQS
	struct {
		PKI_ALGOR_ID algId;
	} oqs;
#endif // ENABLE_OQS

#ifdef ENABLE_COMPOSITE
	struct {
		PKI_X509_KEYPAIR_STACK * k_stack;
	} comp;
#endif

} PKI_KEYPARAMS;

#ifdef ENABLE_OQS
typedef enum {
	PKI_ALGOR_OQS_PARAM_UNKNOWN       = 0,
	PKI_ALGOR_OQS_PARAM_DILITHIUM_AES,
	PKI_ALGOR_OQS_PARAM_SPHINCS_SHAKE
} PKI_ALGOR_OQS_PARAM;

#endif

typedef X509_REVOKED	PKI_X509_CRL_ENTRY;

typedef struct pki_digest_data {
	const PKI_DIGEST_ALG *algor;
	unsigned char *digest;
	size_t size;
} PKI_DIGEST;

typedef struct pki_store_st {
        void	*store_ptr;
} PKI_STORE;

#define PKI_X509_KEYPAIR_VALUE  EVP_PKEY
#define PKI_X509_KEYPAIR        PKI_X509

#define PKI_X509_CERT_VALUE     X509 	
#define PKI_X509_CERT           PKI_X509 	

#define PKI_X509_REQ_VALUE      X509_REQ
#define PKI_X509_REQ            PKI_X509 	

#define PKI_X509_CRL_VALUE      X509_CRL 
#define PKI_X509_CRL            PKI_X509 

#define PKI_X509_PKCS7_VALUE    PKCS7
#define PKI_X509_PKCS7          PKI_X509

#define PKI_X509_CMS_VALUE      CMS_ContentInfo
#define PKI_X509_CMS            PKI_X509

#define PKI_X509_CMS_SIGNER_INFO CMS_SignerInfo
#define PKI_X509_CMS_RECIPIENT_INFO CMS_RecipientInfo

#define PKI_X509_PKCS12_VALUE   PKCS12
#define PKI_X509_PKCS12_DATA    STACK_OF(PKCS7)
#define PKI_X509_PKCS12         PKI_X509

#define PKI_OCSP_REQ_SINGLE     OCSP_ONEREQ
#define PKI_OCSP_CERTID         OCSP_CERTID

#define PKI_X509_OCSP_REQ_VALUE OCSP_REQUEST
#define PKI_X509_OCSP_REQ       PKI_X509

typedef struct pki_ocsp_resp_st {
	OCSP_RESPONSE * resp;
	OCSP_BASICRESP *bs;
} PKI_OCSP_RESP;

typedef enum {
	PKI_X509_OCSP_RESPID_NOT_SET       = -1,
	PKI_X509_OCSP_RESPID_TYPE_BY_NAME  =  0,
	PKI_X509_OCSP_RESPID_TYPE_BY_KEYID =  1
} PKI_X509_OCSP_RESPID_TYPE;

#define PKI_X509_OCSP_BASICRESP_VALUE OCSP_BASICRESP

#define PKI_X509_OCSP_RESP_VALUE OCSP_RESPONSE
#define PKI_X509_OCSP_RESP       PKI_X509

#define PKI_X509_XPAIR_VALUE     PKI_XPAIR
#define PKI_X509_XPAIR           PKI_X509

#define PKI_X509_PRQP_REQ_VALUE  PKI_PRQP_REQ
#define PKI_X509_PRQP_REQ        PKI_X509

#define PKI_X509_PRQP_RESP_VALUE PKI_PRQP_RESP
#define PKI_X509_PRQP_RESP       PKI_X509

#include <libpki/hsm_st.h>
#include <libpki/token_st.h>

#define __B64_write_bio_internal(type,bio,data,p) ({ BIO *b64; int r;\
                b64 = BIO_new(BIO_f_base64()) ; \
                        bio = BIO_push(b64, bio) ; \
                        r = i2d_##type##p(bio, data); \
                        BIO_flush(bio); \
                        bio = BIO_pop(bio); \
                        BIO_free(b64); PKI_OK ;})

#define B64_write_bio(type,bio,data) \
                __B64_write_bio_internal(type,bio,data,_bio)


/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
