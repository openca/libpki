/* X509_data_st.h */

#ifndef LIBPKI_X509_INT_H
#define LIBPKI_X509_INT_H

#include <openssl/x509.h>

# if OPENSSL_VERSION_NUMBER > 0x1010000fL

// =================
// X509 Certificates
// =================

typedef struct x509_cinf_st {
    ASN1_INTEGER *version;      /* [ 0 ] default of v1 */
    ASN1_INTEGER serialNumber;
    X509_ALGOR signature;
    X509_NAME *issuer;
    X509_VAL validity;
    X509_NAME *subject;
    X509_PUBKEY *key;
    ASN1_BIT_STRING *issuerUID; /* [ 1 ] optional in v2 */
    ASN1_BIT_STRING *subjectUID; /* [ 2 ] optional in v2 */
    STACK_OF(X509_EXTENSION) *extensions; /* [ 3 ] optional in v3 */
    ASN1_ENCODING enc;
} LIBPKI_X509_CINF /* X509_CINF */ ;

typedef struct x509_st {
    LIBPKI_X509_CINF cert_info;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
    int references;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    uint32_t ex_flags;
    uint32_t ex_kusage;
    uint32_t ex_xkusage;
    uint32_t ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    X509_POLICY_CACHE *policy_cache;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
# endif
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    X509_CERT_AUX *aux;
    CRYPTO_RWLOCK *lock;
} LIBPKI_X509_CERT /* X509 */ ;

// =============
// X509 Requests
// =============

typedef struct X509_req_info_st {
    ASN1_ENCODING enc;          /* cached encoding of signed part */
    ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject;         /* certificate request DN */
    X509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
} LIBPKI_X509_REQ_INFO /* X509_REQ_INFO */ ;

typedef struct X509_req_st {
    LIBPKI_X509_REQ_INFO req_info;     /* signed certificate request data */
    X509_ALGOR sig_alg;         /* signature algorithm */
    ASN1_BIT_STRING *signature; /* signature */
    int references;
    CRYPTO_RWLOCK *lock;
} LIBPKI_X509_REQ /* X509_REQ */;


// =========
// X509 CRLs
// =========

typedef struct X509_crl_info_st {
    ASN1_INTEGER *version;      /* version: defaults to v1(0) so may be NULL */
    X509_ALGOR sig_alg;         /* signature algorithm */
    X509_NAME *issuer;          /* CRL issuer name */
    ASN1_TIME *lastUpdate;      /* lastUpdate field */
    ASN1_TIME *nextUpdate;      /* nextUpdate field: optional */
    STACK_OF(X509_REVOKED) *revoked;        /* revoked entries: optional */
    STACK_OF(X509_EXTENSION) *extensions;   /* extensions: optional */
    ASN1_ENCODING enc;                      /* encoding of signed portion of CRL */
} LIBPKI_CRL_INFO /* CRL_INFO */ ;

// ==========
// X509 ALGOR
// ==========

typedef struct _libpki_X509_algor_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
} LIBPKI_X509_ALGOR /* X509_ALGOR */ ;

// ==============
// X509 EXTENSION
// ==============

typedef struct X509_extension_st {
    ASN1_OBJECT *object;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING value;
} LIBPKI_X509_EXTENSION /* X509_EXTENSION */ ;


# else /* OPENSSL_VERSION */

typedef X509		LIBPKI_X509_CERT;
typedef X509_CINF	LIBPKI_X509_CINF;

typedef X509_REQ	LIBPKI_X509_REQ;
typedef X509_REQ_INFO	LIBPKI_X509_REQ_INFO;

typedef X509_CRL	LIBPKI_X509_CRL;
typedef X509_CRL_INFO	LIBPKI_X509_CRL_INFO;

typedef X509_ALGOR	LIBPKI_X509_ALGOR;

typedef X509_EXTENSION	LIBPKI_X509_EXTENSION;

# endif /* OPENSSL_VERSION */

#endif
