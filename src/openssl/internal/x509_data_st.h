/* X509_data_st.h */

#include <openssl/opensslv.h>
#include <openssl/x509.h>

#ifndef LIBPKI_X509_INT_H
#define LIBPKI_X509_INT_H

#  if OPENSSL_VERSION_NUMBER > 0x1000000fL

// PKIX Generic Structures Forward References
typedef struct x509_cinf_st       LIBPKI_X509_CINF;
typedef struct x509_st            LIBPKI_X509_CERT;
typedef struct X509_req_info_st   LIBPKI_X509_REQ_INFO;
typedef struct X509_req_st        LIBPKI_X509_REQ;
typedef struct X509_crl_info_st   LIBPKI_X509_CRL_INFO;
typedef struct X509_crl_st        LIBPKI_X509_CRL;
typedef struct X509_algor_st      LIBPKI_X509_ALGOR;
typedef struct X509_extension_st  LIBPKI_X509_EXTENSION;
typedef struct x509_attributes_st LIBPKI_X509_ATTRIBUTE_FULL;

// OCSP Structures Forward references
typedef struct ocsp_cert_id_st        LIBPKI_X509_OCSP_CERTID;
typedef struct ocsp_req_info_st       LIBPKI_X509_OCSP_REQ_INFO;
typedef struct ocsp_signature_st      LIBPKI_X509_OCSP_SIGNATURE;
typedef struct ocsp_request_st        LIBPKI_X509_OCSP_REQ;
typedef struct ocsp_responder_id_st   LIBPKI_X509_OCSP_RESPID;
typedef struct ocsp_response_data_st  LIBPKI_X509_OCSP_RESPDATA;
typedef struct ocsp_basic_response_st LIBPKI_X509_OCSP_BASICRESP;
typedef struct ocsp_resp_bytes_st     LIBPKI_X509_OCSP_RESPBYTES;
typedef struct ocsp_response_st       LIBPKI_X509_OCSP_RESPONSE;

// CMS Structures Forward references
typedef struct CMS_IssuerAndSerialNumber_st LIBPKI_CMS_ISSUER_AND_SERIAL_NUMBER;
typedef struct CMS_EncapsulatedContentInfo_st LIBPKI_CMS_CI_ENCAPSULATED;
typedef struct CMS_SignerIdentifier_st LIBPKI_CMS_SIGNER_IDENTIFIER;
typedef struct CMS_SignedData_st LIBPKI_CMS_SIGNED_DATA;
typedef struct CMS_OtherRevocationInfoFormat_st LIBPKI_CMS_OTHER_REVOCATION_INFO_FORMAT;
typedef struct CMS_OriginatorInfo_st LIBPKI_CMS_ORIGINATOR_INFO;
typedef struct CMS_EncryptedContentInfo_st LIBPKI_CMS_CI_ENCRYPTED;
typedef struct CMS_EnvelopedData_st LIBPKI_CMS_DATA_ENVELOPED;
typedef struct CMS_DigestedData_st LIBPKI_CMS_DATA_DIGESTED;
typedef struct CMS_EncryptedData_st LIBPKI_CMS_DATA_ENCRYPTED;
typedef struct CMS_AuthenticatedData_st LIBPKI_CMS_DATA_AUTH;
typedef struct CMS_CompressedData_st LIBPKI_CMS_DATA_COMPRESSED;
typedef struct CMS_OtherCertificateFormat_st LIBPKI_CMS_OTHER_CERTIFICATE_FORMAT;
typedef struct CMS_KeyTransRecipientInfo_st LIBPKI_CMS_RECIPIENT_INFO_KTRANS;
typedef struct CMS_OriginatorPublicKey_st LIBPKI_CMS_ORIGINATOR_PUBLIC_KEY;
typedef struct CMS_OriginatorIdentifierOrKey_st LIBPKI_CMS_ORIGINATOR_IDENTIFIER_OR_KEY;
typedef struct CMS_KeyAgreeRecipientInfo_st LIBPKI_CMS_RECIPIENT_INFO_KAGREE;
typedef struct CMS_RecipientKeyIdentifier_st LIBPKI_CMS_RECIPIENT_KEY_IDENTIFIER;
typedef struct CMS_KeyAgreeRecipientIdentifier_st
    LIBPKI_CMS_KAGREE_RECIPIENT_IDENTIFIER;
typedef struct CMS_KEKIdentifier_st LIBPKI_CMS_KEK_IDENTIFIER;
typedef struct CMS_KEKRecipientInfo_st LIBPKI_CMS_RECIPIENT_INFO_KEK;
typedef struct CMS_PasswordRecipientInfo_st LIBPKI_CMS_RECIPIENT_INFO_PASSWORD;
typedef struct CMS_OtherRecipientInfo_st LIBPKI_CMS_RECIPIENT_INFO_OTHER;
typedef struct CMS_ReceiptsFrom_st LIBPKI_CMS_RECEIPTS_FROM;

// Definition for OSSL v1.1.1+
typedef int CRYPTO_REF_COUNT;

// ----- Includes specific for OpenSSL v1.0.x ----- //
#    if OPENSSL_VERSION_NUMBER <= 0x1000fffL
#      include "ossl_1_0_x/cms_lcl.h"
#    else
// ----- Includes specific for OpenSSL v1.1.0+ ----- //
#      if OPENSSL_VERSION_NUMBER <= 0x101000fL
#        include "ossl_1_1_0/x509_lcl.h"
#        include "ossl_1_1_0/x509_int.h"
#        include "ossl_1_1_0/ocsp_lcl.h"
#        include "ossl_1_1_0/cms_lcl.h"
#      else
// ----- Includes specific for OpenSSL v1.1.1+ ----- //
#        if OPENSSL_VERSION_NUMBER > 0x1010000L
#          include "ossl_1_1_1/x509_lcl.h"
#          include "ossl_1_1_1/x509_int.h"
#          include "ossl_1_1_1/ocsp_lcl.h"
#          include "ossl_1_1_1/cms_lcl.h"
#        endif
#      endif
#    endif
#  endif

#endif
