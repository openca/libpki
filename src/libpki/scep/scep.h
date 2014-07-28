/*
 * OpenCA SCEP 
 *
 * (c) 2002-2009 by Massimiliano Pala and OpenCA Labs
 *
 * Thanks to the OpenSCEP group for their work and help
 *
 */

#ifndef _LIBPKI_SCEP_H_
#define _LIBPKI_SCEP_H_

/*
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
*/

/*
#define SCEP_ATTRIBUTE_OID_MESSAGE_TYPE		"2.16.840.1.113733.1.9.2"
#define SCEP_ATTRIBUTE_STRING_MESSAGE_TYPE	"messageType"
#define SCEP_ATTRIBUTE_OID_PKI_STATUS		"2.16.840.1.113733.1.9.3"
#define SCEP_ATTRIBUTE_STRING_PKI_STATUS	"pkiStatus"
#define SCEP_ATTRIBUTE_OID_FAIL_INFO		"2.16.840.1.113733.1.9.4"
#define SCEP_ATTRIBUTE_STRING_FAIL_INFO		"failInfo"
#define SCEP_ATTRIBUTE_OID_SENDER_NONCE		"2.16.840.1.113733.1.9.5"
#define SCEP_ATTRIBUTE_STRING_SENDER_NONCE	"senderNonce"
#define SCEP_ATTRIBUTE_OID_RECIPIENT_NONCE	"2.16.840.1.113733.1.9.6"
#define SCEP_ATTRIBUTE_STRING_RECIPIENT_NONCE	"recipientNonce"
#define SCEP_ATTRIBUTE_OID_TRANS_ID		"2.16.840.1.113733.1.9.7"
#define SCEP_ATTRIBUTE_STRING_TRANS_ID		"transId"
#define SCEP_ATTRIBUTE_OID_EXTENSION_REQ	"2.16.840.1.113733.1.9.8"
#define SCEP_ATTRIBUTE_STRING_EXTENSION_REQ	"extensionReq"
#define SCEP_ATTRIBUTE_OID_PROXY_AUTHENTICATOR 	"1.3.6.1.4.1.4263.5.5"
#define SCEP_ATTRIBUTE_STRING_PROXY_AUTHENTICATOR	"proxyAuthenticator"
*/

#define TRANS_ID_SIZE				16

typedef struct scep_oid_st {
	int  attr_type;
	char *oid_s;
	char *descr;
	char *long_descr;
	int  nid;
} SCEP_CONF_ATTRIBUTE;

/* These should be in the same order than the SCEP_ATTRIBUTE_list in scep_attrs.c */
typedef enum {
	SCEP_ATTRIBUTE_MESSAGE_TYPE 		= 0,
	SCEP_ATTRIBUTE_PKI_STATUS,
	SCEP_ATTRIBUTE_FAIL_INFO,
	SCEP_ATTRIBUTE_SENDER_NONCE,
	SCEP_ATTRIBUTE_RECIPIENT_NONCE,
	SCEP_ATTRIBUTE_TRANS_ID,
	SCEP_ATTRIBUTE_EXTENSION_REQ,
	SCEP_ATTRIBUTE_PROXY_AUTH
} SCEP_ATTRIBUTE_TYPE;

typedef enum {
	PKI_X509_SCEP_MSG_UNKNOWN 		= -1,
	PKI_X509_SCEP_MSG_V2REQUEST 		= 17,
	PKI_X509_SCEP_MSG_V2PROXY 		= 18,
	PKI_X509_SCEP_MSG_PKCSREQ 		= 19,
	PKI_X509_SCEP_MSG_CERTREP 		= 3,
	PKI_X509_SCEP_MSG_GETCERTINITIAL 	= 20,
	PKI_X509_SCEP_MSG_GETCERT 		= 21,
	PKI_X509_SCEP_MSG_GETCRL 		= 22
} SCEP_MESSAGE_TYPE;

typedef enum {
	SCEP_STATUS_SUCCESS			= 0,
	SCEP_STATUS_FAILURE			= 2,
	SCEP_STATUS_PENDING			= 3
} SCEP_STATUS;

typedef enum {
	SCEP_FAILURE_BADALG			= 0,
	SCEP_FAILURE_BADMESSAGECHECK		= 1,
	SCEP_FAILURE_BADREQUEST			= 2,
	SCEP_FAILURE_BADTIME			= 3,
	SCEP_FAILURE_BADCERTID			= 4
} SCEP_FAILURE;

#define SCEP_NONCE				PKI_MEM
#define NONCE_SIZE				16

#define PKI_X509_SCEP_MSG_VALUE			PKCS7
#define PKI_X509_SCEP_DATA			PKI_X509_PKCS7
#define	PKI_X509_SCEP_MSG			PKI_X509_PKCS7

#include <libpki/scep/pki_x509_scep_asn1.h>
#include <libpki/scep/pki_x509_scep_data.h>
#include <libpki/scep/pki_x509_scep_attrs.h>
#include <libpki/scep/pki_x509_scep_msg.h>


#endif


/*
typedef struct scep_recip_info {
	STACK_OF(PKCS7_RECIP_INFO) *sk_recip_info;
	STACK_OF(X509) *sk_recip_certs;

	PKCS7_ISSUER_AND_SERIAL *ias;

} SCEP_RECIP_INFO;
*/

/*
typedef struct {
	int NID_p7data;
	
	// enc p7 enveloped data
	PKCS7 *p7env; 
	PKCS7 *p7;

	// Info about the recipient of the message
	SCEP_RECIP_INFO recip_info;
	EVP_PKEY *pkey;
	X509 *cacert;

	union {
		// PKCSReq Content
		X509_REQ *req;
		// CertResp Content
		X509 *issued_cert;
		// CertReq Content
		X509 *self_signed_cert;
		// GetCertInitial Content
		SCEP_ISSUER_AND_SUBJECT *init_certinfo;
		// GetCert && GetCrl Content
		PKCS7_ISSUER_AND_SERIAL	*ias;
	} content;

	X509_CRL *crl;

} SCEP_ENVELOPED_DATA;

typedef struct {
	int messageType;

	STACK_OF(PKCS7_SIGNER_INFO) *sk_signer_info;
	PKCS7_ISSUER_AND_SERIAL *signer_ias;
	X509 *signer_cert;
	EVP_PKEY *signer_pkey;

	STACK_OF(X509_ATTRIBUTE) *attrs;

	SCEP_ENVELOPED_DATA env_data;

	STACK_OF(X509) *sk_others;

} SCEP_MSG;
*/

/*
#define	SCEP_MESSAGE_is(a, b) (!strcmp(a, b))
#define SCEP_PKISTATUS_is(a, b) (!strcmp(a, b))
#define	SCEP_FAILURE_is(a, b) (!strcmp(a, b))

#define	SCEP_type2str(a) ( 			\
(0 == a ) ? "(not set)" : ( 			\
(SCEP_MSG_PKCSREQ == a ) ? "PKCSReq" : ( 		\
(SCEP_MSG_V2REQUEST == a ) ? "v2Request" : (		\
(SCEP_MSG_V2PROXY == a ) ? "v2Proxy" : (		\
(SCEP_MSG_CERTREP == a ) ? "CertRep" : (		\
(SCEP_MSG_GETCERTINITIAL == a ) ? "GetCertInitial" : (	\
(SCEP_MSG_GETCERT == a ) ? "GetCert" : (		\
(SCEP_MSG_GETCRL == a ) ? "GetCRL" : "unknown"))))))))

#define	SCEP_str2type( a )	(	\
(NULL == a) ? -1 :				(	\
(0 == strcmp("PKCSReq", a)) ? SCEP_MSG_PKCSREQ : (		\
(0 == strcmp("v2Request", a)) ? SCEP_MSG_V2REQUEST : (	\
(0 == strcmp("v2Proxy", a)) ? SCEP_MSG_V2PROXY : (		\
(0 == strcmp("CertRep", a)) ? SCEP_MSG_CERTREP : (		\
(0 == strcmp("GetCertInitial", a)) ? SCEP_MSG_GETCERTINITIAL : (\
(0 == strcmp("GetCert", a)) ? SCEP_MSG_GETCERT : (		\
(0 == strcmp("GetCRL", a)) ? SCEP_MSG_GETCRL : -1 ))))))))

#define	SCEP_TYPE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_MESSAGE_TYPE_PKCSREQ, a)) ? "PKCSReq" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2REQUEST, a)) ? "v2Request" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2PROXY, a)) ? "v2Proxy" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_CERTREP, a)) ? "CertRep" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERTINITIAL, a)) ? "GetCertInitial" : (\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERT, a)) ? "GetCert" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCRL, a)) ? "GetCRL" : "unknown"))))))))

#define SCEP_status2str(a)					(	\
(PKI_SUCCESS == a ) ? "Success" : (		\
(PKI_FAILURE == a ) ? "Failure" : (		\
(PKI_PENDING == a ) ? "Pending" : "(unknown)")))

#define SCEP_str2status(a)                                      (       \
(NULL == a) ? -1 :                              (       \
(0 == strcmp("SUCCESS", a)) ? PKI_SUCCESS : (      \
(0 == strcmp("FAILURE", a)) ? PKI_FAILURE :        (       \
(0 == strcmp("PENDING", a)) ? PKI_PENDING : -1 ))))

#define SCEP_STATUS(a)					(	\
(NULL == a) ? "(not set)" :				(	\
(0 == strcmp(SCEP_PKISTATUS_SUCCESS, a)) ? "SUCCESS" : 	(	\
(0 == strcmp(SCEP_PKISTATUS_FAILURE, a)) ? "FAILURE" : 	(	\
(0 == strcmp(SCEP_PKISTATUS_PENDING, a)) ? "PENDING" : "(unknown)"))))

#define	SCEP_failure2str(a)				(	\
(FAIL_BADALG == a ) ? "BadAlg" : 			(	\
(FAIL_BADMESSAGECHECK == a ) ? "BadMessageCheck" : 	(	\
(FAIL_BADREQUEST == a ) ? "BadRequest" : 		(	\
(FAIL_BADTIME == a ) ? "BadTime" : 			(	\
(FAIL_BADCERTID == a ) ? "BadCertID" : "(unknown)")))))

#define	SCEP_str2failure(a)					(	\
(NULL == a) ? -1 :					(	\
(0 == strcmp("badAlg", a)) ? FAIL_BADALG : (			\
(0 == strcmp("badMessageCheck", a)) ? FAIL_BADMESSAGECHECK : ( \
(0 == strcmp("badRequest", a)) ? FAIL_BADREQUEST : (		\
(0 == strcmp("badTime", a)) ? FAIL_BADTIME : (		\
(0 == strcmp("badCertId", a)) ? FAIL_BADCERTID : -1 ))))))

#define	SCEP_FAILURE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_FAILURE_BADALG, a)) ? "BadAlg" : (			\
(0 == strcmp(SCEP_FAILURE_BADMESSAGECHECK, a)) ? "BadMessageCheck" : (	\
(0 == strcmp(SCEP_FAILURE_BADREQUEST, a)) ? "BadRequest" : (		\
(0 == strcmp(SCEP_FAILURE_BADTIME, a)) ? "BadTime" : (			\
(0 == strcmp(SCEP_FAILURE_BADCERTID, a)) ? "BadCertID" : "(unknown)"))))))
*/

/*
#define SCEP_str2attribute(a)			(	\
(NULL == a) ? -1 :				(	\
(0 == strcmp(MESSAGE_TYPE_OID_STRING, a)) ? SCEP_MESSAGE_TYPE_ATTRIBUTE : (\
(0 == strcmp(PKI_STATUS_OID_STRING, a)) ? SCEP_PKI_STATUS_ATTRIBUTE :     (\
(0 == strcmp(FAIL_INFO_OID_STRING, a)) ? SCEP_FAIL_INFO_ATTRIBUTE :       (\
(0 == strcmp(SENDER_NONCE_OID_STRING, a)) ? SCEP_SENDER_NONCE_ATTRIBUTE : (\
(0 == strcmp(RECIPIENT_NONCE_OID_STRING, a)) ? SCEP_RECIPIENT_NONCE_ATTRIBUTE : (\
(0 == strcmp(TRANS_ID_OID_STRING, a)) ? SCEP_TRANS_ID_ATTRIBUTE : 	  (\
(0 == strcmp(EXTENSION_REQ_OID_STRING, a)) ? SCEP_EXTENSION_REQ_ATTRIBUTE : (\
(0 == strcmp(PROXY_AUTHENTICATOR_OID_STRING, a)) ? SCEP_PROXY_AUTHENTICATOR_ATTRIBUTE : -1 )))))))))
*/

