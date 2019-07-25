/* CMS Includes for LibPKI */

#ifndef _LIBPKI_CMS_H
#define _LIBPKI_CMS_H

#define CMS_REQ_SIMPLE_DATATYPE		"application/pkcs10"
#define CMS_REQ_SIMPLE_EXTENSION	"p10"

#define CMS_REQ_FULL_DATATYPE		"application/pkcs7-mime"
#define CMS_REQ_FULL_EXTENSION		"p7m"

#define CMS_RESP_SIMPLE_DATATYPE	"application/pkcs7-mime"
#define CMS_RESP_SIMPLE_EXTENSION	"p7c"

#define CMS_RESP_FULL_DATATYPE		"application/pkcs7-mime"
#define CMS_RESP_FULL_EXTENSION		"p7m"

#define PEM_STRING_CERT_REQ_MSG		"CERTIFICATE REQUEST MESSAGE"
#define PKI_CONTENT_TYPE_CERT_REQ_MSG	"application/pkcs7-mime"

/*
   PEND_INFO ::= SEQUENCE {
	pendToken		OCTET STRING,
	pendTime		GeneralizedTime
   }
*/

typedef struct PendInfo_st {
	ASN1_OCTET_STRING *pendInfo;
	ASN1_GENERALIZEDTIME *pendTime;
} PEND_INFO;

DECLARE_ASN1_FUNCTIONS(PEND_INFO)

/*
   BODY_PART_REFERENCE ::= SEQUENCE {
	bodyPartID		BodyPartID,
	bodyPartPath		SEQUENCE SIZE(1..MAX) OF BodyPartID
   }
*/

typedef struct BodyPartReference_st {
	ASN1_INTEGER * bodyPartID;
	STACK_OF(ASN1_INTEGER) * bodyPartPath;
} BODY_PART_REFERENCE;

DECLARE_ASN1_FUNCTIONS(BODY_PART_REFERENCE)

DECLARE_STACK_OF(BODY_PART_REFERENCE)

/* 
   CMC_STATUS_INFO ::= SEQUENCE {
	cMCStatus		CMCStatus,
	bodyList		SEQUENCE SIZE (1..MAX) OF BODY_PART_REFERENCE,
	statusString		UTF8String	OPTIONAL,
	otherInfo		CHOICE {
					failInfo	CMCFailInfo,
					pendInfo	PEND_INFO,
					extendedFailInfo	SEQUENCE {
						failInfoOID		OBJECT_IDENTIFIER,
						failInfoValue		AttributeValue }
				} OPTIONAL
   }
*/

/* Watch out because the ASN1_ANY value could swallow everything else... */

typedef struct ExtendedFailInfo_st {
	ASN1_OBJECT *failInfoOID;
	/* Should be ASN1_ANY not void! */
	ASN1_TYPE * failInfoValue;
} EXTENDED_FAIL_INFO;

DECLARE_ASN1_FUNCTIONS(EXTENDED_FAIL_INFO)

typedef struct OtherInfoEx_st {
	int type;
	union {
		ASN1_INTEGER *failInfo;
		PEND_INFO *pendInfo;
		EXTENDED_FAIL_INFO *extendedFailInfo;
	} value;
} OTHER_INFO_EX;

DECLARE_ASN1_FUNCTIONS(OTHER_INFO_EX)

typedef struct CMCStatusInfoEx_st {
	ASN1_INTEGER *cMCStatus;
	STACK_OF(BODY_PART_REFERENCE) *bodyList;
	ASN1_UTF8STRING *statusString;
	OTHER_INFO_EX *otherInfo;
} CMC_STATUS_INFO_EX;

DECLARE_ASN1_FUNCTIONS(CMC_STATUS_INFO_EX)

/*
   CMCStatusInfo ::= SEQUENCE {
	cMCStatusInfo		CMCStatus,
	bodyList		SEQUENCE SIZE (1..MAX) OF BodyPartID,
	statusString		UTF8String  OPTIONAL,
	otherInfo		CHOICE {
					failInfo	CMCFailInfo,
					pendInfo	PendInfo
				}  OPTIONAL
	}
*/

typedef struct OtherInfo_st {
	int type;
	union {
		ASN1_INTEGER * failInfo;
		PEND_INFO * pendInfo;
	} value;	
} OTHER_INFO;


DECLARE_ASN1_FUNCTIONS(OTHER_INFO)

typedef struct CMCStatusInfo_st {
	ASN1_INTEGER *cMCStatusInfo;
	STACK_OF(ASN1_INTEGER) *bodyList;
	ASN1_UTF8STRING *statusString;
	OTHER_INFO *otherInfo;
} CMC_STATUS_INFO;

DECLARE_ASN1_FUNCTIONS(CMC_STATUS_INFO)
	
/*
   TAGGED_ATTRIBUTE ::= SEQUENCE {
	bodyPartID		BodyPartID,
	attrType		OBJECT IDENTIFIER,
	attrValues		SET OF AttributeValue
   }
*/

typedef struct TaggedAttribute_st {
	ASN1_INTEGER *bodyPartID;
	ASN1_OBJECT *attrType;
	STACK_OF(X509_ATTRIBUTE) *attrValues;
} TAGGED_ATTRIBUTE;

DECLARE_ASN1_FUNCTIONS(TAGGED_ATTRIBUTE)

DECLARE_STACK_OF(TAGGED_ATTRIBUTE)

/*
   OTHER_MSG ::= SEQUENECE {
	bodyPartID		BodyPartID,
	otherMsgType		OBJECT IDENTIFIER,
	otherMsgValue		ANY DEFINED BY otherMsgType
   }
*/

typedef struct OtherMsg_st {
	ASN1_INTEGER * bodyPartID;
	ASN1_OBJECT * otherMsgType;
	ASN1_TYPE * otherMsgValue;
} OTHER_MSG;

DECLARE_ASN1_FUNCTIONS( OTHER_MSG )

/*
   CMC_UNSIGNED_DATA ::= SEQUENCE {
	bodyPartPath		SEQUENCE SIZE (1..MAX) OF BodyPartID,
	identifier		OBJECT IDENTIFIER,
	content			ANY DEFINED BY identifier
*/

typedef struct CMCUnsignedData_st {
	STACK_OF(ASN1_INTEGER) * bodyPartPath;
	ASN1_OBJECT * identifier;
	ASN1_TYPE *content;
} CMC_UNSIGNED_DATA;

DECLARE_ASN1_FUNCTIONS( CMC_UNSIGNED_DATA )

/*
   ContentInfo ::= SEQUENCE {
        bodyPartID              BodyPartID,
        contentInfo             ContentInfo
   }
*/

typedef struct ContentInfo_st {
	ASN1_OBJECT * contentType;
	ASN1_TYPE * content;
} CONTENT_INFO;

DECLARE_ASN1_FUNCTIONS(CONTENT_INFO)

/*
   TaggedContentInfo ::= SEQUENCE {
        bodyPartID              BodyPartID,
        contentInfo             ContentInfo
   }
*/

typedef struct TaggedContentInfo_st {
	ASN1_INTEGER *bodyPartID;
	CONTENT_INFO *contentInfo;
} TAGGED_CONTENT_INFO;

DECLARE_ASN1_FUNCTIONS(TAGGED_CONTENT_INFO)

/*
   TaggedCertificationRequest ::= SEQUENCE {
	bodyPartID		BodyPartID,
	certificationRequest	CertificationRequest
   }
*/

typedef struct TaggedCertificationRequest_st {
	ASN1_INTEGER *bodyPartID;
	X509_REQ *certificationRequest;
} TAGGED_CERTIFICATION_REQUEST;

DECLARE_ASN1_FUNCTIONS(TAGGED_CERTIFICATION_REQUEST)

/*
   PKMACValue ::= SEQUENCE {
      algId  AlgorithmIdentifier,
      -- the algorithm value shall be PasswordBasedMac
      --     {1 2 840 113533 7 66 13}
      -- the parameter value is PBMParameter
      value  BIT STRING }
*/

typedef struct PKMACValue_st {
	X509_ALGOR *algID;
	ASN1_BIT_STRING *value;
} PKMAC_VALUE;

DECLARE_ASN1_FUNCTIONS(PKMAC_VALUE)

/*
   POPOSigningKeyInput ::= SEQUENCE {
       authInfo            CHOICE {
           sender              [0] GeneralName,
           -- used only if an authenticated identity has been
           -- established for the sender (e.g., a DN from a
           -- previously-issued and currently-valid certificate)
           publicKeyMAC        PKMACValue },
           -- used if no authenticated GeneralName currently exists for
           -- the sender; publicKeyMAC contains a password-based MAC
           -- on the DER-encoded value of publicKey
       publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
*/

typedef struct AuthInfo_st {
	int type;
	union {
		X509_NAME *sender;
		PKMAC_VALUE *publicKeyMAC;
	} value;
} AUTH_INFO;

DECLARE_ASN1_FUNCTIONS(AUTH_INFO)

typedef struct PubKeyInfo_st {
	X509_ALGOR *algorithm;
	ASN1_BIT_STRING *subjectPublicKey;
} PUBKEY_INFO;

DECLARE_ASN1_FUNCTIONS(PUBKEY_INFO)

typedef struct POPOSigningKeyInput {
	AUTH_INFO *authInfo;
	PUBKEY_INFO *publicKey;
} POP_O_SIGNING_KEY_INPUT;

DECLARE_ASN1_FUNCTIONS(POP_O_SIGNING_KEY_INPUT)

/*
   POPOSigningKey ::= SEQUENCE {
       poposkInput         [0] POPOSigningKeyInput OPTIONAL,
       algorithmIdentifier     AlgorithmIdentifier,
       signature               BIT STRING }
       -- The signature (using "algorithmIdentifier") is on the
       -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
       -- certReq CertTemplate contains the subject and publicKey values,
       -- then poposkInput MUST be omitted and the signature MUST be
       -- computed on the DER-encoded value of CertReqMsg certReq.  If
       -- the CertReqMsg certReq CertTemplate does not contain the public
       -- key and subject values, then poposkInput MUST be present and
       -- MUST be signed.  This strategy ensures that the public key is
       -- not present in both the poposkInput and CertReqMsg certReq
       -- CertTemplate fields.
*/

typedef struct POPOSigningKey {
	POP_O_SIGNING_KEY_INPUT *poposkInput;
	X509_ALGOR *algorithmIdentifier;
	ASN1_BIT_STRING *signature;
} POP_O_SIGNING_KEY;

DECLARE_ASN1_FUNCTIONS(POP_O_SIGNING_KEY)

/*
   SubsequentMessage ::= INTEGER {
       encrCert (0),
       -- requests that resulting certificate be encrypted for the
       -- end entity (following which, POP will be proven in a
       -- confirmation message)
       challengeResp (1) }
       -- requests that CA/RA engage in challenge-response exchange with
       -- end entity in order to prove private key possession

   POPOPrivKey ::= CHOICE {
       thisMessage       [0] BIT STRING,
       -- posession is proven in this message (which contains the private
       -- key itself (encrypted for the CA))
       subsequentMessage [1] SubsequentMessage,
       -- possession will be proven in a subsequent message
       dhMAC             [2] BIT STRING }
       -- for keyAgreement (only), possession is proven in this message
       -- (which contains a MAC (over the DER-encoded value of the
       -- certReq parameter in CertReqMsg, which must include both subject
       -- and publicKey) based on a key derived from the end entity's
       -- private DH key and the CA's public DH key);
       -- the dhMAC value MUST be calculated as per the directions given
       -- in Appendix A.
*/

typedef struct POPOPrivKey_st {
	int type;
	union {
		ASN1_BIT_STRING *thisMessage;
		ASN1_INTEGER *subsequentMessage;
		ASN1_BIT_STRING *dhMAC;
	} value;
} POP_O_PRIVKEY;

DECLARE_ASN1_FUNCTIONS(POP_O_PRIVKEY)

/*
   ProofOfPossession ::= CHOICE {
       raVerified        [0] NULL,
       -- used if the RA has already verified that the requester is in
       -- possession of the private key
       signature         [1] POPOSigningKey,
       keyEncipherment   [2] POPOPrivKey,
       keyAgreement      [3] POPOPrivKey }
*/

typedef struct ProofOfPossession_st {
	/* This should be type NULL - What type is this ? */
	int type;
	union {
		ASN1_INTEGER *raVerified;
		POP_O_SIGNING_KEY *signature;
		POP_O_PRIVKEY *keyEncipherment;
		POP_O_PRIVKEY *keyAgreement;
	} value;
} X509_POP;

DECLARE_ASN1_FUNCTIONS(X509_POP)

/*
   CertReqMsg ::= SEQUENCE {
	certReq		CertificateRequest,
	pop		ProofOfPossession	OPTIONAL,
	regInfo		SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue  OPTIONAL
   }
*/

typedef struct CertReqMsg_st {
	X509_REQ *certReq;
	X509_POP *pop;
	STACK_OF(X509_ATTRIBUTE) *regInfo;
} CERT_REQ_MSG;

DECLARE_ASN1_FUNCTIONS(CERT_REQ_MSG)

/*
   TaggedRequest ::= CHOICE {
	tcr		[0] TaggedCertificationRequest,
	crm		[1] CertReqMsg,
	orm		[2] SEQUENCE {
				bodyPartID		BodyPartID,
				requestMessageType	OBJECT IDENTIFIER,
				requestMessageValue	ANY DEFINED BY requestMessageType
			}
   }
*/

typedef struct OtherReqMsg_st {
	ASN1_INTEGER *bodyPartID;
	ASN1_OBJECT *requestMessageType;
	ASN1_TYPE *requestMessageValue;
} OTHER_REQ_MSG;

DECLARE_ASN1_FUNCTIONS(OTHER_REQ_MSG)

typedef struct TaggedRequest_st {
	int type;
	union {
		TAGGED_CERTIFICATION_REQUEST *tcr;
		CERT_REQ_MSG *crm;
		OTHER_REQ_MSG *orm;
	} value;
} TAGGED_REQUEST;

DECLARE_ASN1_FUNCTIONS(TAGGED_REQUEST)


/*
   PKI_DATA ::= SEQUENCE {
	controlSequence		SEQUENCE SIZE(0..MAX) OF TAGGED_ATTRIBUTE,
	reqSequence		SEQUENCE SIZE(0..MAX) OF TaggedRequest,
	cmsSequence		SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	otherMsgSequence	SEQUENCE SIZE(0..MAX) OF OTHER_MSG
   }
*/

typedef struct PKIData_st {
	STACK_OF(TAGGED_ATTRIBUTE) *controlSequence;
	STACK_OF(TAGGED_REQUEST) * reqSequence;
	STACK_OF(TAGGED_CONTENT_INFO) *cmsSequence;
	STACK_OF(OTHER_MSG) *otherMsgSequence;
} PKI_DATA;

DECLARE_ASN1_FUNCTIONS(PKI_DATA)

/*
   RESPONSE_BODY ::= SEQUENCE {
	controlSequence		SEQUENCE SIZE(0..MAX) OF TAGGED_ATTRIBUTE,
	cmsSequence		SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	otherMsgSequence	SEQUENCE SIZE(0..MAX) OF OTHER_MSG
   }
*/

typedef struct ResponseBody_st {
	STACK_OF(TAGGED_ATTRIBUTE) *controlSequence;
	STACK_OF(TAGGED_CONTENT_INFO) *cmsSequence;
	STACK_OF(OTHER_MSG) *otherMsgSequence;
} RESPONSE_BODY;

DECLARE_ASN1_FUNCTIONS(RESPONSE_BODY)

#include <libpki/cmc/cms_cert_req.h>

/* End _LIBPKI_CMS_H */
#endif
