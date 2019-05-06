/* LibPKI CMS Data Structure and ASN1 code
 * (c) 2004-2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the LICENSE included
 * in the archive. You can not remove this copyright notice.
 */


#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <libpki/pki.h>
#include <libpki/cms_msg.h>

/*
   PEND_INFO ::= SEQUENCE {
	pendToken		OCTET STRING,
	pendTime		GeneralizedTime
   }
*/

ASN1_SEQUENCE(PEND_INFO) = {
	ASN1_SIMPLE(PEND_INFO, pendInfo, ASN1_OCTET_STRING),
	ASN1_SIMPLE(PEND_INFO, pendTime, ASN1_GENERALIZEDTIME)
} ASN1_SEQUENCE_END(PEND_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PEND_INFO)

/*
   BODY_PART_REFERENCE ::= SEQUENCE {
	bodyPartID		BodyPartID,
	bodyPartPath		SEQUENCE SIZE(1..MAX) OF BodyPartID
   }
*/

ASN1_SEQUENCE(BODY_PART_REFERENCE) = {
	ASN1_SIMPLE( BODY_PART_REFERENCE, bodyPartID, ASN1_INTEGER),
	ASN1_SEQUENCE_OF( BODY_PART_REFERENCE, bodyPartPath, ASN1_INTEGER )
} ASN1_SEQUENCE_END(BODY_PART_REFERENCE)

IMPLEMENT_ASN1_FUNCTIONS(BODY_PART_REFERENCE)

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

ASN1_SEQUENCE(EXTENDED_FAIL_INFO) = {
	ASN1_SIMPLE(EXTENDED_FAIL_INFO, failInfoOID, ASN1_OBJECT ),
	ASN1_SIMPLE(EXTENDED_FAIL_INFO, failInfoValue, ASN1_ANY )
} ASN1_SEQUENCE_END(EXTENDED_FAIL_INFO)

IMPLEMENT_ASN1_FUNCTIONS(EXTENDED_FAIL_INFO)

ASN1_CHOICE(OTHER_INFO_EX) = {
	ASN1_SIMPLE(OTHER_INFO_EX, value.failInfo, ASN1_INTEGER),
	ASN1_SIMPLE(OTHER_INFO_EX, value.pendInfo, PEND_INFO),
	ASN1_SIMPLE(OTHER_INFO_EX, value.extendedFailInfo, EXTENDED_FAIL_INFO )
} ASN1_CHOICE_END(OTHER_INFO_EX)

IMPLEMENT_ASN1_FUNCTIONS(OTHER_INFO_EX)

ASN1_SEQUENCE(CMC_STATUS_INFO_EX) = {
	ASN1_SIMPLE(CMC_STATUS_INFO_EX, cMCStatus, ASN1_INTEGER),
	ASN1_SEQUENCE_OF(CMC_STATUS_INFO_EX, bodyList, BODY_PART_REFERENCE),
	ASN1_OPT(CMC_STATUS_INFO_EX, statusString, ASN1_UTF8STRING),
	ASN1_SIMPLE(CMC_STATUS_INFO_EX, otherInfo, OTHER_INFO_EX)
} ASN1_SEQUENCE_END(CMC_STATUS_INFO_EX)

IMPLEMENT_ASN1_FUNCTIONS(CMC_STATUS_INFO_EX)

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

ASN1_CHOICE(OTHER_INFO) = {
	ASN1_SIMPLE(OTHER_INFO, value.failInfo, ASN1_INTEGER),
	ASN1_SIMPLE(OTHER_INFO, value.pendInfo, PEND_INFO),
} ASN1_CHOICE_END(OTHER_INFO)

IMPLEMENT_ASN1_FUNCTIONS(OTHER_INFO)

ASN1_SEQUENCE(CMC_STATUS_INFO) = {
	ASN1_SIMPLE(CMC_STATUS_INFO, cMCStatusInfo, ASN1_INTEGER),
	ASN1_SEQUENCE_OF(CMC_STATUS_INFO, bodyList, ASN1_INTEGER),
	ASN1_OPT(CMC_STATUS_INFO_EX, statusString, ASN1_UTF8STRING),
	ASN1_SIMPLE(CMC_STATUS_INFO_EX, otherInfo, OTHER_INFO)
} ASN1_SEQUENCE_END(CMC_STATUS_INFO)

IMPLEMENT_ASN1_FUNCTIONS(CMC_STATUS_INFO)
	
/*
   TAGGED_ATTRIBUTE ::= SEQUENCE {
	bodyPartID		BodyPartID,
	attrType		OBJECT IDENTIFIER,
	attrValues		SET OF AttributeValue
   }
*/

ASN1_SEQUENCE(TAGGED_ATTRIBUTE) = {
	ASN1_SIMPLE( TAGGED_ATTRIBUTE, bodyPartID, ASN1_INTEGER ),
        ASN1_SIMPLE( TAGGED_ATTRIBUTE, attrType, ASN1_OBJECT),
        ASN1_SET_OF( TAGGED_ATTRIBUTE, attrValues, ASN1_ANY )
} ASN1_SEQUENCE_END( TAGGED_ATTRIBUTE )

IMPLEMENT_ASN1_FUNCTIONS(TAGGED_ATTRIBUTE)

/*
   OTHER_MSG ::= SEQUENECE {
	bodyPartID		BodyPartID,
	otherMsgType		OBJECT IDENTIFIER,
	otherMsgValue		ANY DEFINED BY otherMsgType
   }
*/

ASN1_SEQUENCE(OTHER_MSG) = {
	ASN1_SIMPLE ( OTHER_MSG, bodyPartID, ASN1_INTEGER ),
	ASN1_SIMPLE ( OTHER_MSG, otherMsgType, ASN1_OBJECT ),
	ASN1_SIMPLE ( OTHER_MSG, otherMsgValue, ASN1_ANY )
} ASN1_SEQUENCE_END(OTHER_MSG)

IMPLEMENT_ASN1_FUNCTIONS( OTHER_MSG )

/*
   CMC_UNSIGNED_DATA ::= SEQUENCE {
	bodyPartPath		SEQUENCE SIZE (1..MAX) OF BodyPartID,
	identifier		OBJECT IDENTIFIER,
	content			ANY DEFINED BY identifier
*/

ASN1_SEQUENCE(CMC_UNSIGNED_DATA) = {
	ASN1_SEQUENCE_OF( CMC_UNSIGNED_DATA, bodyPartPath, ASN1_INTEGER ),
	ASN1_SIMPLE ( CMC_UNSIGNED_DATA, identifier, ASN1_OBJECT ),
	ASN1_SIMPLE ( CMC_UNSIGNED_DATA, content, ASN1_ANY )
} ASN1_SEQUENCE_END(CMC_UNSIGNED_DATA)

IMPLEMENT_ASN1_FUNCTIONS(CMC_UNSIGNED_DATA)

/*
   ContentInfo ::= SEQUENCE {
	bodyPartID		BodyPartID,
	contentInfo		ContentInfo
   }
*/

ASN1_SEQUENCE(CONTENT_INFO) = {
	ASN1_SIMPLE(CONTENT_INFO, contentType, ASN1_OBJECT),
	ASN1_EXP_OPT(CONTENT_INFO, content, ASN1_ANY, 0 )
} ASN1_SEQUENCE_END(CONTENT_INFO)

IMPLEMENT_ASN1_FUNCTIONS(CONTENT_INFO)

/*
   TaggedContentInfo ::= SEQUENCE {
	bodyPartID		BodyPartID,
	contentInfo		ContentInfo
   }
*/

ASN1_SEQUENCE(TAGGED_CONTENT_INFO) = {
	ASN1_SIMPLE( TAGGED_CONTENT_INFO, bodyPartID, ASN1_INTEGER),
	ASN1_SIMPLE( TAGGED_CONTENT_INFO, contentInfo, CONTENT_INFO)
} ASN1_SEQUENCE_END(TAGGED_CONTENT_INFO)

IMPLEMENT_ASN1_FUNCTIONS(TAGGED_CONTENT_INFO)

/*
   TaggedCertificationRequest ::= SEQUENCE {
	bodyPartID		BodyPartID,
	certificationRequest	CertificationRequest
   }
*/

ASN1_SEQUENCE(TAGGED_CERTIFICATION_REQUEST) = {
	ASN1_SIMPLE(TAGGED_CERTIFICATION_REQUEST, bodyPartID, ASN1_INTEGER),
	ASN1_SIMPLE(TAGGED_CERTIFICATION_REQUEST, certificationRequest, X509_REQ),
} ASN1_SEQUENCE_END(TAGGED_CERTIFICATION_REQUEST)

IMPLEMENT_ASN1_FUNCTIONS(TAGGED_CERTIFICATION_REQUEST)

/*
   PKMACValue ::= SEQUENCE {
      algId  AlgorithmIdentifier,
      -- the algorithm value shall be PasswordBasedMac
      --     {1 2 840 113533 7 66 13}
      -- the parameter value is PBMParameter
      value  BIT STRING }
*/

ASN1_SEQUENCE(PKMAC_VALUE) = {
	ASN1_SIMPLE(PKMAC_VALUE, algID, X509_ALGOR),
	ASN1_SIMPLE(PKMAC_VALUE, value, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKMAC_VALUE)

IMPLEMENT_ASN1_FUNCTIONS(PKMAC_VALUE)

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

ASN1_CHOICE(AUTH_INFO) = {
	ASN1_EXP(AUTH_INFO, value.sender, X509_NAME, 0),
	ASN1_EXP(AUTH_INFO, value.publicKeyMAC, PKMAC_VALUE, 1)
} ASN1_CHOICE_END(AUTH_INFO)

IMPLEMENT_ASN1_FUNCTIONS(AUTH_INFO)

ASN1_SEQUENCE(PUBKEY_INFO) = {
	ASN1_SIMPLE(PUBKEY_INFO, algorithm, X509_ALGOR),
	ASN1_SIMPLE(PUBKEY_INFO, subjectPublicKey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PUBKEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PUBKEY_INFO)

ASN1_SEQUENCE(POP_O_SIGNING_KEY_INPUT) = {
	ASN1_SIMPLE(POP_O_SIGNING_KEY_INPUT, authInfo, AUTH_INFO),
	ASN1_SIMPLE(POP_O_SIGNING_KEY_INPUT, publicKey, PUBKEY_INFO)
} ASN1_SEQUENCE_END(POP_O_SIGNING_KEY_INPUT)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_SIGNING_KEY_INPUT)

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

ASN1_SEQUENCE(POP_O_SIGNING_KEY) = {
	ASN1_EXP_OPT(POP_O_SIGNING_KEY, poposkInput, POP_O_SIGNING_KEY_INPUT, 0),
	ASN1_SIMPLE(POP_O_SIGNING_KEY, algorithmIdentifier, X509_ALGOR),
	ASN1_SIMPLE(POP_O_SIGNING_KEY, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(POP_O_SIGNING_KEY)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_SIGNING_KEY)

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

ASN1_CHOICE(POP_O_PRIVKEY) = {
	ASN1_EXP(POP_O_PRIVKEY, value.thisMessage, ASN1_BIT_STRING, 0),
	ASN1_EXP(POP_O_PRIVKEY, value.subsequentMessage, ASN1_INTEGER, 1),
	ASN1_EXP(POP_O_PRIVKEY, value.dhMAC, ASN1_BIT_STRING, 2)
} ASN1_CHOICE_END(POP_O_PRIVKEY)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_PRIVKEY)

/*
   ProofOfPossession ::= CHOICE {
       raVerified        [0] NULL,
       -- used if the RA has already verified that the requester is in
       -- possession of the private key
       signature         [1] POPOSigningKey,
       keyEncipherment   [2] POPOPrivKey,
       keyAgreement      [3] POPOPrivKey }
*/

ASN1_CHOICE(X509_POP) = {
	ASN1_EXP(X509_POP, value.raVerified, ASN1_INTEGER, 0),
	ASN1_EXP(X509_POP, value.signature, POP_O_SIGNING_KEY, 1),
	ASN1_EXP(X509_POP, value.keyEncipherment, POP_O_PRIVKEY, 2),
	ASN1_EXP(X509_POP, value.keyAgreement, POP_O_PRIVKEY, 3)
} ASN1_CHOICE_END(X509_POP)

IMPLEMENT_ASN1_FUNCTIONS(X509_POP)

/*
   CertReqMsg ::= SEQUENCE {
	certReq		CertificateRequest,
	pop		ProofOfPossession	OPTIONAL,
	regInfo		SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue  OPTIONAL
   }
*/

ASN1_SEQUENCE(CERT_REQ_MSG) = {
	ASN1_SIMPLE(CERT_REQ_MSG, certReq, X509_REQ ),
	ASN1_OPT(CERT_REQ_MSG, pop, X509_POP ),
	ASN1_SEQUENCE_OF_OPT(CERT_REQ_MSG, certReq, X509_REQ )
} ASN1_SEQUENCE_END(CERT_REQ_MSG)

IMPLEMENT_ASN1_FUNCTIONS(CERT_REQ_MSG)

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

ASN1_SEQUENCE(OTHER_REQ_MSG) = {
	ASN1_SIMPLE(OTHER_REQ_MSG, bodyPartID, ASN1_INTEGER),
	ASN1_SIMPLE(OTHER_REQ_MSG, requestMessageType, ASN1_OBJECT),
	ASN1_SIMPLE(OTHER_REQ_MSG, requestMessageValue, ASN1_ANY),
} ASN1_SEQUENCE_END(OTHER_REQ_MSG)

IMPLEMENT_ASN1_FUNCTIONS(OTHER_REQ_MSG)

ASN1_CHOICE(TAGGED_REQUEST) = {
	ASN1_EXP(TAGGED_REQUEST, value.tcr, TAGGED_CERTIFICATION_REQUEST, 0),
	ASN1_EXP(TAGGED_REQUEST, value.crm, CERT_REQ_MSG, 1),
	ASN1_EXP(TAGGED_REQUEST, value.orm, OTHER_REQ_MSG, 2)
} ASN1_CHOICE_END(TAGGED_REQUEST)

IMPLEMENT_ASN1_FUNCTIONS(TAGGED_REQUEST)

/*
   PKI_DATA ::= SEQUENCE {
	controlSequence		SEQUENCE SIZE(0..MAX) OF TAGGED_ATTRIBUTE,
	reqSequence		SEQUENCE SIZE(0..MAX) OF TaggedRequest,
	cmsSequence		SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	otherMsgSequence	SEQUENCE SIZE(0..MAX) OF OTHER_MSG
   }
*/

ASN1_SEQUENCE(PKI_DATA) = {
	 ASN1_EXP_SEQUENCE_OF_OPT(PKI_DATA, controlSequence, TAGGED_ATTRIBUTE, 0),
	 ASN1_EXP_SEQUENCE_OF_OPT(PKI_DATA, reqSequence, TAGGED_REQUEST, 1),
	 ASN1_EXP_SEQUENCE_OF_OPT(PKI_DATA, cmsSequence, TAGGED_CONTENT_INFO, 2),
	 ASN1_EXP_SEQUENCE_OF_OPT(PKI_DATA, otherMsgSequence, OTHER_MSG, 3)
} ASN1_SEQUENCE_END(PKI_DATA)

IMPLEMENT_ASN1_FUNCTIONS(PKI_DATA)

/*
   RESPONSE_BODY ::= SEQUENCE {
	controlSequence		SEQUENCE SIZE(0..MAX) OF TAGGED_ATTRIBUTE,
	cmsSequence		SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	otherMsgSequence	SEQUENCE SIZE(0..MAX) OF OTHER_MSG
   }
*/

ASN1_SEQUENCE(RESPONSE_BODY) = {
	 ASN1_EXP_SEQUENCE_OF_OPT(RESPONSE_BODY, controlSequence, TAGGED_ATTRIBUTE, 0),
	 ASN1_EXP_SEQUENCE_OF_OPT(RESPONSE_BODY, cmsSequence, TAGGED_CONTENT_INFO, 1),
	 ASN1_EXP_SEQUENCE_OF_OPT(RESPONSE_BODY, otherMsgSequence, OTHER_MSG, 2)
} ASN1_SEQUENCE_END(RESPONSE_BODY)

IMPLEMENT_ASN1_FUNCTIONS(RESPONSE_BODY)

