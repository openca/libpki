/* PRQP Message implementation
 * (c) 2006 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPK_PRQP_ASN1_H
#define _LIBPK_PRQP_ASN1_H
                                                                                
#ifdef  __cplusplus
extern "C" {
#endif

/* PRQPSignature ::= SEQUENCE {
 *	signatureAlgorithm	AlgorithmIdentifier,
 *	signature		BIT STRING,
 *	certs			[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 */

typedef struct PRQPSignature_st {
        X509_ALGOR *signatureAlgorithm;
        ASN1_BIT_STRING *signature;
        X509 *signerCert;
        STACK_OF(X509) *otherCerts;
} PRQP_SIGNATURE;

DECLARE_ASN1_FUNCTIONS(PRQP_SIGNATURE)

/* BasicCertIdentifier ::= SEQUENCE {
 *	issuerNameHash		OCTET STRING,
 *	serialNumber		CertificateSerialNumber }
 */

typedef struct BasicCertIdentifier_st {
	ASN1_INTEGER *serialNumber;
	ASN1_OCTET_STRING * issuerNameHash;
} BASIC_CERT_IDENTIFIER;

DECLARE_ASN1_FUNCTIONS( BASIC_CERT_IDENTIFIER )

/* ExtendedCertInfo ::= SEQUENCE {
 *	certificateHash		OCTET STRING,
 *	subjectKeyHash		OCTET STRING,
 *	subjectKeyIdentifier	[0] KeyIdentifier	OPTIONAL,
 *	issuerKeyIdentifier	[1] KeyIdentifier	OPTIONAL }
 */

typedef struct ExtendedCertInfo_st {
	ASN1_OCTET_STRING * certificateHash;
	ASN1_OCTET_STRING * subjectKeyHash;
	ASN1_OCTET_STRING * subjectKeyId;
	ASN1_OCTET_STRING * issuerKeyId;
} EXTENDED_CERT_INFO;

DECLARE_ASN1_FUNCTIONS( EXTENDED_CERT_INFO )

/* CertIdentifier ::= SET {
 *	hashAlgorithm	AlgorithmIdentifier,
 *	basicCertId	BasicCertIdentifier,
 *	extInfo		[0] ExtendedCertInfo	OPTIONAL }
 */

typedef struct CertIdentifier_st {
	X509_ALGOR		* hashAlgorithm;
	BASIC_CERT_IDENTIFIER	* basicCertId;
	EXTENDED_CERT_INFO	* extInfo;
	X509			* caCert;
	X509			* issuedCert;
} CERT_IDENTIFIER;

// DECLARE_ASN1_SET_OF(CERT_IDENTIFIER)

DECLARE_ASN1_FUNCTIONS(CERT_IDENTIFIER)
CERT_IDENTIFIER *CERT_IDENTIFIER_dup( CERT_IDENTIFIER *cid );

/* ResourceIdentifier ::= SEQUENCE {
 *      resourceId      OBJECT IDENTIFIER,
 *      version         [0] INTEGER     OPTIONAL }
 */

typedef struct ResourceIdentifier_st {
	ASN1_OBJECT *resourceId;
	ASN1_INTEGER *version;
	ASN1_OBJECT *oid;
} RESOURCE_IDENTIFIER;

DECLARE_ASN1_FUNCTIONS ( RESOURCE_IDENTIFIER )
DECLARE_STACK_OF( RESOURCE_IDENTIFIER )

/* ResourceRequestToken ::= SEQUENCE {
 *	ca		certIdentifier,
 *	serviceList	[1]	SET OF ResourceIdentifier	OPTIONAL }
 */
typedef struct ResourceRequestToken_st {
	CERT_IDENTIFIER *ca;
	STACK_OF(RESOURCE_IDENTIFIER) *resourceList;
} RESOURCE_REQUEST_TOKEN;

DECLARE_ASN1_FUNCTIONS(RESOURCE_REQUEST_TOKEN)

/* TBSReqData ::= SEQUENCE {
 * 	version		INTEGER 		{v(1)},
 *	nonce		[0] INTEGER		OPTIONAL,
 *	serviceToken	ResourceRequestToken,
 *	extensions	[1] IMPLICIT Extensions	OPTIONAL }
*/
typedef struct TBSReqData_st {
	ASN1_INTEGER		* version;
	ASN1_INTEGER		* nonce;
	ASN1_GENERALIZEDTIME	* producedAt;
	RESOURCE_REQUEST_TOKEN	* serviceToken;
	STACK_OF(X509_EXTENSION)* extensions;
} PRQP_TBS_REQ_DATA;

DECLARE_ASN1_FUNCTIONS(PRQP_TBS_REQ_DATA)

/* PRQPReq ::= SEQUENCE {
 *	requestData	TBSReqData,
 *	signature	[0] Signature	OPTIONAL }
 */

typedef struct PRQPReq_st {
	PRQP_TBS_REQ_DATA *requestData;
	PRQP_SIGNATURE * prqpSignature;
} PKI_PRQP_REQ;

DECLARE_ASN1_FUNCTIONS(PKI_PRQP_REQ)

PKI_PRQP_REQ * PKI_PRQP_REQ_dup ( PKI_PRQP_REQ *x );

/* PKIStatus ::= INTEGER {
 * 	ok		{0},
 *	badRequest	{1},
 *	caNotPresent	{2},
 *	systemFailure	{3} }
 */

/*   PKIFailureInfo ::= BIT STRING {
 *	-- since we can fail in more than one way!
 *	-- More codes may be added in the future if/when required.
 *    	badAlg           (0),
 *    	-- unrecognized or unsupported Algorithm Identifier
 *    	badMessageCheck  (1),
 *    	-- integrity check failed (e.g., signature did not verify)
 *    	badRequest       (2),
 *    	-- transaction not permitted or supported
 *    	badTime          (3),
 *    	-- messageTime was not sufficiently close to the system time,
 *   	-- as defined by local policy
 *    	badCertId        (4),
 *    	-- no certificate could be found matching the provided criteria
 *    	badDataFormat    (5),
 *    	-- the data submitted has the wrong format
 *    	wrongAuthority   (6),
 *    	-- the authority indicated in the request is different from the
 *    	-- one creating the response token
 *    	incorrectData    (7),
 *    	-- the requester's data is incorrect (for notary services)
 *    	missingTimeStamp (8),
 *    	-- when the timestamp is missing but should be there (by policy)
 */

/* PKIStatusInfo ::= SEQUENCE {
 *	status		PKIStatus,
 *	statusString	PKIFreeText	OPTIONAL,
 *	failInfo	PKIFailureInfo	OPTIONAL }
 */

typedef struct PKIStatusInfo_st {
	ASN1_INTEGER *status;
	ASN1_UTF8STRING *statusString;
	ASN1_BIT_STRING *failInfo;
	STACK_OF(ASN1_IA5STRING) *referrals;
} PKI_STATUS_INFO;

DECLARE_ASN1_FUNCTIONS(PKI_STATUS_INFO)

/* ResourceInfo ::= {
 * 	resourceUri	IA5String,
 * 	version		[0] INTEGER	OPTIONAL }
 */

/*
typedef struct ResourceInfo_st {
	ASN1_IA5STRING  * resourceUri;
} RESOURCE_INFO;

DECLARE_STACK_OF(RESOURCE_INFO)
DECLARE_ASN1_FUNCTIONS(RESOURCE_INFO)
*/

/* ResourceResponseToken ::= {
 *	serviceId		OBJECT IDENTIFIER,
 *	resLocatorList		[0] EXPLICIT SEQUENCE OF ResourceInfo }
 */

typedef struct ResourceResponseToken_st {
	ASN1_OBJECT     	 *resourceId;
	STACK_OF(ASN1_IA5STRING) *resLocatorList;
	ASN1_INTEGER    	 *version;
	ASN1_OBJECT		 *oid;
	ASN1_UTF8STRING 	 *textInfo;
} RESOURCE_RESPONSE_TOKEN;

DECLARE_ASN1_FUNCTIONS(RESOURCE_RESPONSE_TOKEN)
DECLARE_STACK_OF(RESOURCE_RESPONSE_TOKEN)

RESOURCE_RESPONSE_TOKEN * RESOURCE_RESPONSE_TOKEN_dup ( RESOURCE_RESPONSE_TOKEN * p );

/* TBSRespData ::= {
 *	version		INTEGER { v(1) },
 *	nonce		[0] INTEGER		OPTIONAL,
 *	producedAt	GeneralizedTime,
 *	nextUpdate	[1] GeneralizedTime	OPTIONAL,
 *	pkiStatus	PKIStatusInfo,
 *	responseToken	[2] SEQUENCE OF ResourceResponseToken	OPTIONAL,
 *	extensions	[3] EXPLICIT Extensions	OPTIONAL }
 */

typedef struct TBSRespData_st {
	ASN1_INTEGER 				*version;
	ASN1_INTEGER				*nonce;
	PKI_STATUS_INFO	 			*pkiStatus;
	ASN1_GENERALIZEDTIME			*producedAt;
	ASN1_GENERALIZEDTIME			*nextUpdate;
	CERT_IDENTIFIER				*caCertId;
	STACK_OF(RESOURCE_RESPONSE_TOKEN) 	*responseToken;
	STACK_OF(X509_EXTENSION) 		*extensions;
} PRQP_TBS_RESP_DATA;

DECLARE_ASN1_FUNCTIONS(PRQP_TBS_RESP_DATA)

typedef struct PRQPResponse_st {
	PRQP_TBS_RESP_DATA		*respData;
	PRQP_SIGNATURE		*prqpSignature;
} PKI_PRQP_RESP;

DECLARE_ASN1_FUNCTIONS(PKI_PRQP_RESP)

PKI_PRQP_RESP * PKI_PRQP_RESP_dup ( PKI_PRQP_RESP *x );

/* Crypto Functionality */
/*
char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
             ASN1_IA5STRING *ia5);
ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
             X509V3_CTX *ctx, char *str);
*/

#ifdef  __cplusplus
}
#endif
#endif

/* end */

