/* PKI Resource Query Protocol Message implementation
 * (c) 2004 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

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

ASN1_SEQUENCE(PKI_STATUS_INFO) = {
	ASN1_SIMPLE(PKI_STATUS_INFO, status, ASN1_INTEGER),
	ASN1_EXP_OPT(PKI_STATUS_INFO, statusString, ASN1_UTF8STRING, 0),
	ASN1_EXP_OPT(PKI_STATUS_INFO, failInfo, ASN1_BIT_STRING, 1),
	ASN1_EXP_SEQUENCE_OF_OPT(PKI_STATUS_INFO, referrals, ASN1_IA5STRING, 2)
} ASN1_SEQUENCE_END(PKI_STATUS_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PKI_STATUS_INFO)

/* ResourceInfo ::= {
 * 	resourceUri		IA5String,
 * 	version			[0] INTEGER	OPTIONAL }
 */

/*
ASN1_SEQUENCE(RESOURCE_INFO) = {
	ASN1_SIMPLE( RESOURCE_INFO, resourceUri, ASN1_IA5STRING ),
	ASN1_EXP_OPT( RESOURCE_INFO, version, ASN1_INTEGER, 0 ),
	ASN1_EXP_OPT( RESOURCE_INFO, textInfo, ASN1_UTF8STRING, 1 )
} ASN1_SEQUENCE_END (RESOURCE_INFO)

IMPLEMENT_ASN1_FUNCTIONS( RESOURCE_INFO )
IMPLEMENT_ASN1_DUP_FUNCTION ( RESOURCE_INFO )
*/

/* ResourceResponseToken ::= {
 *	serviceId		OBJECT IDENTIFIER,
 *	resLocatorList		[0] EXPLICIT SEQUENCE OF IA5String }
 */

ASN1_SEQUENCE(RESOURCE_RESPONSE_TOKEN) = {
	ASN1_SIMPLE(RESOURCE_RESPONSE_TOKEN, resourceId, ASN1_OBJECT),
	ASN1_EXP_SEQUENCE_OF(RESOURCE_RESPONSE_TOKEN, resLocatorList, ASN1_IA5STRING, 0),
	ASN1_EXP_OPT( RESOURCE_RESPONSE_TOKEN, version, ASN1_INTEGER, 1 ),
	ASN1_EXP_OPT( RESOURCE_RESPONSE_TOKEN, oid, ASN1_OBJECT, 2 ),
	ASN1_EXP_OPT( RESOURCE_RESPONSE_TOKEN, textInfo, ASN1_UTF8STRING, 3 )
} ASN1_SEQUENCE_END(RESOURCE_RESPONSE_TOKEN)

IMPLEMENT_ASN1_FUNCTIONS(RESOURCE_RESPONSE_TOKEN)
IMPLEMENT_ASN1_DUP_FUNCTION(RESOURCE_RESPONSE_TOKEN)

/* TBSRespData ::= SEQUENCE {
 *	version		INTEGER { v(1) },
 *	pkiStatus	PKIStatusInfo,
 *	nonce		[0] INTEGER			OPTIONAL,
 *	producedAt	GeneralizedTime,
 *	nextUpdate	[1] GeneralizedTime		OPTIONAL,
 *	responseToken	[2] SEQUENCE OF ResourceResponseToken	OPTIONAL,
 *	extensions	[3] EXPLICIT Extensions	OPTIONAL }
 */
ASN1_SEQUENCE(PRQP_TBS_RESP_DATA) = {
	ASN1_SIMPLE(PRQP_TBS_RESP_DATA, version, ASN1_INTEGER),
	ASN1_EXP_OPT(PRQP_TBS_RESP_DATA, nonce, ASN1_INTEGER, 0),
	ASN1_SIMPLE(PRQP_TBS_RESP_DATA, producedAt, ASN1_GENERALIZEDTIME),
	ASN1_EXP_OPT(PRQP_TBS_RESP_DATA, nextUpdate, ASN1_GENERALIZEDTIME, 1),
	ASN1_SIMPLE(PRQP_TBS_RESP_DATA, pkiStatus, PKI_STATUS_INFO),
	ASN1_SIMPLE(PRQP_TBS_RESP_DATA, caCertId, CERT_IDENTIFIER),
	ASN1_EXP_SEQUENCE_OF_OPT(PRQP_TBS_RESP_DATA, responseToken, RESOURCE_RESPONSE_TOKEN, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(PRQP_TBS_RESP_DATA, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END(PRQP_TBS_RESP_DATA)

IMPLEMENT_ASN1_FUNCTIONS(PRQP_TBS_RESP_DATA)

/* PRQPResponse ::= SEQUENCE {
 *	respData		TBSRespData,
 *	signature		[0] EXPLICIT Signature	OPTIONAL }
 */

ASN1_SEQUENCE(PKI_PRQP_RESP) = {
	ASN1_SIMPLE(PKI_PRQP_RESP, respData, PRQP_TBS_RESP_DATA),
	ASN1_EXP_OPT(PKI_PRQP_RESP, prqpSignature, PRQP_SIGNATURE, 0)
} ASN1_SEQUENCE_END(PKI_PRQP_RESP)

IMPLEMENT_ASN1_FUNCTIONS(PKI_PRQP_RESP)

IMPLEMENT_ASN1_DUP_FUNCTION(PKI_PRQP_RESP)

/*
PKI_PRQP_RESP * PKI_PRQP_RESP_dup ( PKI_PRQP_RESP *req ) {
	ASN1_item_dup ( &PKI_PRQP_RESP_it, req );
}
*/

/* end */
