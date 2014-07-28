/* Lightweight Internet Revocation Tokens implementation
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

/* Signature ::= SEQUENCE {
 *	signatureAlgorithm	AlgorithmIdentifier,
 *	signature		BIT STRING,
 *	certs			[0] EXPLICIT SEQUENCE OF Certificate OPT }
 */

ASN1_SEQUENCE(LIRT_SIGNATURE) = {
	ASN1_SIMPLE(LIRT_SIGNATURE, signatureAlgorithm, X509_ALGOR ),
	ASN1_SIMPLE(LIRT_SIGNATURE, signature, ASN1_BIT_STRING),
	ASN1_EXP_SEQUENCE_OF_OPT(LIRT_SIGNATURE, certs, X509, 0)
} ASN1_SEQUENCE_END(LIRT_SIGNATURE)

IMPLEMENT_ASN1_FUNCTIONS(LIRT_SIGNATURE)

/* LIRTargetCert ::= SEQUENCE {
 *  algorithm       AlgorithmIdentifier,
 *  certId          BIT STRING }
 */

/*
ASN1_SEQUENCE(LIR_TARGET_CERT) = {
	ASN1_SIMPLE(LIR_TARGET_CERT, algorithm, X509_ALGOR),
	ASN1_SIMPLE(LIR_TARGET_CERT, certId, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(LIR_TARGET_CERT)

IMPLEMENT_ASN1_FUNCTIONS(LIR_TARGET_CERT)
IMPLEMENT_ASN1_DUP_FUNCTION(LIR_TARGET_CERT)
*/

/* LIRRevData ::= SEQUENCE {
 *  version         INTEGER { v(1) },
 *  producedAt      GeneralizedTime,
 *  revokeReason    CRLReason,
 *  caCertId				LIRTargetCert,
 *  extensions      [0] EXPLICIT Extensions OPTIONAL }
 */

/*
ASN1_SEQUENCE(LIR_REV_DATA) = {
	ASN1_SIMPLE(LIR_REV_DATA, version, ASN1_INTEGER),
	ASN1_SIMPLE(LIR_REV_DATA, producedAt, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(LIR_REV_DATA, revokeReason, ASN1_INTEGER),
	ASN1_SIMPLE(LIR_REV_DATA, caCertId, LIR_TARGET_CERT),
	ASN1_IMP_SEQUENCE_OF_OPT(LIR_REV_DATA, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(LIR_REV_DATA)

IMPLEMENT_ASN1_FUNCTIONS(LIR_REV_DATA)
*/

/* LIRToken ::= SEQUENCE {
 *  validFrom          GeneralizedTime,
 *  validFor           INTEGER,
 *  validityStatus     BIT STRING,
 *  signature          [1] EXPLICIT Signature }
 */

ASN1_SEQUENCE(PKI_LIRT) = {
	ASN1_SIMPLE(PKI_LIRT, validFrom, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(PKI_LIRT, validFor, ASN1_INTEGER),
	ASN1_SIMPLE(PKI_LIRT, validityStatus, ASN1_BIT_STRING),
	ASN1_EXP(PKI_LIRT, signature, LIRT_SIGNATURE, 1)
} ASN1_SEQUENCE_END(PKI_LIRT)

IMPLEMENT_ASN1_FUNCTIONS(PKI_LIRT)

/* LIRTbsData ::= SEQUENCE {
 *  targetCert      TBSCert,
 *  token           LIRToken }
 */

/*
ASN1_SEQUENCE(LIRT_TBS_DATA) = {
	ASN1_SIMPLE(LIRT_TBS_DATA, targetCert, X509_CINF ),
	ASN1_SIMPLE(LIRT_TBS_DATA, token, PKI_LIRT)
} ASN1_SEQUENCE_END(LIRT_TBS_DATA)

IMPLEMENT_ASN1_FUNCTIONS(LIRT_TBS_DATA)
*/

// IMPLEMENT_ASN1_DUP_FUNCTION(PKI_LIRT_REQ)

/*
PKI_LIRT_REQ * PKI_LIRT_REQ_dup ( PKI_LIRT_REQ *req ) {
	ASN1_item_dup ( &PKI_LIRT_REQ_it, req );
}
*/

/* end */
