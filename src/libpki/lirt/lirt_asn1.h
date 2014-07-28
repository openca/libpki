/* LIRT Message implementation
 * (c) 2006 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPK_LIRT_ASN1_H
#define _LIBPK_LIRT_ASN1_H
                                                                                
#ifdef  __cplusplus
extern "C" {
#endif

/* LIRTSignature ::= SEQUENCE {
 *	signatureAlgorithm	AlgorithmIdentifier,
 *	signature		BIT STRING,
 *	certs			[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 */

typedef struct LIRTSignature_st {
        X509_ALGOR *signatureAlgorithm;
        ASN1_BIT_STRING *signature;
        STACK_OF(X509) *certs;
} LIRT_SIGNATURE;

DECLARE_ASN1_FUNCTIONS(LIRT_SIGNATURE)

/* LIRTargetCert ::= SEQUENCE {
 *  algorithm       AlgorithmIdentifier,
 *  certId          BIT STRING }
 */

/*
typedef struct LIRTargetCert_st {
	X509_ALGOR	*algorithm;
	ASN1_BIT_STRING	*certId;
} LIR_TARGET_CERT;

DECLARE_ASN1_FUNCTIONS(LIR_TARGET_CERT)
*/

/* LIRRevData ::= SEQUENCE {
 *  version         INTEGER { v(1) },
 *  producedAt      GeneralizedTime,
 *  revokeReason    CRLReason,
 *  caCertId        LIRTargetCert,
 *  extensions      [0] EXPLICIT Extensions OPTIONAL }
 */

/*
typedef struct LIRRevData_st {
	ASN1_INTEGER	*version;
	ASN1_GENERALIZEDTIME *producedAt;
	ASN1_INTEGER *revokeReason;
	LIR_TARGET_CERT *caCertId;
	STACK_OF(X509_EXTENSION) *extensions;
} LIR_REV_DATA;

DECLARE_ASN1_FUNCTIONS(LIR_REV_DATA)
*/

/* LIRToken ::= SEQUENCE {
 *  validFrom          GeneralizedTime,
 *  validFor           INTEGER,
 *  validityStatus     BIT STRING,
 *  signature          [1] EXPLICIT Signature }
 */
 
typedef struct LIRToken_st {
	ASN1_GENERALIZEDTIME *validFrom;
	ASN1_INTEGER *validFor;
	ASN1_BIT_STRING *validityStatus;
	LIRT_SIGNATURE *signature;
} PKI_LIRT;

DECLARE_ASN1_FUNCTIONS(PKI_LIRT)

/* LIRTbsData ::= SEQUENCE {
 *  targetCert      TBSCert,
 *  token           LIRToken }
 */

typedef struct LIRTbsData_st {
	X509_CINF *targetCert;
	PKI_LIRT *token;
} LIR_TBS_DATA;

DECLARE_ASN1_FUNCTIONS(LIR_TBS_DATA)

#ifdef  __cplusplus
}
#endif
#endif

/* end */

