/* PRQP Implementation
 * (c) 2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPKI_PRQP_H
#define _LIBPKI_PRQP_H	1
# pragma once

#include <libpki/compat.h>

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/datatypes.h>
#endif

#include <libpki/openssl/data_st.h>

BEGIN_C_DECLS

#define PKI_PRQP_LIB_CONF_FILE 			PKI_DEFAULT_ETC_DIR"/pki.conf"
#define PKI_PRQP_LIB_CONF_ENTRY_LONG 	"queryauthority"
#define PKI_PRQP_LIB_CONF_ENTRY_SHORT 	"rqa"

#define PKI_PRQP_DEFAULT_PORT			830
#define PKI_PRQP_REQ_CONTENT_TYPE		"application/prqp-request"
#define PKI_PRQP_RESP_CONTENT_TYPE		"application/prqp-response"

/*
#define PRQP_KP_PRQP_SIGNING_OID		""
#define PRQP_KP_PRQP_SIGNING_OID_TEXT		""

#define SERVICE_TYPE__OID			"1.3.6."
#define SERVICE_TYPE__OID_STRING		""

#define SERVICE_TYPE_OCSP_OID             	"1.3.6.1.113733.9.1.1"
#define SERVICE_TYPE_OCSP_OID_STRING     	"OCSP"
#define SERVICE_TYPE_CRL_OID          		"1.3.6.1.113733.9.1.2"
#define SERVICE_TYPE_CRL_OID_STRING		"CRL"
#define SERVICE_TYPE_TIMESTAMPING_OID         	"1.3.6.1.113733.9.1.3"
#define SERVICE_TYPE_TIMESTAMPING_OID_STRING  	"TS"
#define SERVICE_TYPE_DVCS_OID                	"1.3.6.1.113733.9.1.4"
#define SERVICE_TYPE_DVCS_OID_STRING         	"DVCS"
#define SERVICE_TYPE_SCVP_OID                	"1.3.6.1.113733.9.1.5"
#define SERVICE_TYPE_SCVP_OID_STRING         	"SCVP"
#define SERVICE_TYPE_REVOKE_OID                	"1.3.6.1.113733.9.1.6"
#define SERVICE_TYPE_REVOKE_OID_STRING         	"REVOKE"
#define SERVICE_TYPE_SUBSCRIBE_OID          	"1.3.6.1.113733.9.1.7"
#define SERVICE_TYPE_SUBSCRIBE_OID_STRING   	"SUBSCRIBE"
*/

#define PKI_RESOURCE_TYPE_UNKNOWN			0
#define PKI_RESOURCE_TYPE_OCSP				1
#define PKI_RESOURCE_TYPE_CA_ISSUERS		2
#define PKI_RESOURCE_TYPE_TIMESTAMPING		3
#define PKI_RESOURCE_TYPE_SCVP				4
#define PKI_RESOURCE_TYPE_CA_REPOSITORY		5
#define PKI_RESOURCE_TYPE_HTTP_CERTS		6
#define PKI_RESOURCE_TYPE_HTTP_CRL			7
#define PKI_RESOURCE_TYPE_CROSS_CERTS		8
#define PKI_RESOURCE_TYPE_XKMS_GATEWAY		9
#define PKI_RESOURCE_TYPE_CMS_GATEWAY		10
#define PKI_RESOURCE_TYPE_SCEP_GATEWAY		11
#define PKI_RESOURCE_TYPE_CERT_POLICY		12
#define PKI_RESOURCE_TYPE_CPS				13
#define PKI_RESOURCE_TYPE_LOA_POLICY		14
#define PKI_RESOURCE_TYPE_LOA_LEVEL			15
#define PKI_RESOURCE_TYPE_HTML_REVOKE		16
#define PKI_RESOURCE_TYPE_HTML_REQUEST		17
#define PKI_RESOURCE_TYPE_HTML_RENEW		18
#define PKI_RESOURCE_TYPE_HTML_SUSPEND		19
#define PKI_RESOURCE_TYPE_WEBDAV_CERT		20
#define PKI_RESOURCE_TYPE_WEBDAV_REV		21

#define PKI_RESOURCE_TYPE_GRID_ACCREDITATION_BODY	22
#define PKI_RESOURCE_TYPE_GRID_ACCREDITATION_POLICY	23
#define PKI_RESOURCE_TYPE_GRID_ACCREDITATION_STATUS	24
#define PKI_RESOURCE_TYPE_GRID_DISTRIBUTION_UPDATE	25
#define PKI_RESOURCE_TYPE_GRID_ACCREDITED_CA_CERTS	26

#define PKI_RESOURCE_TYPE_TAMP_UPDATE			27
#define PKI_RESOURCE_TYPE_PRQP					28

#define PKI_RESOURCE_TYPE_DELTA_CRL_REPOSITORY	29
#define PKI_RESOURCE_TYPE_CRL_REPOSITORY		30

/* PRQP STATUS INFO STRING and VALUES */

#define PKI_X509_PRQP_STATUS_STRING_OK				"Ok"
#define PKI_X509_PRQP_STATUS_STRING_BAD_REQUEST		"Bad Request"
#define PKI_X509_PRQP_STATUS_STRING_CA_NOT_PRESENT	"CA Not Present"
#define PKI_X509_PRQP_STATUS_STRING_SYS_FAILURE		"System Failure"
#define PKI_X509_PRQP_STATUS_STRING_UNKNOWN			"Unknown"

#define PKI_X509_PRQP_STATUS_STRING_NUM			4

typedef enum {
	PKI_X509_PRQP_STATUS_UNKNOWN = -1,
	PKI_X509_PRQP_STATUS_OK = 0,
	PKI_X509_PRQP_STATUS_BAD_REQUEST = 1,
	PKI_X509_PRQP_STATUS_CA_NOT_PRESENT = 2,
	PKI_X509_PRQP_STATUS_SYS_FAILURE = 3
} PKI_X509_PRQP_STATUS;


// #ifdef __PKI_PRQP_LIB_C__

// static char *prqp_exts_services[] = {
// 	"1.3.6.1.5.5.7.48.12.0", "rqa", "PRQP RQA Server",
// 	"1.3.6.1.5.5.7.48.12.1", "ocspServer", "OCSP Server",
// 	"1.3.6.1.5.5.7.48.12.2", "subjectCert", "Subject Certificate Retieval URI",
// 	"1.3.6.1.5.5.7.48.12.3", "issuerCert", "Issuer's Certificate Retieval URI",
// 	"1.3.6.1.5.5.7.48.12.4", "timeStamp", "TimeStamping Service",
// 	/* PKIX - not yet defined */
// 	"1.3.6.1.5.5.7.48.12.5", "scvp", "SCVP Service",
// 	"1.3.6.1.5.5.7.48.12.6", "crlDistribution", "Latest CRL URI",
// 	"1.3.6.1.5.5.7.48.12.7", "certRepository", "CMS Certificate Repository",
// 	"1.3.6.1.5.5.7.48.12.8", "crlRepository", "CMS CRL Repository",
// 	"1.3.6.1.5.5.7.48.12.9", "crossCertRepository", "CMS Cross Certificate Repository",
// 	/* Gateways */
// 	"1.3.6.1.5.5.7.48.12.10", "cmcGateway", "CMC Gateway",
// 	"1.3.6.1.5.5.7.48.12.11", "scepGateway", "SCEP Gateway",
// 	"1.3.6.1.5.5.7.48.12.12", "htmlGateway", "HTML Gateway",
// 	"1.3.6.1.5.5.7.48.12.13", "xkmsGateway", "XKMS Gateway",
// 	/* Certificate Policies */
// 	"1.3.6.1.5.5.7.48.12.20", "certPolicy", "Certificate Policy (CP) URL",
// 	"1.3.6.1.5.5.7.48.12.21", "certPracticeStatement", "Certificate Practices Statement (CPS) URL",
// 	"1.3.6.1.5.5.7.48.12.22", "endorsedTA", "CMS Endorsed Trust Anchors",
// 	/* Level of Assurance (LOA) */
// 	"1.3.6.1.5.5.7.48.12.25", "loaPolicy", "LOA Policy URL",
// 	"1.3.6.1.5.5.7.48.12.26", "certLOALevel", "Certificate LOA Modifier URL",
// 	/* HTTP (Browsers) based services */
// 	"1.3.6.1.5.5.7.48.12.30", "htmlRequest", "HTML Certificate Request Service URL",
// 	"1.3.6.1.5.5.7.48.12.31", "htmlRevoke", "HTML Based Certificate Revocation Service URL",
// 	"1.3.6.1.5.5.7.48.12.32", "htmlRenew", "HTML Certificate Renewal Service URL",
// 	"1.3.6.1.5.5.7.48.12.33", "htmlSuspend", "HTML Certificate Suspension Service",
// 	/* Webdav Services */
// /*
// 	"1.3.6.1.5.5.7.48.12.40", "webdavCert", "Webdav Certificate Validation URL",
// 	"1.3.6.1.5.5.7.48.12.41", "webdavRev", "Webdav Certificate Revocation URL",
// */

// 	/* Grid Specific Services */
// 	"1.3.6.1.5.5.7.48.12.50", "gridAccreditationBody", "CA Accreditation Bodies",
// 	"1.3.6.1.5.5.7.48.12.51", "gridAccreditationPolicy", "CA Accreditation Policy Document(s) URL",
// 	"1.3.6.1.5.5.7.48.12.52", "gridAccreditationStatus", "CA Accreditation Status Document(s) URL",
// 	"1.3.6.1.5.5.7.48.12.53", "gridDistributionUpdate", "Grid Distribution Package(s) URL",
// 	"1.3.6.1.5.5.7.48.12.54", "gridAccreditedCACerts", "Certificates of Currently Accredited CAs",
// 	/* Trust Anchors Publishing */
// 	"1.3.6.1.5.5.7.48.71", "apexTampUpdate", "APEX Trust Anchors Update URL",
// 	"1.3.6.1.5.5.7.48.70", "tampUpdate", "Trust Anchors Update URL",
// 	/* CA Incident report URL */
// 	"1.3.6.1.5.5.7.48.90", "caIncidentReport", "CA Incident Report URL",
// 	/* Private Services */
// 	"1.3.6.1.5.5.7.48.12.100", "privateSvc", "Private Service",
// 	/* Other PKI */
// 	// "2.5.29.27", "deltaCrl", "Delta CRL Base Address",
// 	// "2.5.29.31", "crl", "CRL Repository",
// 	/* End of the List */
//        	NULL, NULL, NULL
// };

// static char *prqp_exts[] = {
// 	/* PRQP extended key usage - id-kp-PRQPSigning ::= { id-kp 10 }*/
// 	"1.3.6.1.5.5.7.3.11", "prqpSigning", "PRQP Signing",
// 	/* PRQP PKIX identifier - id-prqp ::= { id-pkix 23 } */
// 	"1.3.6.1.5.5.7.23", "PRQP", "PKI Resource Query Protocol",
// 	/* PRQP PKIX - PTA identifier - { id-prqp 1 } */
// 	"1.3.6.1.5.5.7.23.1", "PTA", "PRQP Trusted Authority",
// 	/* PRQP AD id-ad-prqp ::= { id-ad   12 } */
// 	"1.3.6.1.5.5.7.48.12", "prqp", "PRQP Service",
// 	/* End of the List */
//        	NULL, NULL, NULL
// };
// #endif /* __PKI_PRQP_LIB_C__ */

#include <libpki/prqp/prqp_asn1.h>
#include <libpki/prqp/prqp_bio.h>
#include <libpki/prqp/prqp_stack.h>
#include <libpki/prqp/prqp_req_io.h>
#include <libpki/prqp/prqp_resp_io.h>
#include <libpki/prqp/prqp_lib.h>
#include <libpki/prqp/http_client.h>
#include <libpki/prqp/prqp_srv.h>


/* Macros for PKI_MEM conversion */
#define PKI_PRQP_REQ_mem_der(a) \
	PKI_MEM_new_func( (void *) a, i2d_PKI_PRQP_REQ )
#define PKI_PRQP_REQ_mem_pem(a) \
	PKI_MEM_new_func_bio( (void *) a, PEM_write_bio_PRQP_REQ )

END_C_DECLS

#endif // End of _LIBPKI_PRQP_H

/* end */

