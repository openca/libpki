/* libconf/types.h */

#ifndef _LIBPKI_CORE_TYPES_H
#define _LIBPKI_CORE_TYPES_H

/* PKI Datatypes */
typedef enum {

	/* Crypto Datatype */
	PKI_TYPE_ANY = 0,
	PKI_TYPE_PUBKEY,
	PKI_TYPE_PRIVKEY,
	PKI_TYPE_SECRET_KEY,
	PKI_TYPE_CRED,

	/* X509 object types */
	PKI_TYPE_X509_PRIVKEY,
	PKI_TYPE_X509_PUBKEY,
	PKI_TYPE_X509_CERT,
	PKI_TYPE_X509_CRL,
	PKI_TYPE_X509_REQ,
	PKI_TYPE_X509_PKCS7,
	PKI_TYPE_X509_CMS,
	PKI_TYPE_X509_PKCS12,
	PKI_TYPE_X509_OCSP_REQ,
	PKI_TYPE_X509_OCSP_RESP,
	PKI_TYPE_X509_PRQP_REQ,
	PKI_TYPE_X509_PRQP_RESP,
	PKI_TYPE_X509_CMS_MSG,
	PKI_TYPE_X509_XPAIR,

	/* Non-X509 Object types */
	PKI_TYPE_EST_MSG,
	PKI_TYPE_SCEP_MSG,

	/* X509 Certificate Types */
	PKI_TYPE_X509_,
	PKI_TYPE_X509_CERT_CA,
	PKI_TYPE_X509_CERT_EE,
	PKI_TYPE_X509_CERT_ROOT,

	/* Special Extensions */
	PKI_TYPE_X509_EXTENSIONS,
	PKI_TYPE_X509_EXT_BASIC_CONSTRAINTS,
	PKI_TYPE_X509_EXT_KEY_USAGE,
	PKI_TYPE_X509_EXT_EXT_KEY_USAGE,
	PKI_TYPE_X509_EXT_SUBJECT_KEY_ID,
	PKI_TYPE_X509_EXT_AUTH_KEY_ID,
	PKI_TYPE_X509_EXT_CRL_DIST_POINTS,
	PKI_TYPE_X509_EXT_AUTH_INFO_ACCESS,
	PKI_TYPE_X509_EXT_SUBJECT_ALT_NAME,
	PKI_TYPE_X509_EXT_ISSUER_ALT_NAME,
	PKI_TYPE_X509_EXT_NAME_CONSTRAINTS,
	PKI_TYPE_X509_EXT_POLICY_CONSTRAINTS,
	PKI_TYPE_X509_EXT_POLICY_MAPPINGS,

	/* Revocation */
	PKI_TYPE_X509_EXT_CRL_NUMBER,
	PKI_TYPE_X509_EXT_REASON_CODE,
	PKI_TYPE_X509_EXT_INVALIDITY_DATE,
	PKI_TYPE_X509_EXT_DELTA_CRL_INDICATOR,
	PKI_TYPE_X509_EXT_ISSUING_DIST_POINT,
	PKI_TYPE_X509_EXT_FRESHEST_CRL,

	/* Policy */
	PKI_TYPE_X509_EXT_POLICY,
	PKI_TYPE_X509_EXT_POLICY_CONSTRAINTS,
	PKI_TYPE_X509_EXT_POLICY_MAPPINGS,
	PKI_TYPE_X509_EXT_INHIBIT_ANY_POLICY,

	/* X509 data types */
	PKI_TYPE_X509_ALGOR,
	PKI_TYPE_X509_SERIAL,
	PKI_TYPE_X509_VERSION,
	PKI_TYPE_X509_SUBJECT,
	PKI_TYPE_X509_ISSUER,
	PKI_TYPE_X509_VALIDITY,
	PKI_TYPE_X509_SIGNATURE,
	PKI_TYPE_X509_PUBKEY,
	PKI_TYPE_X509_EXTENSION,
	PKI_TYPE_X509_OBJECT,
	PKI_TYPE_X509_NOTBEFORE,
	PKI_TYPE_X509_NOTAFTER,
	PKI_TYPE_X509_THISUPDATE,
	PKI_TYPE_X509_LASTUPDATE,
	PKI_TYPE_X509_NEXTUPDATE,
	PKI_TYPE_X509_PRODUCEDAT,
	PKI_TYPE_X509_ALGORITHM,
	PKI_TYPE_X509_KEYSIZE,
	PKI_TYPE_X509_KEYPAIR_VALUE,
	PKI_TYPE_X509_X509_PUBKEY,
	PKI_TYPE_X509_PUBKEY_BITSTRING,
	PKI_TYPE_X509_PRIVKEY,
	PKI_TYPE_X509_SIGNATURE,
	PKI_TYPE_X509_SIGNATURE_ALG1,
	PKI_TYPE_X509_SIGNATURE_ALG2,
	PKI_TYPE_X509_NONCE,

	/* X500 Names */
	PKI_TYPE_X500_CN,
	PKI_TYPE_X500_C,
	PKI_TYPE_X500_L,
	PKI_TYPE_X500_ST,
	PKI_TYPE_X500_O,
	PKI_TYPE_X500_OU,
	PKI_TYPE_X500_EMAIL,
	PKI_TYPE_X500_UID,
	PKI_TYPE_X500_DC,
	PKI_TYPE_X500_SN,

	/* Certificate Types */
	PKI_TYPE_X509_CA,
	PKI_TYPE_X509_ROOT,
	PKI_TYPE_X509_END_ENTITY,

	/* Trust Settings (PKCS#11 driver)*/
	PKI_TYPE_TRUST_ROOT,
	PKI_TYPE_TRUST_OTHER,
	PKI_TYPE_TRUST_DEPRECATED,

	/* Data Format */
	PKI_TYPE_FORMAT_RAW,
	PKI_TYPE_FORMAT_B64,
	PKI_TYPE_FORMAT_ASN1,
	PKI_TYPE_FORMAT_PEM,
	PKI_TYPE_FORMAT_TXT,
	PKI_TYPE_FORMAT_XML,
	PKI_TYPE_FORMAT_URL,

	/* Custom Type */
	PKI_TYPE_CUSTOM,
} PKI_TYPE;

/* \brief Maximum value for PKI_TYPE */
#define PKI_TYPE_MAX		PKI_TYPE_CUSTOM

#endif /* _LIBPKI_CORE_TYPES_H */