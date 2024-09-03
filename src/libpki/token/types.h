
#ifndef _LIBPKI_SYSTEM_H
# include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_X509_TYPES_H
#include <libpki/x509/types.h>
#endif

#ifndef _LIBPKI_TOKEN_TYPES_H
#define _LIBPKI_TOKEN_TYPES_H

typedef enum pki_token_status_flags {
	PKI_READY						= 0x0,
	PKI_INIT_ERR					= 0x1,
	PKI_LOGIN_ERR					= 0x2,
	PKI_KEYPAIR_ERR					= 0x3,
	PKI_EE_CERT_ERR					= 0x4,
	PKI_CA_CERT_ERR					= 0x5,
	PKI_OTHER_CERTS_ERR				= 0x6,
	PKI_TRUSTED_CERTS_ERR 			= 0x7,
} PKI_STATUS_FLAG;

#define PKI_TOKEN_STATUS_SZ			8

/* Structure for PKI_TOKEN definition */
typedef struct pki_token_st {
	/*! Pointer to the HSM if one is configured for the
	   specific PKI_TOKEN */
	HSM *hsm;

	/*! Scheme used when generating KEYPAIR */
	int scheme;

	/*! Type of TOKEN (software, engine, kmf, etc... ) */
	int type;

	/*! Signature Algorithm used by the PKI_TOKEN */
	void * algor;

	/*! Digest Algorithm used by the PKI_TOKEN */
	CRYPTO_HASH hash_algorithm;

	/*! Pointer to the CA certificate */
	PKI_X509_CERT * cacert;

	/*! Pointer to the certificate */
	PKI_X509_CERT * cert;

	/*! Pointer to the certificate request */
	PKI_X509_REQ * req;

	/*! Pointer to the key */
	CRYPTO_KEYPAIR * keypair;

	/*! Pointer to CRED structure to be used when the PKI_KEYPAIR
            is to be loaded */
	PKI_CRED * cred;

	PKI_CRED * (*cred_cb)(char *);
	char *     cred_prompt;

	/*! Pointer to the stack of chain of certs */
	PKI_X509_CERT_STACK * otherCerts;

	/*! Pointer to the stack of trusted certs */
	PKI_X509_CERT_STACK * trustedCerts;

	/*! Pointer to the stack of CRLs certs */
	PKI_X509_CRL_STACK * crls;

	/*! Pointer to the certificate profile to be used when issuing
	    a certificate */
	PKI_X509_PROFILE_STACK * profiles;

	/*! Pointer to OIDs configuration profile */
	PKI_CONFIG * oids;

	/*! Pointer to the PKI_CONFIG data */
	PKI_CONFIG * config;

	/*! Config directory */
	char * config_dir;

	/*! Token Name */
	char * name;

	/*! For General Device Support */
	long slot_id;

	/*! Identifier for selected Key */
	char * key_id;

	/*! Identifier for selected Certificate */
	char * cert_id;

	/*! Identifier for selected CA Certificate */
	char * cacert_id;

	/*! Identifier for selected Certificate Request */
	char * req_id;

	/*! Token Status Flags */
	uint32_t status;

	/*! Login Status */
	uint8_t isLoggedIn;

	/*! Credentials Status */
	uint8_t isCredSet;

} PKI_TOKEN;

/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
