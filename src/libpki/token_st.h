
#ifndef _LIBPKI_TOKEN_H
#define _LIBPKI_TOKEN_H

#include <libpki/stack.h>
#include <libpki/drivers/engine/engine_st.h>
#include <libpki/hsm_st.h>

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
	PKI_X509_ALGOR_VALUE * algor;

	/*! Digest Algorithm used by the PKI_TOKEN */
	PKI_DIGEST_ALG * digest;

	/*! Pointer to the CA certificate */
	PKI_X509_CERT * cacert;

	/*! Pointer to the certificate */
	PKI_X509_CERT * cert;

	/*! Pointer to the certificate request */
	PKI_X509_REQ * req;

	/*! Pointer to the key */
	PKI_X509_KEYPAIR * keypair;

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

} PKI_TOKEN;

/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
