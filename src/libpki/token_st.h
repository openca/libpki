
#ifndef _LIBPKI_TOKEN_ST_H
#define _LIBPKI_TOKEN_ST_H
# pragma once

// LibPKI Includes
#ifndef _LIBPKI_STACK_H
#include <libpki/stack.h>
#endif

#ifndef _LIBPKI_HSM_ST_H
#include <libpki/hsm_st.h>
#endif

#ifndef _LIBPKI_CONF_H
#include <libpki/pki_config.h>
#endif

#ifndef _LIBPKI_PKI_CRED_H
#include <libpki/pki_cred.h>
#endif

#ifndef _LIBPKI_PKI_X509_CRL_H
#include <libpki/pki_x509_crl.h>
#endif

BEGIN_C_DECLS

						// ========================
						// Exported Data Structures
						// ========================

/*! \brief Data structure for PKI tokens */
typedef struct pki_token_st {
	
	/*! \brief Pointer to the HSM if one is configured for the
	   specific PKI_TOKEN */
	struct hsm_st *hsm;

	/*! \brief Scheme used when generating KEYPAIR */
	int scheme;

	/*! \brief Type of TOKEN (software, engine, kmf, etc... ) */
	int type;

	/*! \brief Signature Algorithm used by the PKI_TOKEN */
	PKI_X509_ALGOR_VALUE * algor;

	/*! \brief Digest Algorithm used by the PKI_TOKEN */
	PKI_DIGEST_ALG * digest;

	/*! \brief Pointer to the CA certificate */
	PKI_X509_CERT * cacert;

	/*! \brief Pointer to the certificate */
	PKI_X509_CERT * cert;

	/*! \brief Pointer to the certificate request */
	PKI_X509_REQ * req;

	/*! \brief Pointer to the key */
	PKI_X509_KEYPAIR * keypair;

	/*! \brief Pointer to CRED structure to be used when the PKI_KEYPAIR
            is to be loaded */
	PKI_CRED * cred;

	/*! \brief Pointer to the callback function to be used when the
	    PKI_CRED structure is not set */
	PKI_CRED * (*cred_cb)(char *);

	/*! \brief Pointer to the prompt text for the callback function */
	char *     cred_prompt;

	/*! \brief Pointer to the stack of chain of certs */
	PKI_X509_CERT_STACK * otherCerts;

	/*! \brief Pointer to the stack of trusted certs */
	PKI_X509_CERT_STACK * trustedCerts;

	/*! \brief Pointer to the stack of CRLs certs */
	PKI_X509_CRL_STACK * crls;

	/*! \brief Pointer to the certificate profile to be used when issuing
	    a certificate */
	PKI_X509_PROFILE_STACK * profiles;

	/*! \brief Pointer to OIDs configuration profile */
	PKI_CONFIG * oids;

	/*! \brief Pointer to the PKI_CONFIG data */
	PKI_CONFIG * config;

	/*! \brief Config directory */
	char * config_dir;

	/*! \brief Token Name */
	char * name;

	/*! \brief For General Device Support */
	long slot_id;

	/*! \brief Identifier for selected Key */
	char * key_id;

	/*! \brief Identifier for selected Certificate */
	char * cert_id;

	/*! \brief Identifier for selected CA Certificate */
	char * cacert_id;

	/*! \brief Identifier for selected Certificate Request */
	char * req_id;

	/*! \brief Token Status Flags */
	uint32_t status;

	/*! \brief Login Status */
	uint8_t isLoggedIn;

	/*! \brief Credentials Status */
	uint8_t isCredSet;

} PKI_TOKEN;

END_C_DECLS

#endif // End of _LIBPKI_TOKEN_ST_H
