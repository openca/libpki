/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

// Library configuration
#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
#define _LIBPKI_PKI_DATATYPES_H	

BEGIN_C_DECLS 

/* Supported Datatype for retrieving data from an X509 data object */
typedef enum {
	PKI_X509_DATA_SERIAL		= 0,
	PKI_X509_DATA_VERSION,
	PKI_X509_DATA_SUBJECT,
	PKI_X509_DATA_ISSUER,
	PKI_X509_DATA_NOTBEFORE,
	PKI_X509_DATA_NOTAFTER,
	PKI_X509_DATA_THISUPDATE,
	PKI_X509_DATA_LASTUPDATE,
	PKI_X509_DATA_NEXTUPDATE,
	PKI_X509_DATA_PRODUCEDAT,
	PKI_X509_DATA_ALGORITHM,
	PKI_X509_DATA_KEYSIZE,
	PKI_X509_DATA_KEYPAIR_VALUE,
	PKI_X509_DATA_X509_PUBKEY,
	PKI_X509_DATA_PUBKEY_BITSTRING,
	PKI_X509_DATA_PRIVKEY,
	PKI_X509_DATA_SIGNATURE,
	PKI_X509_DATA_SIGNATURE_ALG1,
	PKI_X509_DATA_SIGNATURE_ALG2,
	PKI_X509_DATA_TBS_MEM_ASN1,
	PKI_X509_DATA_SIGNER_CERT,
	PKI_X509_DATA_SIGNATURE_CERTS,
	PKI_X509_DATA_PRQP_SERVICES,
	PKI_X509_DATA_PRQP_STATUS_STRING,
	PKI_X509_DATA_PRQP_STATUS_VALUE,
	PKI_X509_DATA_PRQP_REFERRALS,
	PKI_X509_DATA_PRQP_CAID,
	PKI_X509_DATA_NONCE,
	PKI_X509_DATA_CERT_TYPE,
	PKI_X509_DATA_EXTENSIONS
} PKI_X509_DATA;

#define PKI_X509_DATA_SIZE     30

typedef enum {
	PKI_X509_CERT_TYPE_UNKNOWN	= 0,
	PKI_X509_CERT_TYPE_CA		= (1<<0),
	PKI_X509_CERT_TYPE_USER		= (1<<1),
	PKI_X509_CERT_TYPE_SERVER	= (1<<2),
	PKI_X509_CERT_TYPE_PROXY	= (1<<3),
	PKI_X509_CERT_TYPE_ROOT		= (1<<4)
} PKI_X509_CERT_TYPE;

#define PKI_X509_CERT_TYPE_SIZE  6

/* PKI_X509 general object */
typedef struct pki_x509_st {

	/* Type of Object - taken from PKI_DATATYPE */
	int type;

	/* Internal Value - usually the supported crypto lib internal format */
	void *value;

	/* HSM to use for operations */
	struct hsm_st *hsm;

	/* Reference URL */
	char * ref;

	/* Auxillary Data */
	void * aux_data;

	/* Callback to free auxillary data */
	void (*free_aux_data)(void *);

	/* Callback to duplicate auxillary data */
	void * (*dup_aux_data)(void *);

} PKI_X509;


END_C_DECLS

#endif
