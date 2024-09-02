/* net/types.h */


#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_NET_TYPES_H
#include <libpki/utils/net/types.h>
#endif

#ifndef _LIBPKI_UTILS_TYPES_H
#define _LIBPKI_UTILS_TYPES_H

BEGIN_C_DECLS

#ifndef HEADER_SAFESTACK_H
#include <openssl/safestack.h>
#endif

typedef enum {
	PKI_X509_PROFILE_USER = 0,
	PKI_X509_PROFILE_PROXY,
	PKI_X509_PROFILE_WEB_SERVER,
	PKI_X509_PROFILE_MAIL_SERVER
} PKI_X509_PROFILE_TYPE;

#define PKI_PROFILE_DEFAULT_PROXY_NAME "__DEFAULT_PROXY_PROFILE__"
#define PKI_PROFILE_DEFAULT_USER_NAME "__DEFAULT_USER_PROFILE__"

/*!
 * \brief Data structure for PKI_STACK nodes (INTERNAL ONLY)
 */
typedef struct pki_stack_node_st {
	struct pki_stack_node_st *next;
	struct pki_stack_node_st *prev;

	void *data;
} PKI_STACK_NODE;

/*!
 * \brief Data structure for PKI_STACK
 *
 * The PKI_STACK is the basic structure for storing a stack of generic
 * elements. Fields SHOULD NOT be accessed directly, instead specific
 * PKI_STACK_new(), PKI_STACK_free(), etc... functions exist that take
 * care about details and initialization of the structure.
 */
struct pki_stack_st {
	/*!  \brief Number of elements in the PKI_STACK */
	int elements;

	/*! \brief Pointer to the first node of the PKI_STACK */
	PKI_STACK_NODE *head;

	/*! \brief Pointer to the last node of the PKI_STACK */
	PKI_STACK_NODE *tail;

	/*! \brief Pointer to the function called to free the data object */
	void (*free)( void *);
};

/*! \brief Auxillary Types */
typedef struct pki_stack_st PKI_X509_STACK;
typedef struct pki_stack_st PKI_X509_CERT_STACK;
typedef struct pki_stack_st PKI_X509_REQ_STACK;
typedef struct pki_stack_st PKI_X509_CRL_STACK;
typedef struct pki_stack_st PKI_X509_XPAIR_STACK;
typedef struct pki_stack_st PKI_X509_PROFILE_STACK;
typedef struct pki_stack_st PKI_X509_EXTENSION_STACK;
typedef struct pki_stack_st PKI_X509_CRL_ENTRY_STACK;
typedef struct pki_stack_st PKI_X509_CRL_STACK;
typedef struct pki_stack_st PKI_CONFIG_STACK;
typedef struct pki_stack_st PKI_CONFIG_ELEMENT_STACK;
typedef struct pki_stack_st PKI_OID_STACK;
typedef struct pki_stack_st PKI_ID_INFO_STACK;
typedef struct pki_stack_st PKI_TOKEN_STACK;
typedef struct pki_stack_st PKI_X509_OCSP_REQ_STACK;
typedef struct pki_stack_st PKI_X509_OCSP_RESP_STACK;
typedef struct pki_stack_st PKI_RESOURCE_IDENTIFIER_STACK;
typedef struct pki_stack_st PKI_RESOURCE_RESPONSE_TOKEN_STACK;

END_C_DECLS

#endif
