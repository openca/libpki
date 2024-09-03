/* net/types.h */


#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_NET_TYPES_H
#include <libpki/utils/net/types.h>
#endif

#ifndef _STDARG_H
#include <stdarg.h>
#endif

#ifndef HEADER_SAFESTACK_H
#include <openssl/safestack.h>
#endif

#ifndef _LIBPKI_UTILS_TYPES_H
#define _LIBPKI_UTILS_TYPES_H

BEGIN_C_DECLS

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

typedef enum {
	PKI_LOG_TYPE_STDOUT = 0,
	PKI_LOG_TYPE_STDERR,
	PKI_LOG_TYPE_SYSLOG,
	PKI_LOG_TYPE_FILE,
	PKI_LOG_TYPE_FILE_XML,
	PKI_LOG_TYPE_DB
} PKI_LOG_TYPE;

typedef enum {
	PKI_LOG_NONE 		= -1,
	PKI_LOG_MSG 		= 0,
	PKI_LOG_ERR 		= 1,
	PKI_LOG_WARNING 	= 2,
	PKI_LOG_NOTICE 		= 3,
	PKI_LOG_INFO 		= 4,
	PKI_LOG_DEBUG 		= 5,
	PKI_LOG_ALWAYS 		= 99
} PKI_LOG_LEVEL;

typedef enum {
	PKI_LOG_FLAGS_NONE 				= 0,
	PKI_LOG_FLAGS_ENABLE_DEBUG   	= 0x01,
	PKI_LOG_FLAGS_ENABLE_SIGNATURE 	= 0x02,
} PKI_LOG_FLAGS;


typedef struct PKIlog_st {
	/* Keep track if the LOG subsystem has undergone initialization */
	int initialized;

	/* Type of PKI_LOG - PKI_LOG_TYPE */
	PKI_LOG_TYPE type;

	/* Identifier of the resource */
	char *resource;

	/* Log Level - one of PKI_LOG_LEVEL */
	PKI_LOG_LEVEL level;

	/* Flags for log activities - DEBUG, SIGNATURE, etc... */
	PKI_LOG_FLAGS flags;

	/* Enable Signed Log */
	CRYPTO_KEYPAIR *tk;

	/* Callbacks function - init */
	int (*init)(struct PKIlog_st *);

	/* Callbacks function - add */
	void (*add)(int, const char *, va_list);

	/* Callbacks function - finalize */
	int (*finalize)(struct PKIlog_st *);

	/* Callback function - sign */
	int (*entry_sign)(struct PKIlog_st *, char * );

} PKI_LOG;

END_C_DECLS

#endif
