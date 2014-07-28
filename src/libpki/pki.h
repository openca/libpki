/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

/* BEGIN_C_DECLS should be used at the beginning of your declarations,
so that C++ compilers don't mangle their names.  Use END_C_DECLS at
the end of C declarations. */
#undef BEGIN_C_DECLS
#undef END_C_DECLS
#ifdef __cplusplus
	# define BEGIN_C_DECLS extern "C" {
	# define END_C_DECLS }
#else
	# define BEGIN_C_DECLS /* empty */
	# define END_C_DECLS /* empty */
#endif
     
/* PARAMS is a macro used to wrap function prototypes, so that
compilers that don't understand ANSI C prototypes still work,
and ANSI C compilers can issue warnings about type mismatches. */
#undef PARAMS
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
		|| defined(WIN32) || defined(__cplusplus)
	# define PARAMS(protos) protos
#else
	# define PARAMS(protos) ()
#endif

#ifndef _LIBPKI_PKI_H
#define _LIBPKI_PKI_H	1

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
// #include <libxml/nanohttp.h>

#ifdef __LIB_BUILD__
#include <libpki/config.h>
#endif

#include <libpki/os.h>

extern const long LIBPKI_OS_DETAILS;

#include <limits.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>

#define __XOPEN_OR_POSIX
#include <signal.h>
#undef __XOPEN_OR_POSIX

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/file.h>
#include <sys/times.h>

#include <sys/sem.h>
#include <sys/ipc.h>

#ifdef LIBPKI_TARGET_SOLARIS
#include <fcntl.h>
#endif

#if defined (__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
	/* Ok, Semafores are correctly supported */
#elif defined (_SYS_SEM_H_)
	/* OpenBSD is not a GNU_LIBRARY but knows semaphores */
#else
	/* We should define here the structure */
	union semun {
             int val;                  /* value for SETVAL */
             struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
             unsigned short *array;    /* array for GETALL, SETALL */
                                       /* Linux specific part: */
             struct seminfo *__buf;    /* buffer for IPC_INFO */
       };

#endif

BEGIN_C_DECLS

#define PKI_NAMESPACE_PREFIX		"pki"
#define PKI_NAMESPACE_HREF			"http://www.openca.org/openca/pki/1/0/0"

#define PKI_SUBSCRIBER_REQ_TYPE		"application/pki-subscriber-request"
#define PKI_SUBSCRIBER_RESP_TYPE	"application/pki-subscriber-response"
#define PKI_MANAGEMENT_REQ_TYPE		"application/pki-management-request"
#define PKI_MANAGEMENT_RESP_TYPE	"application/pki-management-response"

#ifdef HAVE_ENGINE
#define ENV_OPENCA_ENGINE			"engine"
#define ENV_OPENCA_ENGINE_ID		"engine_id"
#define ENV_OPENCA_ENGINE_PRE		"engine_pre"
#define ENV_OPENCA_ENGINE_POST		"engine_post"
#endif

#define PKI_IO				BIO

/* PKI Datatypes */
typedef enum {
	/* Driver(s) Datatype */
	PKI_DATATYPE_UNKNOWN = 0,
	PKI_DATATYPE_ANY,
	PKI_DATATYPE_APPLICATION,
	PKI_DATATYPE_PUBKEY,
	PKI_DATATYPE_PRIVKEY,
	PKI_DATATYPE_SECRET_KEY,
	PKI_DATATYPE_CRED,
	/* X509 types */
	PKI_DATATYPE_X509_KEYPAIR,
	PKI_DATATYPE_X509_CERT,
	PKI_DATATYPE_X509_CRL,
	PKI_DATATYPE_X509_REQ,
	PKI_DATATYPE_X509_PKCS7,
	PKI_DATATYPE_X509_PKCS12,
	PKI_DATATYPE_X509_OCSP_REQ,
	PKI_DATATYPE_X509_OCSP_RESP,
	PKI_DATATYPE_X509_PRQP_REQ,
	PKI_DATATYPE_X509_PRQP_RESP,
	PKI_DATATYPE_X509_XPAIR,
	PKI_DATATYPE_X509_CMS_MSG,
	PKI_DATATYPE_X509_LIRT,
	/* Non-X509 types */
	PKI_DATATYPE_SCEP_MSG,
	/* Custom Type */
	PKI_DATATYPE_CUSTOM,
	/* Used in PKCS11 driver */
	PKI_DATATYPE_X509_CA,
	PKI_DATATYPE_X509_TRUSTED,
	PKI_DATATYPE_X509_OTHER
} PKI_DATATYPE;

/* Token Datatypes */
typedef enum {
	PKI_TOKEN_DATATYPE_UNKNOWN = 0,
	PKI_TOKEN_DATATYPE_KEYPAIR,
	PKI_TOKEN_DATATYPE_PRIVKEY,
	PKI_TOKEN_DATATYPE_PUBKEY,
	PKI_TOKEN_DATATYPE_CERT,
	PKI_TOKEN_DATATYPE_CACERT,
	PKI_TOKEN_DATATYPE_TRUSTEDCERT,
	PKI_TOKEN_DATATYPE_OTHERCERT,
	PKI_TOKEN_DATATYPE_CRL,
	PKI_TOKEN_DATATYPE_CRED,
	PKI_TOKEN_DATATYPE_NICKNAME,
	PKI_TOKEN_DATATYPE_IDENTITY
} PKI_TOKEN_DATATYPE;

typedef enum {
	/* Usual Ok */
	PKI_TOKEN_STATUS_OK					= 0,
	/* General Setup Errors */
	PKI_TOKEN_STATUS_INIT_ERR			= 1,
	PKI_TOKEN_STATUS_LOGIN_ERR			= 4,
	/* Configuration  Errors */
	PKI_TOKEN_STATUS_KEYPAIR_ERR 		= 8,
	PKI_TOKEN_STATUS_CERT_ERR			= 16,
	PKI_TOKEN_STATUS_CACERT_ERR			= 32,
	PKI_TOKEN_STATUS_OTHERCERTS_ERR		= 64,
	PKI_TOKEN_STATUS_TRUSTEDCERTS_ERR 	= 128,
	/* Generic Errors */
	PKI_TOKEN_STATUS_MEMORY_ERR			= 1024,
	PKI_TOKEN_STATUS_UNKNOWN			= 2048,
} PKI_TOKEN_STATUS;

/* Data Export Format */
typedef enum {
	PKI_DATA_FORMAT_UNKNOWN		= 0,
	PKI_DATA_FORMAT_PEM,
	PKI_DATA_FORMAT_ASN1,
	PKI_DATA_FORMAT_B64,
	PKI_DATA_FORMAT_TXT,
	PKI_DATA_FORMAT_XML,
	PKI_DATA_FORMAT_URL,
} PKI_DATA_FORMAT;

#define PKI_DATA_FORMAT_SIZE		6

typedef enum {
	PKI_FORMAT_UNDEF		= 0,
	PKI_FORMAT_CMS,
	PKI_FORMAT_SCEP,
	PKI_FORMAT_NETSCAPE,
	PKI_FORMAT_PKCS11,
	PKI_FORMAT_SMIME,
	PKI_FORMAT_ENGINE
} PKI_FORMAT;

#define PKI_FORMAT_SIZE			10

/* Supported Signing schemes identifiers */
typedef enum {
	PKI_SCHEME_UNKNOWN 	= 0,
	PKI_SCHEME_RSA,
	PKI_SCHEME_DSA,
	PKI_SCHEME_DH,
	PKI_SCHEME_ECDSA
} PKI_SCHEME_ID;

#define PKI_SCHEME_DEFAULT		PKI_SCHEME_RSA

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
	PKI_X509_DATA_PUBKEY,
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

typedef enum {
	PKI_X509_CERT_TYPE_UNKNOWN	= 0,
	PKI_X509_CERT_TYPE_CA		= (1<<0),
	PKI_X509_CERT_TYPE_USER		= (1<<1),
	PKI_X509_CERT_TYPE_SERVER	= (1<<2),
	PKI_X509_CERT_TYPE_PROXY	= (1<<3),
	PKI_X509_CERT_TYPE_ROOT		= (1<<4)
} PKI_X509_CERT_TYPE;

typedef enum {
	PKI_RSA_KEY_MIN_SIZE		= 1024,
	PKI_DSA_KEY_MIN_SIZE		= 2048,
	PKI_EC_KEY_MIN_SIZE			= 256,
} PKI_KEY_MIN_SIZE;

typedef enum {
	PKI_RSA_KEY_DEFAULT_SIZE	= 2048,
	PKI_DSA_KEY_DEFAULT_SIZE	= 2048,
	PKI_EC_KEY_DEFAULT_SIZE		= 256,
} PKI_KEY_DEFAULT_SIZE;

#define CRL_OK			1
#define	CRL_NOT_YET_VALID	2
#define	CRL_EXPIRED		3
#define	CRL_ERROR_NEXT_UPDATE	4
#define	CRL_ERROR_LAST_UPDATE	5
#define CRL_ERROR_UNKNOWN	10

#define	PKI_VALIDITY_ONE_HOUR	3600
#define PKI_VALIDITY_ONE_DAY	PKI_VALIDITY_ONE_HOUR*24
#define PKI_VALIDITY_ONE_WEEK	PKI_VALIDITY_ONE_DAY*7
#define PKI_VALIDITY_ONE_MONTH	PKI_VALIDITY_ONE_DAY*30
#define PKI_VALIDITY_ONE_YEAR	PKI_VALIDITY_ONE_DAY*365

typedef enum {
	PKI_CRL_REASON_UNSPECIFIED					= 0,
	PKI_CRL_REASON_KEY_COMPROMISE				= 1,
	PKI_CRL_REASON_CA_COMPROMISE				= 2,		
	PKI_CRL_REASON_AFFILIATION_CHANGED			= 3,
	PKI_CRL_REASON_SUPERSEDED					= 4,
	PKI_CRL_REASON_CESSATION_OF_OPERATION		= 5,
	PKI_CRL_REASON_CERTIFICATE_HOLD				= 6,
	// Value #7 is not used
	PKI_CRL_REASON_REMOVE_FROM_CRL				= 8,
	PKI_CRL_REASON_PRIVILEGE_WITHDRAWN			= 9,
	PKI_CRL_REASON_AA_COMPROMISE				= 10,	
	// Hold instructions
	PKI_CRL_REASON_HOLD_INSTRUCTION_REJECT		= 0xA2,
	PKI_CRL_REASON_HOLD_INSTRUCTION_CALLISSUER	= 0xA3,
} PKI_X509_CRL_REASON;

/*
typedef enum {
	PKI_CRL_REASON_HOLD_INSTRUCTION_REJECT		= 0xA2,
	PKI_CRL_REASON_HOLD_INSTRUCTION_CALLISSUER	= 0xA3,
} PKI_X509_CRL_HOLD_INSTRUCTION;
*/

typedef struct __pkiCrlReasonCodes_st {
	int code;
	const char *name;
	const char *descr;
} PKI_X509_CRL_REASON_CODE;


typedef enum {
	PKI_HTTP_METHOD_UNKNOWN		= 0,
	PKI_HTTP_METHOD_GET,
	PKI_HTTP_METHOD_POST,
	PKI_HTTP_METHOD_HTTP
} PKI_HTTP_METHOD;

#define PKI_HTTP_METHOD_POST_TXT	"POST"
#define PKI_HTTP_METHOD_GET_TXT		"GET"
#define PKI_HTTP_METHOD_HTTP_TXT	"HTTP"

// #define APP_PASS_LEN    			1024

#define PKI_ERR					0
#define PKI_OK					1
#define PKI_CONFIG  				xmlDoc
#define PKI_CONFIG_ELEMENT  			xmlNode

/* Misc Define */
#define PKI_X509_CERT_BEGIN_ARMOUR	"-----BEGIN CERTIFICATE-----"
#define PKI_X509_CERT_END_ARMOUR	"-----END CERTIFICATE-----"

#define PKI_X509_REQ_BEGIN_ARMOUR	"-----BEGIN CERTIFICATE REQUEST-----"
#define PKI_X509_REQ_END_ARMOUR		"-----END CERTIFICATE REQUEST-----"

#define PKI_X509_CRL_BEGIN_ARMOUR	"-----BEGIN CRL-----"
#define PKI_X509_CRL_END_ARMOUR		"-----END CRL-----"

#define PKI_KEYPAIR_BEGIN_ARMOUR	"-----BEGIN KEYPAIR-----"
#define PKI_KEYPAIR_END_ARMOUR		"-----END KEYPAIR-----"

#define PKI_PUBKEY_BEGIN_ARMOUR		"-----BEGIN PUBKEY-----"
#define PKI_PUBKEY_END_ARMOUR		"-----END PUBKEY-----"

#define PKI_PRIVKEY_BEGIN_ARMOUR	"-----BEGIN PRIVKEY-----"
#define PKI_PRIVKEY_END_ARMOUR		"-----END PRIVKEY-----"

#define PKI_X509_OCSP_REQ_BEGIN_ARMOUR	"-----BEGIN OCSP REQUEST-----"
#define PKI_X509_OCSP_REQ_END_ARMOUR	"-----END OCSP REQUEST-----"

#define PKI_X509_OCSP_RESP_BEGIN_ARMOUR	"-----BEGIN OCSP RESPONSE-----"
#define PKI_X509_OCSP_RESP_END_ARMOUR	"-----END OCSP RESPONSE-----"

typedef enum {
	PKI_MUTEX_READ		= 0,
	PKI_MUTEX_WRITE		= 1,
} PKI_MUTEX_METHOD;

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
  // Do we need any includes for the threads on WIN (???)
  typedef SRWLOCK PKI_RWLOCK;
  typedef CONDITION_VARIABLE PKI_COND;
  typedef CRITICAL_SECTION	PKI_MUTEX;

  typedef struct timespec {
		long long tv_sec;
		long long tv_nsec;
  };

  typedef struct _thread_v {
	void *ret_arg;
	void *(* func)(void *);
	_pthread_cleanup *clean;
	HANDLE h;
	int cancelled;
	unsigned p_state;
	int keymax;
	void **keyval;
	
	jmp_buf jb;
  };

  typedef _thread_v PKI_THREAD;

  typedef struct pthread_attr_t {
	unsigned p_state;
	void *stack;
	size_t s_size;
  } PKI_PTHREAD_ATTR;

#define PKI_THREAD_CREATE_JOINABLE 0
#define PKI_THREAD_CREATE_DETACHED 0x04

#define PKI_THREAD_EXPLICT_SCHED 0
#define PKI_THREAD_INHERIT_SCHED 0x08

#define PKI_THREAD_SCOPE_PROCESS 		0
#define PKI_THREAD_SCOPE_SYSTEM 		0x10

#define PKI_THREAD_DESTRUCTOR_ITERATIONS 256

#define PKI_THREAD_PRIO_NONE 			0
#define PKI_THREAD_PRIO_INHERIT 		8
#define PKI_THREAD_PRIO_PROTECT 		16
#define PKI_THREAD_PRIO_MULT 			32

#define PKI_THREAD_PROCESS_SHARED 		0
#define PKI_THREAD_PROCESS_PRIVATE 		1

#else
/* Pthread lib include */
  #include <pthread.h>

#ifndef HAVE_PTHREAD_RWLOCK
  typedef struct pthread_rwlock_t
  {
    pthread_cond_t cond_var;
    pthread_mutex_t lock_mutex;
    pthread_mutex_t data_mutex;

    uint64_t n_readers;
    uint64_t n_writers;
    uint64_t n_writers_waiting;
  } PKI_RWLOCK;
#else
  typedef pthread_rwlock_t PKI_RWLOCK;
#endif
  typedef pthread_mutex_t PKI_MUTEX;
  typedef pthread_cond_t PKI_COND;

  typedef pthread_t PKI_THREAD;

  typedef pthread_attr_t PKI_THREAD_ATTR;
  typedef pthread_t PKI_THREAD_ID;

#define PKI_THREAD_CREATE_JOINABLE 		PTHREAD_CREATE_JOINABLE 
#define PKI_THREAD_CREATE_DETACHED 		PTHREAD_CREATE_DETACHED 

#define PKI_THREAD_EXPLICT_SCHED 		PTHREAD_EXPLICT_SCHED 
#define PKI_THREAD_INHERIT_SCHED 		PTHREAD_INHERIT_SCHED 

#define PKI_THREAD_SCOPE_PROCESS 		PTHREAD_SCOPE_PROCESS 
#define PKI_THREAD_SCOPE_SYSTEM 		PTHREAD_SCOPE_SYSTEM 

#define PKI_THREAD_DESTRUCTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS 

#define PKI_THREAD_PRIO_NONE 			PTHREAD_PRIO_NONE 
#define PKI_THREAD_PRIO_INHERIT 		PTHREAD_PRIO_INHERIT 
#define PKI_THREAD_PRIO_PROTECT 		PTHREAD_PRIO_PROTECT 
#define PKI_THREAD_PRIO_MULT 			PTHREAD_PRIO_MULT 

#define PKI_THREAD_PROCESS_SHARED 		PTHREAD_PROCESS_SHARED 
#define PKI_THREAD_PROCESS_PRIVATE 		PTHREAD_PROCESS_PRIVATE 

#endif

#include <libpki/pki_threads_vars.h>
#include <libpki/pki_threads.h>
#include <libpki/openssl/pthread_init.h>

/* Credentials */
#include <libpki/pki_cred.h>

#include <libpki/errors.h>
#include <libpki/support.h>
#include <libpki/pki_mem.h>
#include <libpki/stack.h>
#include <libpki/net/sock.h>
#include <libpki/net/ssl.h>
#include <libpki/net/pki_socket.h>
#include <libpki/net/url.h>
#include <libpki/net/http_s.h>
#include <libpki/net/ldap.h>
#include <libpki/net/dns.h>

/* General X509 object */
#include <libpki/pki_x509_data_st.h>
#include <libpki/pki_x509.h>
#include <libpki/pki_x509_mime.h>

/* Forward declarations */
#define PKI_X509_CERT	PKI_X509
#define PKI_X509_REQ	PKI_X509

/* Libpki Includes */
#include <libpki/pki_x509_profile.h>
#include <libpki/crypto.h>
#include <libpki/pki_string.h>
#include <libpki/pki_init.h>
#include <libpki/pki_algor.h>
#include <libpki/pki_algorithm.h>
#include <libpki/pki_id.h>
#include <libpki/pki_oid.h>
#include <libpki/pki_digest.h>
#include <libpki/pki_hmac.h>
#include <libpki/pki_conf.h>
#include <libpki/pki_x509_attribute.h>
#include <libpki/pki_keypair.h>
#include <libpki/pki_x509_signature.h>
#include <libpki/pki_x509_name.h>
#include <libpki/pki_x509_cert.h>
#include <libpki/pki_x509_req.h>
#include <libpki/pki_x509_crl.h>
#include <libpki/pki_time.h>
#include <libpki/pki_integer.h>
#include <libpki/pki_x509_pkcs7.h>
#include <libpki/pki_x509_p12.h>
#include <libpki/pki_x509_mem.h>

/* OCSP support */

typedef enum {
	PKI_OCSP_CERTSTATUS_GOOD 	= V_OCSP_CERTSTATUS_GOOD,
	PKI_OCSP_CERTSTATUS_REVOKED = V_OCSP_CERTSTATUS_REVOKED,
	PKI_OCSP_CERTSTATUS_UNKNOWN = V_OCSP_CERTSTATUS_UNKNOWN,
} PKI_OCSP_CERTSTATUS;

typedef enum {
	PKI_X509_OCSP_RESP_STATUS_SUCCESSFUL 			= 0,
	PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST		= 1,
	PKI_X509_OCSP_RESP_STATUS_INTERNALERROR 		= 2,
	PKI_X509_OCSP_RESP_STATUS_TRYLATER 				= 3,
	PKI_X509_OCSP_RESP_STATUS_SIGREQUIRED 			= 5,
	PKI_X509_OCSP_RESP_STATUS_UNAUTHORIZED 			= 6
} PKI_X509_OCSP_RESP_STATUS;

#include <libpki/pki_ocsp_req.h>
#include <libpki/pki_ocsp_resp.h>


/* HSM Support */
#include <libpki/drivers/hsm_keypair.h>
#include <libpki/drivers/hsm_main.h>
#include <libpki/drivers/hsm_slot.h>

/* Software HSM Support */
#include <libpki/drivers/openssl/openssl_hsm.h>
#include <libpki/drivers/openssl/openssl_hsm_pkey.h>
#include <libpki/drivers/openssl/openssl_hsm_obj.h>
#include <libpki/drivers/openssl/openssl_hsm_cb.h>

#ifdef HAVE_ENGINE /* ENGINE Support */
#include <openssl/engine.h>
#include <libpki/drivers/engine/engine_hsm.h>
#include <libpki/drivers/engine/engine_hsm_pkey.h>
#include <libpki/drivers/engine/engine_hsm_obj.h>
#endif

/* PKCS11 Support */
#include <libpki/drivers/pkcs11/rsa/cryptoki.h> /* Updated to pkcs11t */
#include <libpki/drivers/pkcs11/pkcs11_hsm.h>
#include <libpki/drivers/pkcs11/pkcs11_hsm_pkey.h>
#include <libpki/drivers/pkcs11/pkcs11_hsm_obj.h>
#include <libpki/drivers/pkcs11/pkcs11_utils.h>

/* Profile and Config support */
#include <libpki/profile.h>
#include <libpki/extensions.h>
#include <libpki/pki_x509_extension.h>

/* PKI_ID_INFO support */
#include <libpki/pki_id_info.h>

/* TOKEN interface */
#include <libpki/token_data.h>
#include <libpki/token_id.h>
#include <libpki/token.h>

/* Log Subsystem Support */
#include <libpki/pki_log.h>

/* DBMS support */
#ifdef __LIB_BUILD__
#include <libpki/net/pki_mysql.h>
#include <libpki/net/pki_pg.h>
#include <libpki/net/pkcs11.h>
#endif /* END of __LIB_BUILD__ */

/* SCEP Interface */
// #include <libpki/scep/scep_asn1.h>
// #include <libpki/scep/scep_bio.h>
#include <libpki/scep/scep.h>
// #include <libpki/scep/scep_msg.h>
// #include <libpki/scep/scep_pk7.h>
// #include <libpki/scep/scep_sigattr.h>

/* CMS Interface */
#include <libpki/cms.h>

/* General PKI Messaging System */
#include <libpki/pki_msg.h>
#include <libpki/pki_msg_req.h>
#include <libpki/pki_msg_resp.h>

/* PRQP Support */
#include <libpki/prqp/prqp.h>

/* crossCertificatePair support */
#include <libpki/pki_x509_xpair_asn1.h>
#include <libpki/pki_x509_xpair.h>

/* LIRT Support */
#include <libpki/lirt/lirt.h>

/* I/O operations for PKIX objects */
#include <libpki/pki_io.h>

END_C_DECLS

#endif
