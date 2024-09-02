/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_PKI_H
#define _LIBPKI_PKI_H	1

#ifndef _LIBPKI_COMPAT_H
# include <libpki/compat.h>
#endif

#ifndef LIBPKI_VERSION_H
# include <libpki/libpkiv.h>
#endif

// Library configuration
#ifdef __LIB_BUILD__
#include <libpki/config.h>
#else
#include <libpki/libpki_enables.h>
#endif

#include <libpki/os.h>

#include <limits.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>

#include <sys/socket.h>

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

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
// #include <libxml/nanohttp.h>


BEGIN_C_DECLS

extern const long LIBPKI_OS_DETAILS;

#define PKI_NAMESPACE_PREFIX		"pki"
#define PKI_NAMESPACE_HREF		    "http://www.openca.org/openca/pki/1/0/0"

#define PKI_SUBSCRIBER_REQ_TYPE		"application/pki-subscriber-request"
#define PKI_SUBSCRIBER_RESP_TYPE	"application/pki-subscriber-response"
#define PKI_MANAGEMENT_REQ_TYPE		"application/pki-management-request"
#define PKI_MANAGEMENT_RESP_TYPE	"application/pki-management-response"

#ifdef HAVE_ENGINE
#define ENV_OPENCA_ENGINE		    "engine"
#define ENV_OPENCA_ENGINE_ID		"engine_id"
#define ENV_OPENCA_ENGINE_PRE		"engine_pre"
#define ENV_OPENCA_ENGINE_POST		"engine_post"
#endif

/* Imports the library's datatypes */
#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

#ifdef ENABLE_COMPOSITE
#include <libpki/openssl/composite/composite_pmeth.h>
#endif

#define PKI_SCHEME_DEFAULT		PKI_SCHEME_RSA

#define PKI_DEFAULT_CLASSIC_SEC_BITS	128
#define PKI_DEFAULT_QUANTUM_SEC_BITS	128

#define CRL_OK			        1
#define	CRL_NOT_YET_VALID	    2
#define	CRL_EXPIRED		        3
#define	CRL_ERROR_NEXT_UPDATE	4
#define	CRL_ERROR_LAST_UPDATE	5
#define CRL_ERROR_UNKNOWN       10

#define	PKI_VALIDITY_ONE_HOUR	3600
#define PKI_VALIDITY_ONE_DAY	PKI_VALIDITY_ONE_HOUR*24
#define PKI_VALIDITY_ONE_WEEK	PKI_VALIDITY_ONE_DAY*7
#define PKI_VALIDITY_ONE_MONTH	PKI_VALIDITY_ONE_DAY*30
#define PKI_VALIDITY_ONE_YEAR	PKI_VALIDITY_ONE_DAY*365

typedef enum {
	PKI_X509_CRL_REASON_ERROR 						= -1,
	PKI_X509_CRL_REASON_UNSPECIFIED					= 0,
	PKI_X509_CRL_REASON_KEY_COMPROMISE				= 1,
	PKI_X509_CRL_REASON_CA_COMPROMISE				= 2,		
	PKI_X509_CRL_REASON_AFFILIATION_CHANGED			= 3,
	PKI_X509_CRL_REASON_SUPERSEDED					= 4,
	PKI_X509_CRL_REASON_CESSATION_OF_OPERATION		= 5,
	PKI_X509_CRL_REASON_CERTIFICATE_HOLD			= 6,
	// Value #7 is not used
	PKI_X509_CRL_REASON_REMOVE_FROM_CRL				= 8,
	PKI_X509_CRL_REASON_PRIVILEGE_WITHDRAWN			= 9,
	PKI_X509_CRL_REASON_AA_COMPROMISE				= 10,	
	// Hold instructions
	PKI_X509_CRL_REASON_HOLD_INSTRUCTION_REJECT		= 0xA2,
	PKI_X509_CRL_REASON_HOLD_INSTRUCTION_CALLISSUER	= 0xA3,
} PKI_X509_CRL_REASON;

typedef struct __pkiCrlReasonCodes_st {
	int code;
	const char *name;
	const char *descr;
} PKI_X509_CRL_REASON_CODE;

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

#define PKI_THREAD_CREATE_JOINABLE       0
#define PKI_THREAD_CREATE_DETACHED       0x04

#define PKI_THREAD_EXPLICT_SCHED         0
#define PKI_THREAD_INHERIT_SCHED         0x08

#define PKI_THREAD_SCOPE_PROCESS 		 0
#define PKI_THREAD_SCOPE_SYSTEM 		 0x10

#define PKI_THREAD_DESTRUCTOR_ITERATIONS 256

#define PKI_THREAD_PRIO_NONE 			 0
#define PKI_THREAD_PRIO_INHERIT 		 8
#define PKI_THREAD_PRIO_PROTECT 		 16
#define PKI_THREAD_PRIO_MULT 			 32

#define PKI_THREAD_PROCESS_SHARED 		 0
#define PKI_THREAD_PROCESS_PRIVATE 		 1

#else
/* Pthread lib include */
  #include <pthread.h>

#ifdef __LIB_BUILD__
# ifndef HAVE_PTHREAD_RWLOCK
  typedef struct pthread_rwlock_t
  {
    pthread_cond_t cond_var;
    pthread_mutex_t lock_mutex;
    pthread_mutex_t data_mutex;

    uint64_t n_readers;
    uint64_t n_writers;
    uint64_t n_writers_waiting;
  } PKI_RWLOCK;
# else
  typedef pthread_rwlock_t PKI_RWLOCK;
# endif
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

/* Generic */
#include <libpki/banners.h>

/* Credentials */
#include <libpki/pki_err.h>
#include <libpki/pki_cred.h>
#include <libpki/support.h>
#include <libpki/pki_mem.h>
#include <libpki/stack.h>
#include <libpki/crypto.h>
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
#include <libpki/pki_time.h>
#include <libpki/pki_rand.h>
#include <libpki/pki_integer.h>
#include <libpki/pki_x509_profile.h>
#include <libpki/pki_x509_mem.h>
#include <libpki/pki_keyparams.h>
#include <libpki/pki_string.h>
#include <libpki/pki_init.h>
#include <libpki/pki_algor.h>
#include <libpki/pki_id.h>
#include <libpki/pki_oid.h>
#include <libpki/pki_digest.h>
#include <libpki/pki_hmac.h>
#include <libpki/pki_kdf.h>
#include <libpki/pki_config.h>
#include <libpki/pki_keypair.h>
#include <libpki/pki_x509_item.h>
#include <libpki/pki_x509_attribute.h>
#include <libpki/pki_x509_signature.h>
#include <libpki/pki_x509_name.h>
#include <libpki/pki_x509_req.h>
#include <libpki/pki_x509_cert.h>
#include <libpki/pki_x509_crl.h>
#include <libpki/pki_x509_pkcs7.h>
#include <libpki/pki_x509_p12.h>
#include <libpki/pki_x509_cms.h>

#include <libpki/openssl/pki_oid_defs.h>

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

/* EST Interface */
#include <libpki/est/est.h>

/* SCEP Interface */
#include <libpki/scep/scep.h>

/* CMC Interface */
#include <libpki/cmc.h>

/* General PKI Messaging System */
#include <libpki/pki_msg.h>
#include <libpki/pki_msg_req.h>
#include <libpki/pki_msg_resp.h>

/* PRQP Support */
#include <libpki/prqp/prqp.h>

/* crossCertificatePair support */
#include <libpki/pki_x509_xpair_asn1.h>
#include <libpki/pki_x509_xpair.h>

/* I/O operations for PKIX objects */
#include <libpki/pki_io.h>

END_C_DECLS

#endif
