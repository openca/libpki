
#ifndef _LIBPKI_LOG_H
#define _LIBPKI_LOG_H

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h> 
#endif

BEGIN_C_DECLS

#ifndef _LIBPKI_TOKEN_HEADERS_H
# include <libpki/token.h>
#endif

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
	PKI_TOKEN *tk;

	/* Callbacks function - init */
	int (*init)(struct PKIlog_st *);

	/* Callbacks function - add */
	void (*add)(int, const char *, va_list);

	/* Callbacks function - finalize */
	int (*finalize)(struct PKIlog_st *);

	/* Callback function - sign */
	int (*entry_sign)(struct PKIlog_st *, char * );

} PKI_LOG;

// --------------------- Function Prototypes ------------------------- //

int PKI_log_init ( PKI_LOG_TYPE type, PKI_LOG_LEVEL level, char *resource,
				PKI_LOG_FLAGS flags, PKI_TOKEN *tk );

void PKI_log( int level, const char *fmt, ... );

void PKI_log_debug_simple( const char *fmt, ... );

void PKI_log_err_simple( const char *fmt, ... );

int PKI_log_end( void );

// ------------------------- Useful Macros ---------==---------------- //

/* Macro To Automatically add [__FILE__:__LINE__] to the message */
#define PKI_log_line(a, b, args...) \
	PKI_log(a, "[%s:%d] " b, __FILE__, __LINE__, ## args)

/* Macro To Automatically add [__FILE__:__LINE__]::DEBUG:: to the message */
#define PKI_log_debug(a, args...) \
	PKI_log_debug_simple((const char *)"[%s:%d] [%s()] [DEBUG] " a, \
			     __FILE__, __LINE__, __func__, ## args)

#define PKI_log_err(a, args...) \
	PKI_log_err_simple((const char *) "[%s:%d] [%s()] [ERROR] " a, \
		__FILE__, __LINE__, __func__, ## args)

#define PKI_log_crypto_err(a) \
	PKI_log_err_simple("[%s:%d] [%s()] [ERROR] %d:%s", __FILE__, __LINE__, \
			__func__, HSM_get_errno(a), HSM_get_errdesc(HSM_get_errno(a), a))

#define PKI_DEBUG(a, args...) \
	PKI_log_debug_simple((const char *)"[%s:%d] [%s()] [DEBUG]: " a, \
			     __FILE__, __LINE__, __func__, ## args)

END_C_DECLS

#endif
