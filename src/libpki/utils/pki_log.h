
#ifndef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif

#ifndef _LIBPKI_TOKEN_TYPES_H
#include <libpki/token/types.h>
#endif

#ifndef _LIBPKI_LOG_H
#define _LIBPKI_LOG_H

BEGIN_C_DECLS

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
