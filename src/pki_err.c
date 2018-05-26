/* PKI ERR Management Functions */

#define __LIBPKI_ERR__

#include <libpki/pki.h>

/* Private variables */
// static int pki_err = PKI_OK;
// static char *pki_errval;

/* Externally accessible variable */
// char ext_pki_errval[1024];

/* ERR Stack Mutex */
// static pthread_mutex_t err_mutex = PTHREAD_MUTEX_INITIALIZER;
// static pthread_cond_t err_cond;

/* Pointer to the Error Stack */
PKI_STACK *pki_err_stack = NULL;

// static int _set_pki_errval (int err);
// static char * _get_pki_errval (int err);

/*!
 * \brief Set and logs library errors
 */
#pragma GCC diagnostic ignored "-Wuninitialized"
int __pki_error ( const char *file, int line, int err, const char *info, ... ) {
 
	int i, found;
	PKI_ERR_ST *curr = NULL;
	char fmt[2048];

	va_list ap;

	found = -1;
	for ( i = 0; i < __libpki_err_size ; i++ ) 
	{
		curr = (PKI_ERR_ST *) &__libpki_errors_st[i];

		if ( ( curr ) && ( curr->code == err ) ) 
		{
			found = i;
			if ( !curr->descr ) break;

			if ( info == NULL )
			{
				PKI_log_err_simple( "[%s:%d] %s", file, line, curr->descr );
			} 
			else 
			{
				snprintf(fmt, sizeof(fmt), "[%s:%d] %s => %s", file, line, curr->descr, info );
				PKI_log_err_simple( fmt, ap);
			}

			break;
		}
	}

	if ( found < 0 ) err = PKI_ERR_UNKNOWN;

	return ( PKI_ERR );
}

#ifndef LIBPKI_TARGET_OSX
# ifdef HAVE_GCC_PRAGMA_POP
#  pragma GCC diagnostic pop
# endif
#endif
