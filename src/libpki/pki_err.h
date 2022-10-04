/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_ERRORS_H
#include <libpki/errors.h>
#endif

#ifndef _LIBPKI_ERR_H
#define _LIBPKI_ERR_H

// ------------------------- Useful Macros --------------------------- //

// Second Argument is a const char *
#define PKI_ERROR(a,b,args...) __pki_error(__FILE__, __LINE__, a, b, ## args)

#define PKI_ERROR_crypto_get_errno() HSM_get_errno(NULL)

#define PKI_ERROR_crypto_get_errdesc() HSM_get_errdesc(HSM_get_errno(NULL),NULL)

// --------------------- Function Prototypes ------------------------- //

int __pki_error ( const char *file, int line, int err, const char *info, ... );

#endif
