/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef __LIBPKI_OPENSSL_ENGINE_H__
#define __LIBPKI_OPENSSL_ENGINE_H__

#ifdef ENABLE_OPENSSL
# ifdef ENABLE_OPENSSL_ENGINE
#  ifndef HEADER_ENGINE_H
#   include <openssl/engine.h>
#  endif
# endif
#endif

typedef struct pki_openssl_store_st {
        void	*store_ptr;
} PKI_OPENSSL_STORE;

#endif // End of __LIBPKI_OPENSSL_ENGINE_H__
