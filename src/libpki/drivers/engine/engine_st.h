/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_HEADER_PKI_ENGINE_ST_H
#define _LIBPKI_HEADER_PKI_ENGINE_ST_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#ifdef ENABLE_ECDSA
#include <openssl/ec.h>
#endif

#ifdef ENABLE_KMF
#include <kmfapi.h>
#endif

typedef struct pki_engine_st_2 {
	int type;
	union {
		void * 		openssl_engine;
#ifdef ENABLE_KMF
		KMF_LIB_HANDLE_T kmf_engine;
#endif
	} engine;
} PKI_ENGINE_2;

/* End of _LIBPKI_HEADER_ENGINE_ST_H */
#endif
