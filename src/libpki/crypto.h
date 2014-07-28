/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef HEADER_LIBPKI_CRYPTO_H
#define HEADER_LIBPKI_CRYPTO_H

typedef enum {
	PKI_ATTR_SUBJECT = 0,
	PKI_ATTR_ISSUER,
	PKI_ATTR_NOTBEFORE,
	PKI_ATTR_NOTAFTER,
	PKI_ATTR_SERIALNUMBER,
	PKI_ATTR_MD5_FINGERPRINT,
	PKI_ATTR_SHA1_FINGERPRINT,
	PKI_ATTR_EXTENSIONS
} PKI_X509_ATTRIBUTE;


/* Here we have the specific definitions that enables OPENSSL to
   provide with the high-level crypto interface.

   To use a different crypto layer you have to provide the definition
   for:
	HSM
	TOKEN
 */
#include <libpki/openssl/data_st.h>

#ifdef ENABLE_KMF
/* BEGIN of ENABLE KMF */
#include <stdio.h>
#include <kmfapi.h>

#include <libpki/drivers/kmf/data_st.h>
#include <libpki/drivers/kmf/pki_kmflib.h>

/* END of ENABLE KMF */
#endif
#ifdef ENABLE_KMF
#include <kmfapi.h>
#endif

/*
typedef struct pki_engine_st {
        int type;
        union {
                void *          openssl_engine;
#ifdef ENABLE_KMF
                KMF_LIB_HANDLE_T kmf_engine;
#endif
        } driver;
} PKI_ENGINE;
*/

/* Include all the pkicrypto header files here */
/*
#include <libpki/drivers/openssl/data_st.h>
#include <libpki/drivers/openssl/openssl_hsm.h>
#include <libpki/drivers/openssl/openssl_hsm_pkey.h>
*/
/* 
#include <libpki/drivers/openssl/openssl_hsm_engine.h>
#include <libpki/drivers/openssl/openssl_hsm_sign.h>
*/

#include <libpki/pki_keyparams.h>

/* Include this here because it needs the kmf definitions in case
   KMF is used */

#include <libpki/drivers/hsm_main.h>

// #include <libpki/drivers/hsm_sign.h>

// #include <libpki/pki_pkey.h>
// #include <libpki/pki_x509_req.h>
// #include <libpki/pki_x509_cert.h>
// #include <libpki/token.h>

/* End of HEADER_LIBPKICRYPTO_H */
#endif
