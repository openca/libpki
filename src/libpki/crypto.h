/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef HEADER_LIBPKI_CRYPTO_H
#define HEADER_LIBPKI_CRYPTO_H

#include <libpki/openssl/data_st.h>

#ifdef ENABLE_KMF
/* BEGIN of ENABLE KMF */
#include <stdio.h>
#include <kmfapi.h>

#include <libpki/drivers/kmf/data_st.h>
#include <libpki/drivers/kmf/pki_kmflib.h>

/* END of ENABLE KMF */
#endif

/* Include this here because it needs the kmf definitions in case
   KMF is used */

#include <libpki/drivers/hsm_main.h>

/* End of HEADER_LIBPKICRYPTO_H */
#endif
