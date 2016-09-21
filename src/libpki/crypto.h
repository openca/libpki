/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef __LIBPKI_CRYPTO_H__
#define __LIBPKI_CRYPTO_H__

#ifndef __LIBPKI_CORE_DATA_ST_H__
#include <libpki/pki_core_data_st.h>
#endif

#ifdef ENABLE_KMF
#include <stdio.h>
#include <kmfapi.h>

#include <libpki/drivers/kmf/data_st.h>
#include <libpki/drivers/kmf/pki_kmflib.h>

#endif // End of ENABLE_KMF

/* End of __LIBPKICRYPTO_H__ */
#endif
