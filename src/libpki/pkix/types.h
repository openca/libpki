/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

// Library configuration
#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifdef ENABLE_OQS
# include <oqs/oqsconfig.h>
#endif

#ifndef _LIBPKI_PKIX_TYPES_H
#define _LIBPKI_PKIX_TYPES_H	

BEGIN_C_DECLS

#define PKI_DATA_FORMAT_MIN			PKI_DATA_FORMAT_RAW
#define PKI_DATA_FORMAT_MAX			PKI_DATA_FORMAT_URL

typedef enum pki_data_format_flag {
	PKI_DATA_FORMAT_FLAG_NONE		      = 0,
	PKI_DATA_FORMAT_FLAG_B64_SKIPNEWLINES = 1,
} PKI_DATA_FORMAT_FLAG;

#define PKI_DATA_FORMAT_FLAG_SIZE   2

END_C_DECLS

#endif
