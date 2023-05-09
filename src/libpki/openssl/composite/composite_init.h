/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/
#ifndef _LIBPKI_COMPOSITE_INIT_H
#define _LIBPKI_COMPOSITE_INIT_H

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

BEGIN_C_DECLS

int PKI_COMPOSITE_init();

int PKI_EXPLICIT_COMPOSITE_init();

int PKI_COMPOSITE_PKEY_new(char * name, int flags);

END_C_DECLS

#endif // End of _LIBPKI_PQC_INIT_H