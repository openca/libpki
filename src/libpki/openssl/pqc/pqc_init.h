/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

/**
 * @file pqc_init.h
 * @brief Header file for initializing the PQC (Post-Quantum Cryptography) module and the Crypto Layer.
 *
 * This file contains the declarations for initializing the PQC module and the Crypto Layer.
 * It provides functions to initialize the PQC module, create a new PQC key, and initialize the Crypto Layer.
 */

#ifndef _LIBPKI_PQC_INIT_H
#define _LIBPKI_PQC_INIT_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_PQC_DEFS_H
#include <libpki/openssl/pqc/pqc_defs.h>
#endif

BEGIN_C_DECLS

/**
 * @brief Initializes the PQC (Post-Quantum Cryptography) module.
 *
 * This function initializes the PQC module and prepares it for use.
 *
 * @return 1 on success, 0 on failure.
 */
int PKI_PQC_init();

int PKI_PQC_PKEY_new(char * name, int flags);

END_C_DECLS

#endif // End of _LIBPKI_PQC_INIT_H