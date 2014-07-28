/* Lightweight Internet Revocation Token implementation
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPKI_PKI_LIRT_H
#define _LIBPKI_PKI_LIRT_H 1

#ifdef  __cplusplus
extern "C" {
#endif

#include <libpki/lirt/lirt_asn1.h>
#include <libpki/lirt/lirt_bio.h>
#include <libpki/lirt/lirt_lib.h>

/* Macros for PKI_MEM conversion */
#define PKI_LIRT_mem_der(a) \
	PKI_MEM_new_func( (void *) a, i2d_PKI_LIRT )
#define PKI_LIRT_mem_pem(a) \
	PKI_MEM_new_func_bio( (void *) a, PEM_write_bio_PKI_LIRT )

#ifdef  __cplusplus
}
#endif
#endif

/* end */
