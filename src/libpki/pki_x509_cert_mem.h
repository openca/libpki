/* PKI_X509 to/from PKI_MEM management */

#ifndef _LIBPKI_PKI_X509_CERT_MEM_H
#define _LIBPKI_PKI_X509_CERT_MEM_H
# pragma once

// LibPKI Includes
#include <libpki/pki_mem.h>
#include <libpki/pki_x509_cert.h>

BEGIN_C_DECLS

						// ===================
						// Function Prototypes
						// ===================

/* ----------------------------------- Get -------------------------------- */

PKI_X509_CERT *PKI_X509_CERT_get_mem(PKI_MEM  * mem,
									 PKI_CRED * cred);

PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_mem(PKI_MEM  * mem,
												 PKI_CRED * cred);

/* ----------------------------------- Put -------------------------------- */

int PKI_X509_CERT_STACK_put_mem(PKI_X509_CERT_STACK * sk,
								int 				  format, 
								PKI_MEM 			* pki_mem,
								PKI_CRED 			* cred,
								int 				  num );

END_C_DECLS

#endif // End of _LIBPKI_PKI_X509_CERT_MEM_H
