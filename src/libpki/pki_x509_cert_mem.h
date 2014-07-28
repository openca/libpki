/* PKI_X509 to/from PKI_MEM management */

#ifndef _LIBPKI_PKI_X509_CERT_MEM_H
#define _LIBPKI_PKI_X509_CERT_MEM_H

/* ----------------------------------- Get -------------------------------- */

PKI_X509_CERT *PKI_X509_CERT_get_mem ( PKI_MEM *mem, PKI_CRED *cred );
PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_mem(PKI_MEM *mem, PKI_CRED *cred);

/* ----------------------------------- Put -------------------------------- */
PKI_MEM *PKI_X509_CERT_put_mem ( PKI_X509_CERT *x, int format, PKI_CRED *cred);
int PKI_X509_CERT_STACK_put_mem ( PKI_X509_CERT_STACK *sk, int format, 
				PKI_MEM *pki_mem, PKI_CRED *cred, int num );

#endif
