/* PKI_X509 to/from PKI_MEM */

#ifndef _LIBPKI_PKI_X509_MEM_H
#define _LIBPKI_PKI_X509_MEM_H

/* --------------------------- PKI_MEM get ------------------------------- */
PKI_X509 *PKI_X509_get_mem ( PKI_MEM *mem, PKI_DATATYPE type, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

void *PKI_X509_get_mem_value ( PKI_MEM *mem, PKI_DATATYPE type, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509_STACK *PKI_X509_STACK_get_mem ( PKI_MEM *mem, PKI_DATATYPE type,
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

/* --------------------------- PKI_MEM put ------------------------------- */
PKI_MEM *PKI_X509_put_mem ( PKI_X509 *x, PKI_DATA_FORMAT format, 
					PKI_MEM **pki_mem, PKI_CRED *cred );

PKI_MEM *PKI_X509_put_mem_value ( void *x, PKI_DATATYPE type, PKI_MEM **mem,
			PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_MEM * PKI_X509_STACK_put_mem ( PKI_X509_STACK *sk, PKI_DATA_FORMAT format, 
				PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

#endif /* _LIBPKI_PKI_X509_MEM_H */
