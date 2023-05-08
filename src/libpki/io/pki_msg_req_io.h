/* src/libpki/pki_msg_req.h - General PKI message */

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

#ifndef _LIBPKI_PKI_MSG_H
# include <libpki/pki_msg_types.h>
#endif

#ifndef _LIBPKI_PKI_CRED_H
# include <libpki/pki_cred.h>
#endif

#ifndef _LIBPKI_PKI_MEM_H
# include <libpki/pki_mem.h>
#endif

#ifndef _LIBPKI_PKI_MSG_REQ_IO_H
#define _LIBPKI_PKI_MSG_REQ_IO_H

/* --------------------------- Functions -------------------------- */

/* Sends a message and retrieves the response */
int PKI_MSG_REQ_put ( PKI_MSG_REQ *msg, PKI_DATA_FORMAT format, 
			char *url, char *mime, PKI_CRED *cred, HSM *hsm,
				PKI_MEM_STACK **ret_sk );

PKI_MEM *PKI_MSG_REQ_put_mem ( PKI_MSG_REQ *msg, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

#endif
