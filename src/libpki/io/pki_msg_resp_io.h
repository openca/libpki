/* src/libpki/io/pki_msg_resp.h - General PKI message (responses) I/O */

#ifndef _LIBPKI_PKI_MSG_RESP_IO_H
#define _LIBPKI_PKI_MSG_RESP_IO_H

/* --------------------------- Functions -------------------------- */

/*! \brief Writes the message to a URL */
int PKI_MSG_RESP_put ( PKI_MSG_RESP *msg, PKI_DATA_FORMAT format, 
			char *url, char *mime, PKI_CRED *cred, HSM *hsm );

/*! \brief Writes the message in a memory buffer */
PKI_MEM *PKI_MSG_RESP_put_mem ( PKI_MSG_RESP *msg, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

#endif
