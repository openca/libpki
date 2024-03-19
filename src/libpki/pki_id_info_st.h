/* PKI_ID_INFO data structure definition */

#ifndef _LIBPKI_PKI_ID_INFO_ST_H
#define _LIBPKI_PKI_ID_INFO_ST_H
# pragma once

/* Structure for PKI_ID_INFO definition */
typedef struct pki_id_info_st {

	/*! Number of the ID within the TOKEN */
	int  num;

	/*! Number of the SLOT where the TOKEN is connected
         * (0 if not applicable */
	int  slot_id;

	/*! Label for the identity (ID) */
	char *label;

	/*! Pointer to the Token who holds the ID (if available) */
	struct pki_token_st *tk;

} PKI_ID_INFO;

/* End of _LIBPKI_PKI_ID_INFO_ST_H */
#endif
