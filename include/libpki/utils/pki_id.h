/* ID management for libpki */

#ifndef _LIBPKI_PKI_ID_H
#define _LIBPKI_PKI_ID_H

#ifndef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

// ======================
// Exported Data Pointers
// ======================

extern int pqc_sig_nids_list[];
extern int pqc_kem_nids_list[];

// ==================
// Exported Functions
// ==================

/*!
 * \brief Create a new ID object
 *
 * Create a new ID by using its name. It returns an int
 * if successful, otherwise it returns NULL
 */
PKI_ID PKI_ID_get_by_name(const char * name);

/*!
 * \brief Checks if a PKI IDentifier exists
 *
 * This function retrieves an ID generated from the passed ID, if the ID
 * does not exist in the library database, it returns PKI_ID_UNKNOWN.
 *
 * Basically it checks if it exists or not.
 */
PKI_ID PKI_ID_get( PKI_ID id );

const char * PKI_ID_get_txt( PKI_ID id );

int PKI_ID_is_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id);

int PKI_ID_is_explicit_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id);

int PKI_ID_is_traditional(PKI_ID key_id, PKI_SCHEME_ID * scheme_id);

int PKI_ID_is_pqc(PKI_ID id, PKI_SCHEME_ID * scheme_id);

int PKI_ID_requires_digest(PKI_ID id);

#endif // End of _LIBPKI_PKI_ID_H


