/* ID management for libpki */

#ifndef _LIBPKI_PKI_ASN1_H
#define _LIBPKI_PKI_ASN1_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_ERR_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

// ==================
// Exported Functions
// ==================

/*! \brief Verifies the signature on an ASN1_ITEM
 *
 * This function verifies the signature on an ASN1_ITEM. It returns
 * PKI_OK if the signature is valid, otherwise it returns PKI_ERR.
 * 
 * @param it is the ASN1_ITEM to be verified
 * @param a is the algorithm used to sign the ASN1_ITEM
 * @param signature is the signature to be verified
 * @param asn is the ASN1_ITEM to be verified
 * @param pkey is the public key used to verify the signature
 * @retval PKI_OK if the signature is valid, PKI_ERR otherwise
 * 
*/
int PKI_ASN1_item_verify(const ASN1_ITEM * it, 
						 X509_ALGOR 	 * a,
                     	 ASN1_BIT_STRING  * signature,
						 void             * asn, 
						 EVP_PKEY         * pkey);


#endif // End of _LIBPKI_PKI_ASN1_H


