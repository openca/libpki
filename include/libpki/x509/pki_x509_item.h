/* pki_x509_item.h */

#ifndef _LIBPKI_X509_ITEM_H
#define _LIBPKI_X509_ITEM_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

int PKI_X509_ITEM_verify(const ASN1_ITEM * it, 
						 X509_ALGOR 	 * a,
                     	 ASN1_BIT_STRING  * signature,
						 void             * asn, 
						 EVP_PKEY         * pkey);

#endif
