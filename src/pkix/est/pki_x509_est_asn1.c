/* EST ASN.1 implementation
 * (c) 2003-2019 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the OpenCA License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>
 
ASN1_SEQUENCE(EST_ISSUER_AND_SUBJECT) = {
        ASN1_SIMPLE(EST_ISSUER_AND_SUBJECT, issuer, X509_NAME),
        ASN1_SIMPLE(EST_ISSUER_AND_SUBJECT, subject, X509_NAME)
} ASN1_SEQUENCE_END(EST_ISSUER_AND_SUBJECT)
 
IMPLEMENT_ASN1_FUNCTIONS(EST_ISSUER_AND_SUBJECT)

