/*
 * EST - ASN1 Functions
 */

#ifndef _LIBPKI_PKI_X509_EST_ASN1_H
#define _LIBPKI_PKI_X509_EST_ASN1_H

typedef struct est_issuer_and_subject_st {
        X509_NAME *issuer;
        X509_NAME *subject;
} EST_ISSUER_AND_SUBJECT;

DECLARE_ASN1_FUNCTIONS(EST_ISSUER_AND_SUBJECT)

#endif
