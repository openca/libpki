/*
 * SCEP - ASN1 Functions
 */

#ifndef _LIBPKI_PKI_X509_SCEP_ASN1_H
#define _LIBPKI_PKI_X509_SCEP_ASN1_H

typedef struct scep_issuer_and_subject_st {
        X509_NAME *issuer;
        X509_NAME *subject;
} SCEP_ISSUER_AND_SUBJECT;

DECLARE_ASN1_FUNCTIONS(SCEP_ISSUER_AND_SUBJECT)

#endif
