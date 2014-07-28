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

// DECLARE_ASN1_DUP_FUNCTION(SCEP_ISSUER_AND_SUBJECT)

/* New Issuer and Subject structure */
// SCEP_ISSUER_AND_SUBJECT	*SCEP_ISSUER_AND_SUBJECT_new(void);

/* Free Issuer and Subject */
// void SCEP_ISSUER_AND_SUBJECT_free(SCEP_ISSUER_AND_SUBJECT *ias);

#endif
