
#ifndef _LIBPKI_X509_XPAIR_ASN1_H
#define _LIBPKI_X509_XPAIR_ASN1_H
                                                                                
#define	PEM_STRING_XPAIR	"CROSS CERTIFICATE PAIR"

typedef struct pki_x509_xpair_st {
        PKI_X509_CERT_VALUE *forward;
        PKI_X509_CERT_VALUE *reverse;
} PKI_XPAIR;

DECLARE_ASN1_FUNCTIONS(PKI_XPAIR)

PKI_X509_XPAIR_VALUE *d2i_PKI_XPAIR_bio ( BIO *bp, PKI_XPAIR *p );
int i2d_PKI_XPAIR_bio(BIO *bp, PKI_XPAIR *o );
int PEM_write_bio_PKI_XPAIR( PKI_IO *bp, PKI_XPAIR *o );
PKI_X509_XPAIR_VALUE *PEM_read_bio_PKI_XPAIR( PKI_IO *bp );

#endif
