#include <libpki/pki.h>

ASN1_SEQUENCE(PKI_XPAIR) = {
	ASN1_EXP(PKI_XPAIR, forward, X509, 0),
	ASN1_EXP_OPT(PKI_XPAIR, reverse, X509, 1),
} ASN1_SEQUENCE_END(PKI_XPAIR)

IMPLEMENT_ASN1_FUNCTIONS(PKI_XPAIR)

IMPLEMENT_ASN1_DUP_FUNCTION(PKI_XPAIR)

/*
PKI_XPAIR *PKI_XPAIR_dup ( PKI_XPAIR * x ) {
	return ASN1_item_dup ( &PKI_XPAIR_it, x );
}
*/

/* DER <-> INTERNAL Macros */
PKI_X509_XPAIR_VALUE *d2i_PKI_XPAIR_bio ( BIO *bp, PKI_XPAIR *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_X509_XPAIR_VALUE *) ASN1_d2i_bio(
			(char *(*)(void))PKI_XPAIR_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_PKI_XPAIR, 
			bp, (unsigned char **) &p);
#else
	return (PKI_X509_XPAIR_VALUE *) ASN1_d2i_bio(
			(void *(*)(void))PKI_XPAIR_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_PKI_XPAIR, 
			bp, (void **) &p);
#endif
}

int i2d_PKI_XPAIR_bio(BIO *bp, PKI_XPAIR *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(PKI_XPAIR *, unsigned char **)) i2d_PKI_XPAIR, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_PKI_XPAIR, bp, (unsigned char *) o);
#endif
}

/* PEM <-> INTERNAL Macros */
PKI_X509_XPAIR_VALUE *PEM_read_bio_PKI_XPAIR( PKI_IO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_X509_XPAIR_VALUE *) PEM_ASN1_read_bio( (char *(*)()) d2i_PKI_XPAIR, 
				PEM_STRING_XPAIR, bp, NULL, NULL, NULL);
#else
	return (PKI_X509_XPAIR_VALUE *) PEM_ASN1_read_bio( (void *(*)()) d2i_PKI_XPAIR, 
				PEM_STRING_X509_XPAIR, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_PKI_XPAIR( BIO *bp, PKI_XPAIR *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_PKI_XPAIR, 
			PEM_STRING_X509_XPAIR, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

