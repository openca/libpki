/* Lightweight Internet Revocation Token implementation
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

/* DER <-> INTERNAL Macros */
PKI_LIRT *d2i_PKI_LIRT_bio ( BIO *bp, PKI_LIRT *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_LIRT *) ASN1_d2i_bio(
			(char *(*)(void))PKI_LIRT_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_PKI_LIRT, 
			bp, (unsigned char **) &p);
#else
	return (PKI_LIRT *) ASN1_d2i_bio(
			(void *(*)(void))PKI_LIRT_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_PKI_LIRT, 
			bp, (void **) &p);
#endif
}

int i2d_PKI_LIRT_bio(BIO *bp, PKI_LIRT *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(PKI_LIRT *, unsigned char **)) i2d_PKI_LIRT, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_PKI_LIRT, bp, (unsigned char *) o);
#endif
}


/* PEM <-> INTERNAL Macros */
PKI_LIRT *PEM_read_bio_PKI_LIRT( BIO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_LIRT *) PEM_ASN1_read_bio( (char *(*)()) d2i_PKI_LIRT, 
				PEM_STRING_PKI_LIRT, bp, NULL, NULL, NULL);
#else
	return (PKI_LIRT *) PEM_ASN1_read_bio( (void *(*)()) d2i_PKI_LIRT, 
				PEM_STRING_PKI_LIRT, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_PKI_LIRT( BIO *bp, PKI_LIRT *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_PKI_LIRT, 
			PEM_STRING_PKI_LIRT, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

