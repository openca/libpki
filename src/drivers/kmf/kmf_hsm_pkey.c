/* openssl/pki_pkey.c */

#include <libpki/pki.h>

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_INTERNAL_PKEY_H
#define _LIBPKI_INTERNAL_PKEY_H

#define PKI_RSA_KEY	RSA
#define PKI_DSA_KEY	DSA

#ifdef ENABLE_ECDSA
/* No ECDSA support in KMF so far! */
#define PKI_EC_KEY	0
#endif

#define PKI_RSA_KEY_MIN_SIZE		512
#define PKI_DSA_KEY_MIN_SIZE		512
#define PKI_EC_KEY_MIN_SIZE		56

/* End of _LIBPKI_INTERNAL_PKEY_H */
#endif

int HSM_KMF_KEYPAIR_free ( PKI_KEYPAIR *pkey ) {

	if( !pkey ) return(PKI_ERR);

	return (PKI_ERR);
}

PKI_KEYPAIR *HSM_KMF_KEYPAIR_new( int type, int bits, HSM *hsm, 
							PKI_CRED *cred ) {
	PKI_KEYPAIR *ret = NULL;
	PKI_RSA_KEY *rsa = NULL;
	PKI_DSA_KEY *dsa = NULL;

	/* Let's return the PKEY infrastructure */
	return ( ret );
}

int PKI_KMF_KEYPAIR_write_file( PKI_KEYPAIR *key, int format, char *file,
							HSM *hsm ) {
	int ret = PKI_OK;

	if( !key ) return (PKI_ERR);

	switch( format ) {
		case PKI_FORMAT_PEM:
		case PKI_FORMAT_ASN1:
			break;
		default:
			/* Format not recognized ! */
			fprintf(stderr, "%s:%d format not recognized (%d)\n",
					format, __FILE__, __LINE__ );
			return(PKI_ERR);
	}

	/* Open the file... etc... */
	switch( format ) {
		case PKI_FORMAT_PEM:
			break;
		case PKI_FORMAT_ASN1:
			break;
		default:
			/* Format not recognized ! */
			fprintf(stderr, "%s:%d error\n", __FILE__, __LINE__ );
	}

	return(ret);
}

