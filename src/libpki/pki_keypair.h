/* libpki pKey */

#ifndef _LIBPKI_X509_KEYPAIR_HEADER_H
#define _LIBPKI_X509_KEYPAIR_HEADER_H

typedef struct pw_cb_data {
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

#define PKI_X509_KEYPAIR_new_RSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new( PKI_SCHEME_RSA,a,l,c,h );
#define PKI_X509_KEYPAIR_new_DSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new( PKI_SCHEME_DSA,a,l,c,h );

#ifdef ENABLE_ECDSA
#define PKI_X509_KEYPAIR_new_ECDSA(a,l,c,h) \
		PKI_X509_KEYPAIR_new(PKI_SCHEME_ECDSA,a,l,c,h);
#endif

/* ------------------------ Memory Management ----------------------- */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_null ();
void PKI_X509_KEYPAIR_free( PKI_X509_KEYPAIR *key );
void PKI_X509_KEYPAIR_free_void ( void *key );

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new( PKI_SCHEME_ID type, int bits, 
				char *label, PKI_CRED *cred, HSM *hsm );
PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_kp( PKI_KEYPARAMS *kp,
				char *label, PKI_CRED *cred, HSM *hsm );
PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url( PKI_SCHEME_ID type, int bits, 
				URL *url, PKI_CRED *cred, HSM *hsm );
PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url_kp( PKI_KEYPARAMS *kp,
				URL *url, PKI_CRED *cred, HSM *hsm );

/* ------------------------ General Functions ----------------------- */

char *PKI_X509_KEYPAIR_get_parsed(PKI_X509_KEYPAIR *pkey );
PKI_SCHEME_ID PKI_X509_KEYPAIR_get_scheme(PKI_X509_KEYPAIR *k);
PKI_ALGOR * PKI_X509_KEYPAIR_get_algor(PKI_X509_KEYPAIR *k);
int PKI_X509_KEYPAIR_get_size(PKI_X509_KEYPAIR *k);
PKI_MEM *PKI_X509_KEYPAIR_get_pubkey(PKI_X509_KEYPAIR *kp);
PKI_MEM *PKI_X509_KEYPAIR_get_privkey(PKI_X509_KEYPAIR *kp);
PKI_DIGEST *PKI_X509_KEYPAIR_VALUE_pub_digest(PKI_X509_KEYPAIR_VALUE *pkey,
			PKI_DIGEST_ALG *md );

PKI_SCHEME_ID PKI_X509_KEYPAIR_VALUE_get_scheme(PKI_X509_KEYPAIR_VALUE *pVal);
PKI_ALGOR * PKI_X509_KEYPAIR_VALUE_get_algor ( PKI_X509_KEYPAIR_VALUE *pVal );
int PKI_X509_KEYPAIR_VALUE_get_size ( PKI_X509_KEYPAIR_VALUE *pKey );
PKI_DIGEST *PKI_X509_KEYPAIR_pub_digest ( PKI_X509_KEYPAIR *pkey, 
			PKI_DIGEST_ALG *md);

/* ------------------------ EC Specific ------------------------------ */

int PKI_X509_KEYPAIR_get_curve(PKI_X509_KEYPAIR *kp);

/* ----------------------- PKCS#8 Format ----------------------------- */

PKI_MEM *PKI_X509_KEYPAIR_get_p8 ( PKI_X509_KEYPAIR *key );

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_p8 ( PKI_MEM *buf );

#endif
