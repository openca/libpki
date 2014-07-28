/* libpki/pki_x509_pkcs7.h */

#ifndef _LIBPKI_X509_PKCS7_H
#define _LIBPKI_X509_PKCS7_H

/* ---------------------- Stack and Data Types -------------------------- */

typedef enum {
	PKI_X509_PKCS7_TYPE_UNKNOWN = NID_undef,
	PKI_X509_PKCS7_TYPE_EMPTY = 1,
	PKI_X509_PKCS7_TYPE_SIGNED = NID_pkcs7_signed,
	PKI_X509_PKCS7_TYPE_ENCRYPTED = NID_pkcs7_enveloped,
	PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED = NID_pkcs7_signedAndEnveloped,
	PKI_X509_PKCS7_TYPE_DATA = NID_pkcs7_data,
} PKI_X509_PKCS7_TYPE;

/* ---------------------------- Functions ------------------------------- */

void PKI_X509_PKCS7_free ( PKI_X509_PKCS7 *p7 );
void PKI_X509_PKCS7_free_void ( void *p7 );
PKI_X509_PKCS7 *PKI_X509_PKCS7_new ( PKI_X509_PKCS7_TYPE type );

// PKCS#7 Type
PKI_X509_PKCS7_TYPE PKI_X509_PKCS7_get_type ( PKI_X509_PKCS7 *p7 );

// CRL
int PKI_X509_PKCS7_add_crl ( PKI_X509_PKCS7 *p7, PKI_X509_CRL *crl );
int PKI_X509_PKCS7_add_crl_stack ( PKI_X509_PKCS7 *p7, 
						PKI_X509_CRL_STACK *crl_sk );
int PKI_X509_PKCS7_get_crls_num ( PKI_X509_PKCS7 *p7 );
PKI_X509_CERT *PKI_X509_PKCS7_get_crl ( PKI_X509_PKCS7 *p7, int idx );

// Certs
int PKI_X509_PKCS7_add_cert ( PKI_X509_PKCS7 *p7, PKI_X509_CERT *x );
int PKI_X509_PKCS7_add_cert_stack ( PKI_X509_PKCS7 *p7, 
					PKI_X509_CERT_STACK *crl_sk );
int PKI_X509_PKCS7_get_certs_num ( PKI_X509_PKCS7 *p7 );
int PKI_X509_PKCS7_clear_certs ( PKI_X509_PKCS7 *p7 );
PKI_X509_CERT *PKI_X509_PKCS7_get_cert ( PKI_X509_PKCS7 *p7, int idx );

// Signer
int PKI_X509_PKCS7_has_signers ( PKI_X509_PKCS7 *p7 );
int PKI_X509_PKCS7_add_signer ( PKI_X509_PKCS7 *p7, PKI_X509_CERT *signer,
			PKI_X509_KEYPAIR *pkey, PKI_DIGEST_ALG *md );
int PKI_X509_PKCS7_add_signer_tk ( PKI_X509_PKCS7 *p7, PKI_TOKEN *tk, 
			PKI_DIGEST_ALG *md);
PKCS7_SIGNER_INFO * PKI_X509_PKCS7_get_signer_info (PKI_X509_PKCS7 *p7,int idx);

// Cipher
int PKI_X509_PKCS7_set_cipher ( PKI_X509_PKCS7 *p7, PKI_CIPHER *cipher );
PKI_ALGOR * PKI_X509_PKCS7_get_encode_alg ( PKI_X509_PKCS7 *p7 );
int PKI_X509_PKCS7_encode (PKI_X509_PKCS7 *p7,unsigned char *data, size_t size);
PKI_MEM *PKI_X509_PKCS7_decode (PKI_X509_PKCS7 *p7, 
		PKI_X509_KEYPAIR *pkey, PKI_X509_CERT *x);

// Recipients
int PKI_X509_PKCS7_has_recipients ( PKI_X509_PKCS7 *p7 );
int PKI_X509_PKCS7_set_recipients ( PKI_X509_PKCS7 *p7, PKI_X509_CERT_STACK *x_sk );
int PKI_X509_PKCS7_add_recipient ( PKI_X509_PKCS7 *p7, PKI_X509_CERT *x );

int PKI_X509_PKCS7_get_recipients_num ( PKI_X509_PKCS7 *p7 );
PKCS7_RECIP_INFO * PKI_X509_PKCS7_get_recipient_info ( PKI_X509_PKCS7 *p7,
							int idx );
PKI_X509_CERT * PKI_X509_PKCS7_get_recipient_cert ( PKI_X509_PKCS7 *p7,
							int idx );

// Data
PKI_MEM *PKI_X509_PKCS7_get_data ( PKI_X509_PKCS7 *p7, PKI_X509_KEYPAIR *pkey,
					PKI_X509_CERT *x );

PKI_MEM *PKI_X509_PKCS7_get_data_tk ( PKI_X509_PKCS7 *p7 , PKI_TOKEN *tk);

PKI_MEM *PKI_X509_PKCS7_get_raw_data ( PKI_X509_PKCS7 *p7 );



/* ------------------------- X509_ATTRIBUTE funcs ----------------------- */

int PKI_X509_PKCS7_add_attribute ( PKI_X509_PKCS7 *p7, PKI_X509_ATTRIBUTE *a );
int PKI_X509_PKCS7_add_signed_attribute ( PKI_X509_PKCS7 *p7, PKI_X509_ATTRIBUTE *a );

PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute( PKI_X509_PKCS7 *p7, PKI_ID id );
PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute( PKI_X509_PKCS7 *p7, PKI_ID id );
PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute_by_name( PKI_X509_PKCS7 *p7, 
					char *name );
PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute_by_name(PKI_X509_PKCS7 *p7, 
					char *name);

int PKI_X509_PKCS7_delete_attribute ( PKI_X509_PKCS7 *p7, PKI_ID id );
int PKI_X509_PKCS7_delete_signed_attribute ( PKI_X509_PKCS7 *p7, PKI_ID id );

/* ------------------------------ TXT Format CB -------------------------- */

int PKI_X509_PKCS7_VALUE_print_bio ( PKI_IO *bio,
                                        PKI_X509_PKCS7_VALUE *p7val );

#endif

