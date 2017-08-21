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

void PKI_X509_PKCS7_free(PKI_X509_PKCS7 *p7);

void PKI_X509_PKCS7_free_void(void *p7);

PKI_X509_PKCS7 *PKI_X509_PKCS7_new(PKI_X509_PKCS7_TYPE type);

PKI_X509_PKCS7_TYPE PKI_X509_PKCS7_get_type(const PKI_X509_PKCS7 * const p7);

// CRL
int PKI_X509_PKCS7_add_crl(PKI_X509_PKCS7     * p7,
                           const PKI_X509_CRL * const crl);

int PKI_X509_PKCS7_add_crl_stack(PKI_X509_PKCS7           * p7,
                                 const PKI_X509_CRL_STACK * const crl_sk );

int PKI_X509_PKCS7_get_crls_num(const PKI_X509_PKCS7 * const p7);

PKI_X509_CRL * PKI_X509_PKCS7_get_crl(const PKI_X509_PKCS7 * const p7,
                                      int                    idx );

// Certs
int PKI_X509_PKCS7_add_cert(const PKI_X509_PKCS7 * p7, 
			    const PKI_X509_CERT  * const x);

int PKI_X509_PKCS7_add_cert_stack(const PKI_X509_PKCS7      * p7, 
				  const PKI_X509_CERT_STACK * const x_sk);

int PKI_X509_PKCS7_get_certs_num(const PKI_X509_PKCS7 * const p7 );

PKI_X509_CERT *PKI_X509_PKCS7_get_cert(const PKI_X509_PKCS7 * const p7,
                                       int                    idx );

int PKI_X509_PKCS7_clear_certs(const PKI_X509_PKCS7 * p7);

// Signer
int PKI_X509_PKCS7_has_signers(const PKI_X509_PKCS7 * const p7 );

int PKI_X509_PKCS7_add_signer(const PKI_X509_PKCS7   * p7,
			      const PKI_X509_CERT    * const signer,
			      const PKI_X509_KEYPAIR * const k,
			      const PKI_DIGEST_ALG   * md );

int PKI_X509_PKCS7_add_signer_tk(PKI_X509_PKCS7       * p7,
                              const PKI_TOKEN      * const tk,
                              const PKI_DIGEST_ALG * const md);

const PKCS7_SIGNER_INFO * PKI_X509_PKCS7_get_signer_info(
                              const PKI_X509_PKCS7 * const p7,
                              int                    idx);

// Cipher
int PKI_X509_PKCS7_set_cipher(const PKI_X509_PKCS7 * p7,
			      const PKI_CIPHER     * const cipher);

const PKI_ALGOR * PKI_X509_PKCS7_get_encode_alg(
                              const PKI_X509_PKCS7 * const p7);

int PKI_X509_PKCS7_encode(const PKI_X509_PKCS7 * const p7,
                          unsigned char        * data,
                          size_t                 size);

PKI_MEM *PKI_X509_PKCS7_decode(const PKI_X509_PKCS7   * const p7,
                               const PKI_X509_KEYPAIR * const pkey,
                               const PKI_X509_CERT    * const x);

// Recipients
int PKI_X509_PKCS7_has_recipients(const PKI_X509_PKCS7 * const p7 );

int PKI_X509_PKCS7_set_recipients(const PKI_X509_PKCS7      * p7, 
				  const PKI_X509_CERT_STACK * const x_sk);

int PKI_X509_PKCS7_add_recipient(const PKI_X509_PKCS7 * p7,
				 const PKI_X509_CERT  * x);

int PKI_X509_PKCS7_get_recipients_num(const PKI_X509_PKCS7 * const p7);

const PKCS7_RECIP_INFO * PKI_X509_PKCS7_get_recipient_info(
                                                 const PKI_X509_PKCS7 * const p7,
                                                 int                    idx );

const PKI_X509_CERT * PKI_X509_PKCS7_get_recipient_cert(
                                                 const PKI_X509_PKCS7 * const p7,
                                                 int                    idx );

// Data
PKI_MEM *PKI_X509_PKCS7_get_data(const PKI_X509_PKCS7   * const p7,
                                 const PKI_X509_KEYPAIR * const pkey,
                                 const PKI_X509_CERT    * const x );

PKI_MEM *PKI_X509_PKCS7_get_data_tk(const PKI_X509_PKCS7 * const p7,
                                    const PKI_TOKEN      * const tk);

PKI_MEM *PKI_X509_PKCS7_get_raw_data(const PKI_X509_PKCS7 * const p7 );


/* ------------------------- X509_ATTRIBUTE funcs ----------------------- */

int PKI_X509_PKCS7_add_attribute(const PKI_X509_PKCS7 * p7,
                                 PKI_X509_ATTRIBUTE   * a);

int PKI_X509_PKCS7_add_signed_attribute(const PKI_X509_PKCS7 * p7,
                                        PKI_X509_ATTRIBUTE   * a);

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute(
                                const PKI_X509_PKCS7 * const p7, 
                                PKI_ID                 id );

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute(
                                const PKI_X509_PKCS7 * const p7,
                                PKI_ID                 id);

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute_by_name(
                                const PKI_X509_PKCS7 * const p7, 
                                const char           * const name );

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute_by_name(
                                const PKI_X509_PKCS7 * const p7, 
                                const char           * const name);

int PKI_X509_PKCS7_delete_attribute(const PKI_X509_PKCS7 * p7,
                                    PKI_ID                 id);

int PKI_X509_PKCS7_delete_signed_attribute(const PKI_X509_PKCS7 * p7,
                                           PKI_ID                 id);

/* ------------------------------ TXT Format CB -------------------------- */

int PKI_X509_PKCS7_VALUE_print_bio(PKI_IO                     * bio,
                                   const PKI_X509_PKCS7_VALUE * const p7val );

#endif

