/* libpki/pki_x509_cms.h */

#ifndef HEADER_CMS_H
#include <openssl/cms.h>
#endif

#ifndef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

#ifndef _LIBPKI_X509_CMS_H
#define _LIBPKI_X509_CMS_H

#ifndef CMS_ASCIICRLF
#define CMS_ASCIICRLF 0x80000
#endif

/* ---------------------- Stack and Data Types -------------------------- */

typedef enum {
    PKI_X509_CMS_TYPE_UNKNOWN                 = NID_undef,
    PKI_X509_CMS_TYPE_SIGNED                  = NID_pkcs7_signed,
    PKI_X509_CMS_TYPE_ENVELOPED               = NID_pkcs7_enveloped,
    PKI_X509_CMS_TYPE_DATA                    = NID_pkcs7_data,
    PKI_X509_CMS_TYPE_DIGEST                  = NID_pkcs7_digest,
    PKI_X509_CMS_TYPE_SMIME_COMPRESSED        = NID_id_smime_ct_compressedData,
    PKI_X509_CMS_TYPE_SYM_ENCRYPTED           = NID_pkcs7_encrypted
} PKI_X509_CMS_TYPE;

typedef enum {
    // Format Flags
    PKI_X509_CMS_FLAGS_BINARY                 = CMS_BINARY,
    PKI_X509_CMS_FLAGS_PARTIAL                = CMS_PARTIAL,
    PKI_X509_CMS_FLAGS_DETACHED               = CMS_DETACHED,
    // Features Flags
    PKI_X509_CMS_FLAGS_NOSMIMECAP             = CMS_NOSMIMECAP,
    PKI_X509_CMS_FLAGS_NOCERTS                = CMS_NOCERTS,
    PKI_X509_CMS_FLAGS_NOATTR                 = CMS_NOATTR,
    PKI_X509_CMS_FLAGS_NOCRL                  = CMS_NOCRL,
    PKI_X509_CMS_FLAGS_NOOLDMIMETYPE          = CMS_NOOLDMIMETYPE,
    PKI_X509_CMS_FLAGS_USE_KEYID              = CMS_USE_KEYID,
    PKI_X509_CMS_FLAGS_STREAM                 = CMS_STREAM,
    // Operational Flags
    PKI_X509_CMS_FLAGS_REUSE_DIGEST           = CMS_REUSE_DIGEST,
    PKI_X509_CMS_FLAGS_OP_DEBUG_DECRYPT       = CMS_DEBUG_DECRYPT,
    PKI_X509_CMS_FLAGS_OP_ASCIICRLF           = CMS_ASCIICRLF,
    PKI_X509_CMS_FLAGS_OP_NOINTERN            = CMS_NOINTERN,
    PKI_X509_CMS_FLAGS_OP_NOSIGS              = CMS_NOSIGS,
    PKI_X509_CMS_FLAGS_OP_NO_SIGNER_VERIFY    = CMS_NO_SIGNER_CERT_VERIFY,
    PKI_X509_CMS_FLAGS_NO_CONTENT_VERIFY      = CMS_NO_CONTENT_VERIFY,
    PKI_X509_CMS_FLAGS_NO_ATTRIBUTES_VERIFY   = CMS_NO_ATTR_VERIFY
} PKI_X509_CMS_FLAGS;

// To help developers, we provide the 'positive' flags as well
#define PKI_X509_CMS_FLAGS_ADD_SMIMECAP(a) \
  a &= ~CMS_NOSMIMECAP

#define PKI_X509_CMS_FLAGS_ADD_CERTS(a) \
  a &= ~CMS_NOCERTS

#define PKI_X509_CMS_FLAGS_ADD_ATTR(a) \
  a &= ~CMS_NOATTR

#define PKI_X509_CMS_FLAGS_ADD_CRL(a) \
  a &= ~CMS_NOCRL

#define PKI_X509_CMS_FLAGS_USE_OLDMIMETYPE(a) \
  a &= ~CMS_NOOLDMIMETYPE

#define PKI_X509_CMS_FLAGS_USE_ISSUERANDSERIAL(a) \
  a &= ~CMS_USE_KEYID

#define PKI_X509_CMS_FLAGS_INIT_DEFAULT \
  PKI_X509_CMS_FLAGS_BINARY | PKI_X509_CMS_FLAGS_PARTIAL | \
  PKI_X509_CMS_FLAGS_NOSMIMECAP | PKI_X509_CMS_FLAGS_STREAM | \
  PKI_X509_CMS_FLAGS_NOOLDMIMETYPE

#define PKI_X509_CMS_FLAGS_INIT_SMIME \
  PKI_X509_CMS_FLAGS_PARTIAL | PKI_X509_CMS_FLAGS_STREAM

/* --------------------- Internal Mem Functions ------------------------- */

PKI_X509_CMS_VALUE * PKI_X509_CMS_VALUE_new(void);

PKI_X509_CMS_VALUE * PKI_X509_CMS_VALUE_dup(const PKI_X509_CMS_VALUE * const cms);

void PKI_X509_CMS_VALUE_free(PKI_X509_CMS_VALUE *cms);

/* ------------------------ PEM I/O Functions --------------------------- */

PKI_X509_CMS_VALUE *PKI_PEM_read_bio_CMS( BIO *bp );

int PKI_PEM_write_bio_CMS( BIO *bp, PKI_X509_CMS_VALUE *o );

/* ---------------------------- Functions ------------------------------- */

void PKI_X509_CMS_free(PKI_X509_CMS *cms);

void PKI_X509_CMS_free_void(void *cms);

PKI_X509_CMS *PKI_X509_CMS_new(PKI_X509_CMS_TYPE type,
                               int               flags);

PKI_X509_CMS *PKI_X509_CMS_new_value(PKI_X509_CMS_VALUE * value);

PKI_X509_CMS_TYPE PKI_X509_CMS_get_type(const PKI_X509_CMS * const cms);

int PKI_X509_CMS_data_set_mem(PKI_X509_CMS  * cms,
                              PKI_MEM       * mem,
                              PKI_MEM      ** out_mem,
                              int             flags);

int PKI_X509_CMS_data_set(PKI_X509_CMS   * cms, 
                          unsigned char  * data,
                          size_t           size,
                          PKI_MEM       ** out_mem,
                          int              flags);

PKI_IO * PKI_X509_CMS_stream_init(PKI_X509_CMS * cms);

int PKI_X509_CMS_stream_write_mem(PKI_IO        * cms_io,
                                  const PKI_MEM * mem);

int PKI_X509_CMS_stream_write(PKI_IO              * cms_io,
                              const unsigned char * data,
                              size_t                size);

int PKI_X509_CMS_stream_final(PKI_X509_CMS * cms,
                              PKI_IO       * cms_io);

PKI_X509_CMS * PKI_X509_CMS_wrap(PKI_X509_CMS      ** cms,
                                 PKI_X509_CMS_TYPE    type);

PKI_X509_CMS * PKI_X509_CMS_unwrap(PKI_X509_CMS ** cms);

// CRL
int PKI_X509_CMS_add_crl(PKI_X509_CMS       * cms,
                         const PKI_X509_CRL * const crl);

int PKI_X509_CMS_add_crl_stack(PKI_X509_CMS             * cms,
                               const PKI_X509_CRL_STACK * const crl_sk );

int PKI_X509_CMS_get_crls_num(const PKI_X509_CMS * const cms);

PKI_X509_CRL * PKI_X509_CMS_get_crl(const PKI_X509_CMS * const cms,
                                    int                  idx );

// Certs
int PKI_X509_CMS_add_cert(const PKI_X509_CMS  * cms, 
			                    const PKI_X509_CERT * const x);

int PKI_X509_CMS_add_cert_stack(const PKI_X509_CMS        * cms, 
				                        const PKI_X509_CERT_STACK * const x_sk);

int PKI_X509_CMS_get_certs_num(const PKI_X509_CMS * const cms );

PKI_X509_CERT *PKI_X509_CMS_get_cert(const PKI_X509_CMS * const cms,
                                     int                  idx );

int PKI_X509_CMS_get_signer_num(const PKI_X509_CMS * cms);

PKI_X509_CERT *PKI_X509_CMS_get_signer_cert(const PKI_X509_CMS * cms,
				       				    	                int                  idx);

int PKI_X509_CMS_clear_certs(const PKI_X509_CMS * cms);

// Signer
int PKI_X509_CMS_has_signers(const PKI_X509_CMS * const cms );

int PKI_X509_CMS_add_signer(const PKI_X509_CMS     * const cms,
                            const PKI_X509_CERT    * const signer,
                            const PKI_X509_KEYPAIR * const k,
                            const PKI_DIGEST_ALG   * md,
                            const int                flags );

int PKI_X509_CMS_add_signer_tk(PKI_X509_CMS         * cms,
                               const PKI_TOKEN      * const tk,
                               const PKI_DIGEST_ALG * const md,
                               const int              flags);

const PKI_X509_CMS_SIGNER_INFO * PKI_X509_CMS_get_signer_info(
                            const PKI_X509_CMS * const cms,
                            int                  idx);

// Cipher
int PKI_X509_CMS_set_cipher(PKI_X509_CMS       * const cms,
                            const PKI_CIPHER   * const cipher);

const PKI_X509_ALGOR_VALUE * PKI_X509_CMS_get_encode_alg(
                            const PKI_X509_CMS * const cms);

int PKI_X509_CMS_encode(const PKI_X509_CMS * const cms,
                        unsigned char      * data,
                        size_t               size);

PKI_MEM *PKI_X509_CMS_decode(const PKI_X509_CMS     * const cms,
                             const PKI_X509_KEYPAIR * const pkey,
                             const PKI_X509_CERT    * const x);

// Recipients
int PKI_X509_CMS_has_recipients(const PKI_X509_CMS * const cms );

int PKI_X509_CMS_set_recipients(const PKI_X509_CMS        * cms, 
                                const PKI_X509_CERT_STACK * const x_sk);

int PKI_X509_CMS_add_recipient(const PKI_X509_CMS  * cms,
                               const PKI_X509_CERT * const x,
                               const PKI_CIPHER    * const cipher,
                               const int             flags);

int PKI_X509_CMS_add_recipient_tk(const PKI_X509_CMS * cms,
                                  const PKI_TOKEN    * const tk,
                                  const PKI_CIPHER   * const cipher,
                                  const int            flags);

int PKI_X509_CMS_get_recipients_num(const PKI_X509_CMS * const cms);

PKI_X509_CMS_RECIPIENT_INFO * PKI_X509_CMS_get_recipient_info(
                                  const PKI_X509_CMS * const cms,
                                  int                  idx );

int PKI_X509_CMS_recipient_num(const PKI_X509_CMS  * const cms,
                               const PKI_X509_CERT * const x );

// Data
PKI_MEM *PKI_X509_CMS_get_data(const PKI_X509_CMS     * const cms,
                               const PKI_X509_KEYPAIR * const pkey,
                               const PKI_X509_CERT    * const x );

PKI_MEM *PKI_X509_CMS_get_data_tk(const PKI_X509_CMS * const cms,
                                  const PKI_TOKEN    * const tk);

PKI_MEM *PKI_X509_CMS_get_raw_data(const PKI_X509_CMS * const cms );


/* ------------------------- X509_ATTRIBUTE funcs ----------------------- */

int PKI_X509_CMS_add_attribute(const PKI_X509_CMS * cms,
                               PKI_X509_ATTRIBUTE * a);

int PKI_X509_CMS_add_signed_attribute(const PKI_X509_CMS * cms,
                                      PKI_X509_ATTRIBUTE * a);

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_signed_attribute(
                            const PKI_X509_CMS * const cms, 
                            PKI_ID               id );

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_attribute(
                            const PKI_X509_CMS * const cms,
                            PKI_ID               id);

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_signed_attribute_by_name(
                            const PKI_X509_CMS * const cms, 
                            const char         * const name );

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_attribute_by_name(
                            const PKI_X509_CMS * const cms, 
                            const char         * const name);

int PKI_X509_CMS_delete_attribute(const PKI_X509_CMS * cms,
                                  PKI_ID               id);

int PKI_X509_CMS_delete_signed_attribute(const PKI_X509_CMS * cms,
                                         PKI_ID               id);

/* ------------------------------ TXT Format CB -------------------------- */

int PKI_X509_CMS_VALUE_print_bio(PKI_IO                   * bio,
                                 const PKI_X509_CMS_VALUE * const cmsval );

#endif

