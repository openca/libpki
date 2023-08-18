/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_PQC_DEFS_H
#define _LIBPKI_PQC_DEFS_H

// Include the library configuration
#ifdef __LIB_BUILD__
#include <libpki/config.h>
#endif

#ifdef ENABLE_OQS
# ifndef OQS_H
#  include <oqs/oqs.h>
# endif
#endif

// ===============
// OQS definitions
// ===============

#define SIZE_OF_UINT32 4
#define ENCODE_UINT32(pbuf, i)  (pbuf)[0] = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[1] = (unsigned char)((i>>16) & 0xff); \
				(pbuf)[2] = (unsigned char)((i>> 8) & 0xff); \
				(pbuf)[3] = (unsigned char)((i    ) & 0xff)
#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) (pbuf)[0]) << 24; \
                                i |= ((uint32_t) (pbuf)[1]) << 16; \
				i |= ((uint32_t) (pbuf)[2]) <<  8; \
				i |= ((uint32_t) (pbuf)[3])


// =======================
// PKEY ASN.1 Method Macro
// =======================

/*
// #define DECLARE_OQS_EVP_PKEY_ASN1_METHOD(ALG)
// extern EVP_PKEY_ASN1_METHOD ALG##_ASN1_METH
*/

#define DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME) \
EVP_PKEY_ASN1_METHOD ALG##_ASN1_METH = {       \
    NID_ALG,                                   \
    NID_ALG,                                   \
    0,                                         \
    SHORT_NAME,                                \
    LONG_NAME,                                 \
    oqs_pub_decode,                            \
    oqs_pub_encode,                            \
    oqs_pub_cmp,                               \
    oqs_pub_print,                             \
    oqs_priv_decode,                           \
    oqs_priv_encode,                           \
    oqs_priv_print,                            \
    oqs_size,                                  \
    oqs_bits,                                  \
    oqs_security_bits,                         \
    0, 0, 0, 0,                                \
    oqs_cmp_parameters,                        \
    0, 0,                                      \
    oqs_free,                                  \
    oqs_ameth_pkey_ctrl,                       \
    0, 0,                                      \
    oqs_item_verify,                           \
    oqs_item_sign_##ALG,                       \
    oqs_sig_info_set_##ALG,                    \
    0, 0, 0, 0, 0,                             \
};

// =================
// PKEY Method Macro
// =================

/*
// #define DECLARE_OQS_EVP_PKEY_METHOD(ALG)
// extern const EVP_PKEY_METHOD ALG##_PKEY_METH
*/

#define DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)    \
const EVP_PKEY_METHOD ALG##_PKEY_METH = {           \
    NID_ALG, EVP_PKEY_FLAG_SIGCTX_CUSTOM,           \
    0, pkey_oqs_copy, 0, 0, 0, 0,                   \
    pkey_oqs_keygen,                                \
    pkey_oqs_sign_init, pkey_oqs_sign,              \
    pkey_oqs_verify_init, pkey_oqs_verify,          \
    0, 0,                                           \
    pkey_oqs_signctx_init, pkey_oqs_signctx,        \
    pkey_oqs_verifyctx_init, pkey_oqs_verifyctx,    \
    0, 0, 0, 0, 0, 0,                               \
    pkey_oqs_ctrl,                                  \
    0,                                              \
    pkey_oqs_digestsign,                            \
    pkey_oqs_digestverify,                          \
    0, 0, 0,                                        \
    pkey_oqs_digestcustom                           \
};

// ====================
// OQS EVP Method Macro
// ====================

#define DEFINE_OQS_EVP_METHODS(ALG, NID_ALG, SHORT_NAME, LONG_NAME)   \
DEFINE_OQS_ITEM_SIGN(ALG, NID_ALG)                                    \
DEFINE_OQS_SIGN_INFO_SET(ALG, NID_ALG)                                \
DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)                              \
DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME)


#endif // End of _LIBPKI_PQC_DEFS_H