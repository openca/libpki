/* src/libpki/drivers/openssl_hsm_cb.h */

#ifndef _LIBPKI_OPENSSL_HSM_CB_H
#define _LIBPKI_OPENSSL_HSM_CB_H

// ================
// OpenSSL Includes
// ================

#ifndef HEADER_PEM_H
#include <openssl/pem.h>
#endif

#ifndef HEADER_CMS_H
#include <openssl/cms.h>
#endif

// ======================
// Library Internal Types
// ======================

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/pki_datatypes.h>
#endif

#ifndef _LIBPKI_PKI_X509_TYPES_H
#include <libpki/pki_x509_types.h>
#endif

#include <libpki/pki_mem.h>
#include <libpki/net/url.h>

#include <libpki/drivers/openssl/openssl_hsm_pkey.h>

#include <libpki/pki_x509_cert.h>

#include <libpki/pki_x509_req.h>

#include <libpki/pki_x509_crl.h>

#include <libpki/pki_x509_pkcs7.h>

#include <libpki/pki_x509_cms.h>

#include <libpki/pki_x509_p12.h>

#include <libpki/pki_ocsp_req.h>

#include <libpki/pki_ocsp_resp.h>

#include <libpki/prqp/prqp.h>




// ========================================
// Function Signature for the HSM Callbacks
// ========================================

const PKI_X509_CALLBACKS *HSM_OPENSSL_X509_get_cb(PKI_DATATYPE type);

#endif

