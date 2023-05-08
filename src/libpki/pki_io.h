/* I/O headers */

#ifndef _LIBPKI_IO_H
#define _LIBPKI_IO_H

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/datatypes.h>
#endif

#ifndef _LIBPKI_PKI_X509_IO_H
#include <libpki/pki_net.h>
#endif

// =================
// External Includes
// =================

#include <openssl/bio.h>

// =====================
// Local LibPKI Includes
// =====================

#include <libpki/io/pki_x509_io.h>
#include <libpki/io/pki_keypair_io.h>
#include <libpki/io/pki_x509_cert_io.h>
#include <libpki/io/pki_x509_req_io.h>
#include <libpki/io/pki_x509_crl_io.h>
#include <libpki/io/pki_x509_pkcs7_io.h>
#include <libpki/io/pki_x509_cms_io.h>
#include <libpki/io/pki_x509_p12_io.h>
#include <libpki/io/pki_x509_xpair_io.h>
#include <libpki/io/pki_ocsp_req_io.h>
#include <libpki/io/pki_ocsp_resp_io.h>
#include <libpki/io/pki_msg_req_io.h>
#include <libpki/io/pki_msg_resp_io.h>

#endif
