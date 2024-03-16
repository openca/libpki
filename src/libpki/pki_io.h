/* I/O headers */

#ifndef _LIBPKI_IO_H
#define _LIBPKI_IO_H
# pragma once

#include <openssl/bio.h>

#include <libpki/pki_x509_data_st.h>

// // Base definition for PKI_IO
// #define PKI_IO				BIO

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
