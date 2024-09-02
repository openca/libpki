/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_HEADER_PKI_509_MIME_H
#define _LIBPKI_HEADER_PKI_509_MIME_H

#define PKI_MIMETYPE_UNKNOWN            "x-application/unknown"
#define PKI_MIMETYPE_KEYPAIR            "x-application/x-x509-keypair"
#define PKI_MIMETYPE_PUBKEY             "x-application/x-x509-pubkey"
#define PKI_MIMETYPE_PRIVKEY            "x-application/x-x509-privkey"
#define PKI_MIMETYPE_CRED               "x-application/x-x509-cred"
#define PKI_MIMETYPE_X509_CERT          "x-application/x-x509-cert"
#define PKI_MIMETYPE_X509_CRL           "x-application/x-x509-crl"
#define PKI_MIMETYPE_X509_REQ           "x-application/x-x509-request"
#define PKI_MIMETYPE_X509_PKCS7         "x-application/x-x509-pkcs7"
#define PKI_MIMETYPE_X509_PKCS12        "x-application/x-x509-pkcs12"
#define PKI_MIMETYPE_X509_OCSP_REQ      "x-application/x-x509-ocsp-request"
#define PKI_MIMETYPE_X509_OCSP_RESP     "x-application/x-x509-ocsp-response"
#define PKI_MIMETYPE_X509_PRQP_REQ      "x-application/x-x509-prqp-request"
#define PKI_MIMETYPE_X509_PRQP_RESP     "x-application/x-x509-prqp-response"
#define PKI_MIMETYPE_X509_X509_XPAIR    "x-application/x-x509-crossCertPair"

const char * PKI_X509_get_mimetype ( PKI_DATATYPE type );

#endif /* _LIBPKI_HEADER_PKI_X509_MIME_H */
