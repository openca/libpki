/* ERR String definitions
 * 
 * NOTE: When adding a new error, please check that the PKI_ERR_
 *       and the corresponding string description match the error!
 */

#ifndef _LIBPKI_ERR_H
#define _LIBPKI_ERR_H

typedef enum {
	// General Errors
	PKI_ERR_UNKNOWN 	= 0,
	PKI_ERR_GENERAL,
	PKI_ERR_NOT_IMPLEMENTED,
	PKI_ERR_MEMORY_ALLOC,
	PKI_ERR_OBJECT_CREATE,
	PKI_ERR_POINTER_NULL,
	PKI_ERR_PARAM_NULL,
	PKI_ERR_CALLBACK_NULL,
	PKI_ERR_PARAM_TYPE,
	PKI_ERR_PKI_FORMAT_UNKNOW,
	PKI_ERR_DATA_FORMAT_UNKNOWN,
	// PKI MEM Errors
	PKI_ERR_MEM_,
	// PKI DIGEST Errors
	PKI_ERR_DIGEST_TYPE_UNKNOWN,
	PKI_ERR_DIGEST_VALUE_NULL,
	// URI related Errors
	PKI_ERR_URI_UNSUPPORTED,
	PKI_ERR_URI_GENERAL,
	PKI_ERR_URI_PARSE,
	PKI_ERR_URI_OPEN,
	PKI_ERR_URI_CLOSE,
	PKI_ERR_URI_READ,
	PKI_ERR_URI_WRITE,
	PKI_ERR_URI_DNS,
	PKI_ERR_URI_SSL,
	PKI_ERR_URI_SSL_TRUST,
	// HSM Related
	PKI_ERR_HSM_INIT,
	PKI_ERR_HSM_LOGIN,
	PKI_ERR_HSM_SET_ALGOR,
	PKI_ERR_HSM_SET_SLOT,
	PKI_ERR_HSM_KEYPAIR_LOAD,
	PKI_ERR_HSM_KEYPAIR_STORE,
	PKI_ERR_HSM_KEYPAIR_IMPORT,
	PKI_ERR_HSM_KEYPAIR_EXPORT,
	PKI_ERR_HSM_KEYPAIR_GENERATE,
	PKI_ERR_HSM_SCHEME_UNSUPPORTED,
	PKI_ERR_HSM_,
	// Configuration Related
	PKI_ERR_CONFIG_MISSING,
	PKI_ERR_CONFIG_LOAD,
	PKI_ERR_CONFIG_SAVE,
	PKI_ERR_CONFIG_,
	// Profile Related
	PKI_ERR_X509_PROFILE_,
	// Token Related
	PKI_ERR_TOKEN_INIT,
	PKI_ERR_TOKEN_LOGIN,
	PKI_ERR_TOKEN_KEYPAIR_LOAD,
	PKI_ERR_TOKEN_CERT_LOAD,
	PKI_ERR_TOKEN_CACERT_LOAD,
	PKI_ERR_TOKEN_OTHERCERTS_LOAD,
	PKI_ERR_TOKEN_TRUSTEDCERTS_LOAD,
	PKI_ERR_TOKEN_SET_CRED,
	PKI_ERR_TOKEN_USE_SLOT,
	PKI_ERR_TOKEN_PROFILE_LOAD,
	PKI_ERR_TOKEN_SET_ALGOR,
	PKI_ERR_TOKEN_GET_ALGOR,
	PKI_ERR_TOKEN_,
	// Key Operations
	PKI_ERR_X509_KEYPAIR_SIZE,
	PKI_ERR_X509_KEYPAIR_SIZE_SHORT,
	PKI_ERR_X509_KEYPAIR_SIZE_LONG,
	PKI_ERR_X509_KEYPAIR_GENERATION,
	PKI_ERR_X509_KEYPAIR_,
	// Certificate Operations
	PKI_ERR_X509_CERT_CREATE,
	PKI_ERR_X509_CERT_CREATE_SUBJECT,
	PKI_ERR_X509_CERT_CREATE_VERSION,
	PKI_ERR_X509_CERT_CREATE_NOTBEFORE,
	PKI_ERR_X509_CERT_CREATE_NOTAFTER,
	PKI_ERR_X509_CERT_CREATE_ISSUER,
	PKI_ERR_X509_CERT_CREATE_SERIAL,
	PKI_ERR_X509_CERT_,
	PKI_ERR_X509_CERT_VERIFY_,
	// Request Operations
	PKI_ERR_X509_REQ_CREATE,
	PKI_ERR_X509_REQ_CREATE_SUBJECT,
	PKI_ERR_X509_REQ_CREATE_VERSION,
	PKI_ERR_X509_REQ_CREATE_NOTBEFORE,
	PKI_ERR_X509_REQ_CREATE_NOTAFTER,
	PKI_ERR_X509_REQ_CREATE_PUBKEY,
	PKI_ERR_X509_REQ_CREATE_ALGORITHM,
	PKI_ERR_X509_REQ_,
	// CRL Errors
	PKI_ERR_X509_CRL,
	// PKI X509 PKCS7 ERRORS
	PKI_ERR_X509_PKCS7_TYPE_UNKNOWN,
	PKI_ERR_X509_PKCS7_SIGNER_INFO_NULL,
	PKI_ERR_X509_PKCS7_CIPHER,
	// OCSP Ops
	PKI_ERR_OCSP_RESP_ENCODE,
	PKI_ERR_OCSP_RESP_DECODE,
	PKI_ERR_OCSP_RESP_SIGN,
	PKI_ERR_OCSP_REQ_ENCODE,
	PKI_ERR_OCSP_REQ_DECODE,
	PKI_ERR_OCSP_REQ_SIGN,
	PKI_ERR_OCSP_NONCE_COPY,
	PKI_ERR_OCSP_,
	// PRQP Ops */
	PKI_ERR_PRQP_,
	// PKI Message Operations
	PKI_ERR_MSG_,
	// Enrollment Protocol Related
	PKI_ERR_ENROLL_,
	// Signatures Related Errors
	PKI_ERR_SIGN_,
	PKI_ERR_SIGN_VERIFY,
	// Network Related Errors
	PKI_ERR_NET_OPEN,
	PKI_ERR_NET_,
	// SSL/TLS Related Errors
	PKI_ERR_NET_SSL_NOT_SUPPORTED,
	PKI_ERR_NET_SSL_NO_CIPHER,
	PKI_ERR_NET_SSL_VERIFY,
	PKI_ERR_NET_SSL_SET_SOCKET,
	PKI_ERR_NET_SSL_SET_CIPHER,
	PKI_ERR_NET_SSL_SET_FLAGS,
	PKI_ERR_NET_SSL_INIT,
	PKI_ERR_NET_SSL_START,
	PKI_ERR_NET_SSL_CONNECT,
	PKI_ERR_NET_SSL_PEER_CERTIFICATE,
	PKI_ERR_NET_SSL_,
	// SCEP Related Errors
	PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN,
	PKI_ERR_SCEP_,
} PKI_ERR_CODE;

typedef struct pki_err_st {
	PKI_ERR_CODE   code;
	char         * descr;
} PKI_ERR_ST;

/* We define the actual object of strings only if we are compiling
 * the pki_err.c file where __LIBPKI_ERR__ is defined */

#ifdef __LIBPKI_ERR__

const PKI_ERR_ST __libpki_errors_st[] = {
	// General Errors
	{ PKI_ERR_UNKNOWN, "Unknown Error" },
	{ PKI_ERR_GENERAL, "General Error" },
	{ PKI_ERR_NOT_IMPLEMENTED, "Not Implemented" },
	{ PKI_ERR_MEMORY_ALLOC, "Memory Allocation Error" },
	{ PKI_ERR_OBJECT_CREATE, "Object Creation Error" },
	{ PKI_ERR_POINTER_NULL, "Null Memory Pointer" },
	{ PKI_ERR_PARAM_NULL, "Null Parameter" },
	{ PKI_ERR_CALLBACK_NULL, "Missing or Null Callback" },
	{ PKI_ERR_PARAM_TYPE, "Wrong Paramenter Type" },
	{ PKI_ERR_PKI_FORMAT_UNKNOW, "Unknow PKI Format" },
	{ PKI_ERR_DATA_FORMAT_UNKNOWN, "Unknown Data Format" },
	// PKI MEM Errors
	{ PKI_ERR_MEM_, "" },
	// PKI DIGEST Errors
	{ PKI_ERR_DIGEST_TYPE_UNKNOWN, "Digest Type Unknown" },
	{ PKI_ERR_DIGEST_VALUE_NULL, "Digest Value not available" },
	// URI Related Operations
	{ PKI_ERR_URI_UNSUPPORTED, "Unsupported URI Schema" },
	{ PKI_ERR_URI_GENERAL, "URI General Error" },
	{ PKI_ERR_URI_PARSE, "URI parsing Error" },
	{ PKI_ERR_URI_OPEN, "File Open Error" },
	{ PKI_ERR_URI_CLOSE, "File Close Error" },
	{ PKI_ERR_URI_READ, "File Read Error" },
	{ PKI_ERR_URI_WRITE, "File Write Error" },
	{ PKI_ERR_URI_DNS, "DNS Error" },
	{ PKI_ERR_URI_SSL, "SSL Connection Error" },
	{ PKI_ERR_URI_SSL_TRUST, "Untrusted SSL Connection Error" },
	/* HSM Related */
	{ PKI_ERR_HSM_INIT, "Can not init HSM" },
	{ PKI_ERR_HSM_LOGIN, "Can not login in HSM" },
	{ PKI_ERR_HSM_SET_ALGOR, "Error while chosing algorithm in HSM" },
	{ PKI_ERR_HSM_SET_SLOT, "Error while setting HSM slot to use" },
	{ PKI_ERR_HSM_KEYPAIR_LOAD, "Can not load HSM key" },
	{ PKI_ERR_HSM_KEYPAIR_STORE, "Can not store Key to HSM" },
	{ PKI_ERR_HSM_KEYPAIR_IMPORT, "Can not import Key to HSM" },
	{ PKI_ERR_HSM_KEYPAIR_EXPORT, "Can not export Key from HSM" },
	{ PKI_ERR_HSM_KEYPAIR_GENERATE, "Can create new key material in HSM" },
	{ PKI_ERR_HSM_SCHEME_UNSUPPORTED, "Unsupported crypto algorithm" },
	{ PKI_ERR_HSM_, "" },
	/* Configuration Related */
	{ PKI_ERR_CONFIG_MISSING, "Can not find Configuration file" },
	{ PKI_ERR_CONFIG_LOAD, "Error while loading configuration data" },
	{ PKI_ERR_CONFIG_SAVE, "Error while storing configuration data" },
	{ PKI_ERR_CONFIG_, "" },
	/* Profile Related */
	{ PKI_ERR_X509_PROFILE_, "" },
	/* Token Related */
	{ PKI_ERR_TOKEN_INIT, "Can not initialize Token" },
	{ PKI_ERR_TOKEN_LOGIN, "Error while logging into token" },
	{ PKI_ERR_TOKEN_KEYPAIR_LOAD,  "Can not load Token Key" },
	{ PKI_ERR_TOKEN_CERT_LOAD,  "Can not load Token certificate" },
	{ PKI_ERR_TOKEN_CACERT_LOAD,  "Can not load Token CA certificate" },
	{ PKI_ERR_TOKEN_OTHERCERTS_LOAD,  "Can not load Token other certificates" },
	{ PKI_ERR_TOKEN_TRUSTEDCERTS_LOAD,  "Can not load Token trusted certificates" },
	{ PKI_ERR_TOKEN_SET_CRED, "Can not set Token credentials" },
	{ PKI_ERR_TOKEN_USE_SLOT, "Error while setting Token's Slot" },
	{ PKI_ERR_TOKEN_PROFILE_LOAD, "Can not load Token's Profile" },
	{ PKI_ERR_TOKEN_SET_ALGOR, "Error while setting Token's Algorithm" },
	{ PKI_ERR_TOKEN_GET_ALGOR, "Error while retrieving Token's Algorithm" },
	{ PKI_ERR_TOKEN_,  "" },
	/* Key Operations */
	{ PKI_ERR_X509_KEYPAIR_SIZE, "Key Size Error" },
	{ PKI_ERR_X509_KEYPAIR_SIZE_SHORT, "Key Size smaller than allowed minimum" },
	{ PKI_ERR_X509_KEYPAIR_SIZE_LONG, "Key Size longer than supported maximum" },
	{ PKI_ERR_X509_KEYPAIR_GENERATION, "Can not create new key material" },
	{ PKI_ERR_X509_KEYPAIR_, "" },
	/* Certificate Operations */
	{ PKI_ERR_X509_CERT_CREATE, "Can not create a certificate object" },
	{ PKI_ERR_X509_CERT_CREATE_SUBJECT, "Can not create a suitable certificate Subject" },
	{ PKI_ERR_X509_CERT_CREATE_VERSION, "Can not set certificate version" },
	{ PKI_ERR_X509_CERT_CREATE_NOTBEFORE, "Can not set certificate notBefore field" },
	{ PKI_ERR_X509_CERT_CREATE_NOTAFTER, "Can not set certificate notAfter field" },
	{ PKI_ERR_X509_CERT_CREATE_ISSUER, "Can not set certificate Issuer field" },
	{ PKI_ERR_X509_CERT_CREATE_SERIAL, "Can not set certificate Serial field" },
	{ PKI_ERR_X509_CERT_, "" },
	{ PKI_ERR_X509_CERT_VERIFY_, "" },
	/* Request Operations */
	{ PKI_ERR_X509_REQ_CREATE, "Can not create a request object" },
	{ PKI_ERR_X509_REQ_CREATE_SUBJECT, "Can not create a suitable request Subject" },
	{ PKI_ERR_X509_REQ_CREATE_VERSION, "Can not set request version" },
	{ PKI_ERR_X509_REQ_CREATE_NOTBEFORE, "Can not set request notBefore field" },
	{ PKI_ERR_X509_REQ_CREATE_NOTAFTER, "Can not set request notAfter field" },
	{ PKI_ERR_X509_REQ_CREATE_PUBKEY, "Can not set request PublicKey field" },
	{ PKI_ERR_X509_REQ_CREATE_ALGORITHM, "Can not set request Algorithm" },
	{ PKI_ERR_X509_REQ_, "" },
	/* CRL Errors */
	{ PKI_ERR_X509_CRL, "" },
	// PKI X509 PKCS7 ERRORS
	{ PKI_ERR_X509_PKCS7_TYPE_UNKNOWN, "Unknown PKCS#7 Type" },
	{ PKI_ERR_X509_PKCS7_SIGNER_INFO_NULL, "Missing SignerInfo Structure" },
	{ PKI_ERR_X509_PKCS7_CIPHER, "Cipher not supported" },
	/* OCSP Ops */
	{ PKI_ERR_OCSP_RESP_ENCODE, "Can not encode OCSP response" },
	{ PKI_ERR_OCSP_RESP_DECODE, "Can not decode OCSP response" },
	{ PKI_ERR_OCSP_RESP_SIGN, "Can not sign OCSP response" },
	{ PKI_ERR_OCSP_REQ_ENCODE, "Can not encode OCSP request" },
	{ PKI_ERR_OCSP_REQ_DECODE, "Can not decode OCSP request" },
	{ PKI_ERR_OCSP_REQ_SIGN, "Can not sign OCSP request" },
	{ PKI_ERR_OCSP_NONCE_COPY, "Can not copy NONCE from request" },
	{ PKI_ERR_OCSP_, "" },
	/* PRQP Ops */
	{ PKI_ERR_PRQP_, "" },
	/* PKI Message Operations */
	{ PKI_ERR_MSG_, "" },
	/* Enrollment Protocol Related */
	{ PKI_ERR_ENROLL_, "" },
	/* Signatures Related Errors */
	{ PKI_ERR_SIGN_, "" },
	{ PKI_ERR_SIGN_VERIFY, "" },
	/* Network Related Errors */
	{ PKI_ERR_NET_OPEN, "Can not open socket connection" },
	{ PKI_ERR_NET_, "" },
    /* SSL/TLS Related Errors */
	{ PKI_ERR_NET_SSL_NOT_SUPPORTED , "Not supported by SSL/TLS" },
	{ PKI_ERR_NET_SSL_NO_CIPHER , "No valid cipher (algorithm)" },
	{ PKI_ERR_NET_SSL_VERIFY , "TLS/SSL certificate verify error" },
	{ PKI_ERR_NET_SSL_SET_SOCKET , "Can not set the socket FD for SSL/TLS" },
	{ PKI_ERR_NET_SSL_SET_CIPHER , "Can not set the selected ciphers list" },
	{ PKI_ERR_NET_SSL_SET_FLAGS , "Can not set the selected flags for SSL/TLS" },
	{ PKI_ERR_NET_SSL_INIT , "Can not init the SSL/TLS protocol" },
	{ PKI_ERR_NET_SSL_START , "Can not start the SSL/TLS protocol" },
	{ PKI_ERR_NET_SSL_CONNECT , "Can not connect via SSL/TLS protocol" },
	{ PKI_ERR_NET_SSL_PEER_CERTIFICATE , "Can not process peer certificate" },
	{ PKI_ERR_NET_SSL_ , "" },
	// SCEP Related Errors
	{ PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN , "Unknown Attribute Type" },
	{ PKI_ERR_SCEP_ , "" },
	/* List Boundary */
	{ 0, 0 }
};

static const int __libpki_err_size = sizeof ( __libpki_errors_st ) / sizeof ( PKI_ERR_ST );

#endif /* __LIBPKI_ERR__ */

int __pki_error ( const char *file, int line, int err, const char *info, ... );

// Second Argument is a const char *
#define PKI_ERROR(a,b,args...) __pki_error(__FILE__, __LINE__, a,b, ## args)

#define PKI_ERROR_crypto_get_errno() HSM_get_errno(NULL)
#define PKI_ERROR_crypto_get_errdesc() HSM_get_errdesc(HSM_get_errno(NULL),NULL)

#endif
