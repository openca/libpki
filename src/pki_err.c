/* PKI ERR Management Functions */

#include <libpki/pki.h>

#ifndef _LIBPKI_ERR_H
#include <libpki/pki_err.h>
#endif

// Local Definition for __libpki_errors_st[]
typedef struct pki_err_st {
	PKI_ERR_CODE   code;
	char         * descr;
} PKI_ERR_ST;

/* We define the actual object of strings only if we are compiling
 * the pki_err.c file where __LIBPKI_ERR__ is defined */

const PKI_ERR_ST __libpki_errors_st[] = {
	// General Errors
	{ PKI_ERR_UNKNOWN, "Unknown Error" },
	{ PKI_ERR_GENERAL, "General Error" },
	{ PKI_ERR_NOT_IMPLEMENTED, "Not Implemented" },
	{ PKI_ERR_MEMORY_ALLOC, "Memory Allocation Error" },
	{ PKI_ERR_OBJECT_CREATE, "Object Creation Error" },
	{ PKI_ERR_OBJECT_TYPE_UNKNOWN, "OID Unknown" },
	{ PKI_ERR_POINTER_NULL, "Null Memory Pointer" },
	{ PKI_ERR_PARAM_NULL, "Null Parameter" },
	{ PKI_ERR_PARAM_TYPE, "Wrong Paramenter Type" },
	{ PKI_ERR_CALLBACK_NULL, "Missing or Null Callback" },
	{ PKI_ERR_PKI_FORMAT_UNKNOW, "Unknow PKI Format" },
	{ PKI_ERR_DATA_FORMAT_UNKNOWN, "Unknown Data Format" },
	{ PKI_ERR_DATA_ASN1_ENCODING, "Error while encoding value in ASN1/DER" },
	// PKI MEM Errors
	{ PKI_ERR_MEM_, "" },
	// PKI DIGEST Errors
	{ PKI_ERR_DIGEST_TYPE_UNKNOWN, "Digest Type Unknown" },
	{ PKI_ERR_DIGEST_VALUE_NULL, "Digest Value not available" },
	// PKI ALGOR Errors
	{ PKI_ERR_ALGOR_UNKNOWN, "Unknown Algorithm" },
	{ PKI_ERR_ALGOR_SET, "Cannot set the Algorithm data"},
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
	{ PKI_ERR_HSM_POINTER_NULL, "Missing (null) HSM Pointer" },
	{ PKI_ERR_HSM_PKCS11_LIB_POINTER_NULL, "Missing (null) PKCS#11 Library Pointer" },
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
	{ PKI_ERR_X509_CERT_CREATE_EXT, "Can not create certificate extension" },
	{ PKI_ERR_X509_CERT_VERIFY_, "Cannot verify the certificate" },
	{ PKI_ERR_X509_CERT_, "" },
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
	{ PKI_ERR_X509_CRL_EXTENSION, "Can not set the requested extension in CRL." },
	{ PKI_ERR_X509_CRL_, "" },
	// PKI X509 PKCS7 ERRORS
	{ PKI_ERR_X509_PKCS7_TYPE_UNKNOWN, "Unknown PKCS#7 Type" },
	{ PKI_ERR_X509_PKCS7_SIGNER_INFO_NULL, "Missing SignerInfo Structure" },
	{ PKI_ERR_X509_PKCS7_CIPHER, "Cipher not supported" },
	{ PKI_ERR_X509_PKCS7_, "" },
	// PKI X509 CMS ERRORS
	{ PKI_ERR_X509_CMS_TYPE_UNKNOWN, "Unknown CMS Type" },
	{ PKI_ERR_X509_CMS_SIGNER_INFO_NULL, "Missign SignerInfo Structure" },
	{ PKI_ERR_X509_CMS_CIPHER, "Cipher not supported" },
	{ PKI_ERR_X509_CMS_RECIPIENT_INFO_NULL, "Missing RecipientInfo Structure"},
	{ PKI_ERR_X509_CMS_DATA_INIT, "Cannot initialize data stream" },
	{ PKI_ERR_X509_CMS_DATA_READ, "Cannot read from the data stream" },
	{ PKI_ERR_X509_CMS_DATA_WRITE, "Cannot write to the data stream" },
	{ PKI_ERR_X509_CMS_DATA_FINALIZE, "Cannot finalize the data stream" },
	{ PKI_ERR_X509_CMS_WRONG_TYPE, "CMS is not of the right type" },
	{ PKI_ERR_X509_CMS_SIGNER_ADD, "Cannot add the signer to the CMS." },
	{ PKI_ERR_X509_CMS_SIGNER_GET, "Cannot retrieve the signer from the CMS." },
	{ PKI_ERR_X509_CMS_RECIPIENT_ADD, "Cannot add the recipient to the CMS." },
	{ PKI_ERR_X509_CMS_RECIPIENT_GET, "Cannot retrieve the recipient from the CMS." },
	{ PKI_ERR_X509_CMS_, "" },
	// Generic PKI_X509_AUX_DATA Errors
	{ PKI_ERR_X509_AUX_DATA_MEMORY_FREE_CB_NULL, "Missing AUX Data free callback function" },
	{ PKI_ERR_X509_AUX_DATA_MEMORY_DUP_CB_NULL, "Missing AUX Data duplicate callback function" },
	{ PKI_ERR_X509_AUX_DATA_, "" },
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
	{ PKI_ERR_SIGNATURE_CREATE, "Can not create signature" },
	{ PKI_ERR_SIGNATURE_CREATE_CALLBACK, "Error while creating signature in callback" },
	{ PKI_ERR_SIGNATURE_VERIFY, "Error while verifying the signature" },
	{ PKI_ERR_SIGNATURE_, "" },
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
	{ PKI_ERR_EST_ATTRIBUTE_UNKNOWN , "Unknown Attribute Type for EST" },
	{ PKI_ERR_EST_ , "" },
	// SCEP Related Errors
	{ PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN , "Unknown Attribute Type for SCEP" },
	{ PKI_ERR_SCEP_ , "" },
	// CMP Related Errors
	{ PKI_ERR_CMP_ATTRIBUTE_UNKNOWN , "Unknown Attribute Type for CMP" },
	{ PKI_ERR_CMP_ , "" },
	/* List Boundary */
	{ 0, 0 }
};

static const int __libpki_err_size = sizeof ( __libpki_errors_st ) / sizeof ( PKI_ERR_ST );

/* Pointer to the Error Stack */
PKI_STACK *pki_err_stack = NULL;

/*!
 * \brief Set and logs library errors
 */
#pragma GCC diagnostic ignored "-Wuninitialized"
int __pki_error ( const char *file, int line, int err, const char *info, ... ) {
 
	int i, found;
	PKI_ERR_ST *curr = NULL;
	char fmt[2048];

	va_list ap;

	found = -1;
	for ( i = 0; i < __libpki_err_size ; i++ ) 
	{
		curr = (PKI_ERR_ST *) &__libpki_errors_st[i];

		if ( ( curr ) && ( curr->code == err ) ) 
		{
			found = i;
			if ( !curr->descr ) break;

			if ( info == NULL ) {
				snprintf(fmt, sizeof(fmt), "[%s:%d] %s (%d):", file, line, curr->descr, curr->code);
				PKI_log_err_simple(fmt, NULL);
			} else {
				snprintf(fmt, sizeof(fmt), "[%s:%d] %s (%d): %s", file, line, curr->descr, curr->code, info );
				PKI_log_err_simple( fmt, ap);
			}

			break;
		}
	}

	if ( found < 0 ) err = PKI_ERR_UNKNOWN;

	return ( PKI_ERR );
}

#ifndef LIBPKI_TARGET_OSX
# ifdef HAVE_GCC_PRAGMA_POP
#  pragma GCC diagnostic pop
# endif
#endif
