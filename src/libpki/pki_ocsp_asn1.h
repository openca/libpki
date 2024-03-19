/* PKI_X509_OCSP_RESP object management */

#ifndef _LIBPKI_X509_OCSP_ASN1_H
#define _LIBPKI_X509_OCSP_ASN1_H
# pragma once

// LibPKI Includes
#include <libpki/pki_mem.h>
#include <libpki/pki_x509_data_st.h>

BEGIN_C_DECLS

						// ======
						// Macros
						// ======

/* Macros for PKI_MEM conversion */
#define PKI_X509_OCSP_RESP_mem_der(a) \
        PKI_MEM_new_func( (void *) a, i2d_OCSP_RESP_bio )
#define PKI_X509_OCSP_RESP_mem_pem(a) \
        PKI_MEM_new_func( (void *) a, PEM_write_bio_OCSP_RESP )

						// =================
						// Defines and Enums
						// =================

typedef enum {
	PKI_OCSP_CERTSTATUS_GOOD 	= V_OCSP_CERTSTATUS_GOOD,
	PKI_OCSP_CERTSTATUS_REVOKED	= V_OCSP_CERTSTATUS_REVOKED,
	PKI_OCSP_CERTSTATUS_UNKNOWN	= V_OCSP_CERTSTATUS_UNKNOWN
} PKI_OCSP_CERTSTATUS;

typedef enum {
	PKI_X509_OCSP_RESP_STATUS_SUCCESSFUL 			= 0,
	PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST		= 1,
	PKI_X509_OCSP_RESP_STATUS_INTERNALERROR 		= 2,
	PKI_X509_OCSP_RESP_STATUS_TRYLATER 			    = 3,
	PKI_X509_OCSP_RESP_STATUS_SIGREQUIRED 			= 5,
	PKI_X509_OCSP_RESP_STATUS_UNAUTHORIZED 			= 6
} PKI_X509_OCSP_RESP_STATUS;

						// ===============
						// Data Structures
						// ===============


//! @brief LibPKI X509 OCSP Response Structure
typedef struct pki_ocsp_resp_st {
	PKI_X509_OCSP_RESP_STATUS status; //! Status of the response
	OCSP_RESPONSE * resp; // ! OCSP Response
	OCSP_BASICRESP * bs; //! OCSP Basic Response
} PKI_X509_OCSP_RESP_VALUE;

//! @brief OCSP Response Backward Compatibility name
#define PKI_OCSP_RESP PKI_X509_OCSP_RESP_VALUE
typedef enum {
	PKI_X509_OCSP_RESPID_NOT_SET       = -1,
	PKI_X509_OCSP_RESPID_TYPE_BY_NAME  =  0,
	PKI_X509_OCSP_RESPID_TYPE_BY_KEYID =  1
} PKI_X509_OCSP_RESPID_TYPE;

// OCSP Structures Forward References
typedef struct ocsp_one_request_st	  PKI_OCSP_REQ_SINGLE;
typedef struct ocsp_request_st 		  PKI_X509_OCSP_REQ_VALUE;
typedef struct ocsp_cert_id_st        LIBPKI_X509_OCSP_CERTID;
typedef struct ocsp_req_info_st       LIBPKI_X509_OCSP_REQ_INFO;
typedef struct ocsp_signature_st      LIBPKI_X509_OCSP_SIGNATURE;
typedef struct ocsp_request_st        LIBPKI_X509_OCSP_REQ;
typedef struct ocsp_responder_id_st   LIBPKI_X509_OCSP_RESPID;
typedef struct ocsp_response_data_st  LIBPKI_X509_OCSP_RESPDATA;
typedef struct ocsp_resp_bytes_st     LIBPKI_X509_OCSP_RESPBYTES;
typedef struct ocsp_response_st       LIBPKI_X509_OCSP_RESPONSE;

typedef struct ocsp_basic_response_st LIBPKI_X509_OCSP_BASICRESP;
typedef OCSP_BASICRESP 				  PKI_X509_OCSP_BASICRESP_VALUE;

typedef PKI_X509 			PKI_X509_OCSP_RESP;
typedef PKI_X509 			PKI_X509_OCSP_REQ;

END_C_DECLS

#endif
