/* src/libpki/pki_msg.h - General PKI message */

#ifndef _LIBPKI_PKI_MSG_H
#define _LIBPKI_PKI_MSG_H

/* --------------------------- Enums -------------------------- */

typedef enum {
	PKI_MSG_PROTO_UNKNOWN = 0,
	PKI_MSG_PROTO_SCEP,
	PKI_MSG_PROTO_CMC,
	PKI_MSG_PROTO_XKMS
} PKI_MSG_PROTO;

typedef enum {
	PKI_MSG_REQ_ACTION_UNKNOWN = 0,
	PKI_MSG_REQ_ACTION_CERTREQ,
	PKI_MSG_REQ_ACTION_CHECK_CERTREQ,
	PKI_MSG_REQ_ACTION_GETCERT,
	PKI_MSG_REQ_ACTION_GETCACERT,
	PKI_MSG_REQ_ACTION_GETCRL
} PKI_MSG_REQ_ACTION;

typedef enum {
	PKI_MSG_RESP_ACTION_UNKNOWN = 0,
	PKI_MSG_RESP_ACTION_CERTREQ,
	PKI_MSG_RESP_ACTION_CHECK_CERTREQ,
	PKI_MSG_RESP_ACTION_GETCERT,
	PKI_MSG_RESP_ACTION_GETCACERT,
	PKI_MSG_RESP_ACTION_GETCRL
} PKI_MSG_RESP_ACTION;

typedef enum {
	PKI_MSG_STATUS_UNKNOWN = 0,
	PKI_MSG_STATUS_OK,
	PKI_MSG_STATUS_FAIL,
	PKI_MSG_STATUS_PENDING
} PKI_MSG_STATUS;

/* ------------------------ Data Structures ------------------- */

typedef struct pki_req_msg_st {
	PKI_MSG_PROTO proto;
	PKI_MSG_REQ_ACTION action;
	PKI_X509_CERT *cacert;
	PKI_X509_CERT_STACK *recipients;
	PKI_X509_KEYPAIR *sign_key;
	PKI_X509_CERT *sign_cert;
	PKI_DIGEST_ALG *sign_md;
	PKI_CRED *cred;
	char * subject;
	char * template_name;
	char * loa;
	PKI_MEM * data;
	PKI_X509 *msg_data;
} PKI_MSG_REQ;

typedef struct pki_resp_msg_st {
	PKI_MSG_PROTO proto;
	PKI_MSG_STATUS status;
	PKI_MSG_RESP_ACTION action;
	PKI_X509_CERT *cacert;
	PKI_X509_KEYPAIR *sign_key;
	PKI_X509_CERT *sign_cert;
	PKI_X509_CERT_STACK *recipients;
	PKI_X509_CERT *issued_cert;
	PKI_MEM *data;
	PKI_X509 *msg_data;
} PKI_MSG_RESP;

#endif
