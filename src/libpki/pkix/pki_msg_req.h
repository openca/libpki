/* src/libpki/pki_msg_req.h - General PKI message */

#ifndef _LIBPKI_PKI_MSG_REQ_H
#define _LIBPKI_PKI_MSG_REQ_H

/* --------------------------- Functions -------------------------- */

/*! \brief Returns an empty generic PKI request message */
PKI_MSG_REQ *PKI_MSG_REQ_new_null ( void );

/*! \brief Free a PKI_MSG_REQ data structure */
void PKI_MSG_REQ_free ( PKI_MSG_REQ *msg );

/*! \brief Adds data to the Message body */
int PKI_MSG_REQ_add_data ( PKI_MSG_REQ *msg, unsigned char *data, size_t size );

/*! \brief Replaces data in a PKI_MSG_REQ message */
int PKI_MSG_REQ_replace_data ( PKI_MSG_REQ *msg, unsigned char *data, 
		size_t size );

/*! \brief Clears the data of the Message body */
int PKI_MSG_REQ_clear_data ( PKI_MSG_REQ *msg );

/*! \brief Sets the messaging protocol to be used */
int PKI_MSG_REQ_set_proto ( PKI_MSG_REQ *msg, PKI_MSG_PROTO proto );

/*! \brief Returns the PKI_MSG_PROTO from a PKI_MSG_REQUEST object */
PKI_MSG_PROTO PKI_MSG_REQ_get_proto ( PKI_MSG_REQ *msg );

/*! \brief Sets the Certificate of the CA the request is intended for */
int PKI_MSG_REQ_set_cacert ( PKI_MSG_REQ *msg, PKI_X509_CERT *cacert );

/*! \brief Gets the Certificate of the CA the request is intended for */
PKI_X509_CERT *PKI_MSG_REQ_get_cacert ( PKI_MSG_REQ *msg );

/*! \brief Sets the Subject to be used in the certificate request */
int PKI_MSG_REQ_set_subject ( PKI_MSG_REQ *msg, char *subject );

/*! \brief Gets the Subject to be used in the certificate request */
char * PKI_MSG_REQ_get_subject ( PKI_MSG_REQ *msg );

/*! \brief Sets the requested template */
int PKI_MSG_REQ_set_template ( PKI_MSG_REQ *msg, char *name );

/*! \brief Gets the requested template */
char *PKI_MSG_REQ_get_template ( PKI_MSG_REQ *msg );

/*! \brief Sets the requested Level of Assurance (LOA) */
int PKI_MSG_REQ_set_loa ( PKI_MSG_REQ *msg, char * loa );

/*! \brief Gets the requested Level Of Assurance (LOA) */
char * PKI_MSG_REQ_get_loa ( PKI_MSG_REQ *msg );

/*! \brief Sets the basic action in a PKI_MSG_REQ message */
int PKI_MSG_REQ_set_action ( PKI_MSG_REQ *msg, PKI_MSG_REQ_ACTION action );

/*! \brief Gets the basic action in a PKI_MSG_REQ message */
PKI_MSG_REQ_ACTION PKI_MSG_REQ_get_action ( PKI_MSG_REQ *msg );

/*! \brief Sets the Keypair to be used when generating the request */
int PKI_MSG_REQ_set_keypair ( PKI_MSG_REQ *msg, PKI_X509_KEYPAIR * pkey );

/*! \brief Sets the Signer Certificate */
int PKI_MSG_REQ_set_signer ( PKI_MSG_REQ *msg, PKI_X509_CERT *signer,
		PKI_DIGEST_ALG *md );

/*! \brief Gets the Signer Certificate */
PKI_X509_CERT * PKI_MSG_REQ_get_signer ( PKI_MSG_REQ *msg );

/*! \brief Gets the Keypair to be used when generating the request */
PKI_X509_KEYPAIR * PKI_MSG_REQ_get_keypair ( PKI_MSG_REQ *msg );

/*! \brief Adds a certificate to the list of recipients */
int PKI_MSG_REQ_add_recipient ( PKI_MSG_REQ *msg, PKI_X509_CERT *x );

/*! \brief Clears the list of recipients in a PKI_MSG_REQ */
int PKI_MSG_REQ_clear_recipients( PKI_MSG_REQ *msg );

/*! \brief Gets the list of recipients in a PKI_MSG_REQ */
PKI_X509_CERT_STACK *PKI_MSG_REQ_get_recipients( PKI_MSG_REQ *msg );

/*! \brief Sets the list of recipients in a PKI_MSG_REQ */
int PKI_MSG_REQ_set_recipients ( PKI_MSG_REQ *msg, PKI_X509_CERT_STACK *x_sk);

/*! \brief Gets the encoded version of the message */
void *PKI_MSG_REQ_get_encoded ( PKI_MSG_REQ *msg );

/*! \brief Encodes the message according to the selected PKI_MSG_PROTO */
int PKI_MSG_REQ_encode ( PKI_MSG_REQ *msg, PKI_MSG_PROTO proto );

/*! Builds a new PKI message by using a PKI_TOKEN */
PKI_MSG_REQ *PKI_MSG_REQ_new_tk( PKI_MSG_REQ_ACTION action, char *subject,
	char *template_name, PKI_TOKEN *tk, PKI_DIGEST_ALG *md );

/*! Builds a new PKI message */
PKI_MSG_REQ * PKI_MSG_REQ_new( PKI_MSG_REQ_ACTION action, char * subject, 
		char *template_name, PKI_X509_KEYPAIR *sign_key, 
			PKI_X509_CERT *signer, PKI_X509_CERT *cacert,
			PKI_DIGEST_ALG *md);

/*! Sends a message and retrieves the response */
PKI_MSG_RESP * PKI_MSG_REQ_send ( PKI_MSG_REQ *msg, PKI_TOKEN *tk, 
						char *url );

/*! Returns a SCEP_MSG from the passed PKI_MSG_REQ */
int PKI_MSG_REQ_SCEP_new ( PKI_MSG_REQ *msg );

/* ---------------------------------- SCEP Specific --------------------- */

PKI_MSG_RESP *PKI_MSG_REQ_SCEP_send ( PKI_MSG_REQ *msg, PKI_STACK *sk,
			PKI_TOKEN *tk );

#endif
