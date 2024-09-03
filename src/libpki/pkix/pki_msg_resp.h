/* src/libpki/pki_msg_resp.h - General PKI message (responses) */

#ifndef _LIBPKI_PKI_MSG_RESP_H
#define _LIBPKI_PKI_MSG_RESP_H

/* --------------------------- Functions -------------------------- */

/*! \brief Returns an empty generic PKI response message */
PKI_MSG_RESP *PKI_MSG_RESP_new_null ( void );

/*! \brief Free a PKI_MSG_RESP data structure */
void PKI_MSG_RESP_free ( PKI_MSG_RESP *msg );

/*! \brief Adds data to the Message body */
int PKI_MSG_RESP_add_data (PKI_MSG_RESP *msg, unsigned char *data, size_t size);

/*! \brief Replaces data in a PKI_MSG_RESP message */
int PKI_MSG_RESP_replace_data ( PKI_MSG_RESP *msg, unsigned char *data,
							size_t size );

/*! \brief Clears the data of the Message body */
int PKI_MSG_RESP_clear_data ( PKI_MSG_RESP *msg );

/*! \brief Sets the messaging protocol to be used */
int PKI_MSG_RESP_set_proto ( PKI_MSG_RESP *msg, PKI_MSG_PROTO proto );

/*! \brief Returns the PKI_MSG_PROTO from a PKI_MSG_RESP object */
PKI_MSG_PROTO PKI_MSG_RESP_get_proto ( PKI_MSG_RESP *msg );

/*! \brief Gets the certificate from the Response */
PKI_X509_CERT *PKI_MSG_RESP_get_issued_cert ( PKI_MSG_RESP *msg );

/*! \brief Sets the certificate from the Response */
int PKI_MSG_RESP_set_issued_cert ( PKI_MSG_RESP *msg, PKI_X509_CERT *x );

/*! \brief Gets the CA certificate from the Response */
PKI_X509_CERT *PKI_MSG_RESP_get_cacert ( PKI_MSG_RESP *msg );

/*! \brief Sets the CA certificate in the Response */
int PKI_MSG_RESP_set_cacert ( PKI_MSG_RESP *msg, PKI_X509_CERT *x );

/*! \brief Sets the basic action in a PKI_MSG_RESP message */
int PKI_MSG_RESP_set_status ( PKI_MSG_RESP *msg, PKI_MSG_STATUS status );

/*! \brief Gets the basic action in a PKI_MSG_RESP message */
PKI_MSG_STATUS PKI_MSG_RESP_get_status ( PKI_MSG_RESP *msg );

/*! \brief Sets the basic action in a PKI_MSG_RESP message */
int PKI_MSG_RESP_set_action ( PKI_MSG_RESP *msg, PKI_MSG_RESP_ACTION action );

/*! \brief Gets the basic action in a PKI_MSG_RESP message */
PKI_MSG_RESP_ACTION PKI_MSG_RESP_get_action ( PKI_MSG_RESP *msg );

/*! \brief Sets the Keypair to be used when generating the response */
int PKI_MSG_RESP_set_keypair ( PKI_MSG_RESP *msg, PKI_X509_KEYPAIR * pkey );

/*! \brief Gets the Keypair to be used when generating the response */
PKI_X509_KEYPAIR * PKI_MSG_RESP_get_keypair ( PKI_MSG_RESP *msg );

/*! \brief Sets the Signer Certificate */
int PKI_MSG_RESP_set_signer ( PKI_MSG_RESP *msg, PKI_X509_CERT *signer );

/*! \brief Gets the Signer Certificate */
PKI_X509_CERT * PKI_MSG_RESP_get_signer ( PKI_MSG_RESP *msg );

/*! \brief Adds a certificate to the list of recipients */
int PKI_MSG_RESP_add_recipient ( PKI_MSG_RESP *msg, PKI_X509_CERT *x );

/*! \brief Clears the list of recipients in a PKI_MSG_RESP */
int PKI_MSG_RESP_clear_recipients( PKI_MSG_RESP *msg );

/*! \brief Gets the list of recipients in a PKI_MSG_RESP */
PKI_X509_CERT_STACK *PKI_MSG_RESP_get_recipients( PKI_MSG_RESP *msg );

/*! \brief Sets the list of recipients in a PKI_MSG_RESP */
int PKI_MSG_RESP_set_recipients( PKI_MSG_RESP *msg, PKI_X509_CERT_STACK *x_sk);

/*! \brief Gets the encoded version of the Response message */
void *PKI_MSG_RESP_get_encoded ( PKI_MSG_RESP *msg );

/*! \brief Encodes the message according to the selected PKI_MSG_PROTO */
void *PKI_MSG_RESP_encode ( PKI_MSG_RESP *msg, PKI_MSG_PROTO proto );

/*! Builds a new PKI Response message by using a PKI_TOKEN */
PKI_MSG_RESP *PKI_MSG_RESP_new_tk( PKI_MSG_RESP_ACTION action, 
		PKI_MSG_STATUS status, PKI_TOKEN *tk );

/*! \brief Builds a new message */
PKI_MSG_RESP * PKI_MSG_RESP_new( PKI_MSG_RESP_ACTION action, 
		PKI_MSG_STATUS status, PKI_X509_KEYPAIR *sign_key, 
			PKI_X509_CERT *signer, PKI_X509_CERT *cacert );

/*! Returns a SCEP_MSG from the passed PKI_MSG_RESP */
PKI_X509_SCEP_MSG *PKI_MSG_RESP_SCEP_new ( PKI_MSG_RESP *msg );

#endif
