/*
 * OpenCA EST -- signed attributes handling routines
 * (c) 2003-2019 by Massimiliano Pala and OpenCA Group
 */

#ifndef _LIBPKI_EST_SIGNED_ATTRS_H
#define _LIBPKI_EST_SIGNED_ATTRS_H

void PKI_X509_EST_init(void);

EST_ATTRIBUTE_TYPE PKI_X509_EST_ATTRIBUTE_get_txt(const char * const txt);

PKI_ID PKI_X509_EST_ATTRIBUTE_get_nid(EST_ATTRIBUTE_TYPE num);

PKI_OID *PKI_X509_EST_MSG_get_oid(EST_ATTRIBUTE_TYPE est_attribute);

int PKI_X509_EST_MSG_set_attribute(PKI_X509_EST_MSG   * msg,
                                    EST_ATTRIBUTE_TYPE   type,
									const unsigned char * const data,
									size_t                size);

int PKI_X509_EST_MSG_set_attribute_by_name(PKI_X509_EST_MSG   * msg,
                                            const char          * const name,
											const unsigned char * const data,
											size_t                size);

int PKI_X509_EST_MSG_set_attribute_int(PKI_X509_EST_MSG * msg,
                                        PKI_ID              id,
										int                 val);

PKI_MEM * PKI_X509_EST_MSG_get_attr_value(const PKI_X509_EST_MSG * const msg,
		                                   EST_ATTRIBUTE_TYPE       type);

int PKI_X509_EST_MSG_get_attr_value_int(const PKI_X509_EST_MSG * const msg,
		                                 EST_ATTRIBUTE_TYPE       type);

/* ------------------------ Specific Attributes ------------------------ */

PKI_MEM *PKI_X509_EST_MSG_new_trans_id(const PKI_X509_KEYPAIR * key);

int PKI_X509_EST_MSG_set_trans_id(PKI_X509_EST_MSG * msg,
		                           const PKI_MEM     * mem);

char * PKI_X509_EST_MSG_get_trans_id(const PKI_X509_EST_MSG * const msg);


int PKI_X509_EST_MSG_set_sender_nonce(PKI_X509_EST_MSG * msg,
		                               const PKI_MEM     * const mem);


int PKI_X509_EST_MSG_set_recipient_nonce(PKI_X509_EST_MSG * msg,
		                                  const PKI_MEM     * const mem);

/*! \brief Sets the messageType attribute in a EST message */

int PKI_X509_EST_MSG_set_type(PKI_X509_EST_MSG * msg,
		                       EST_MESSAGE_TYPE   type);


/*! \brief Returns the messageType attribute from a EST message */

EST_MESSAGE_TYPE PKI_X509_EST_MSG_get_type(const PKI_X509_EST_MSG * const msg);


/*! \brief Sets the pkiStatus attribute in a EST message */

int PKI_X509_EST_MSG_set_status(PKI_X509_EST_MSG * msg,
		                         EST_STATUS         status);


/*! \brief Returns the pkiStatus attribute from a EST message */

EST_STATUS PKI_X509_EST_MSG_get_status(const PKI_X509_EST_MSG * const msg);


/*! \brief Sets the failInfo attribute in a EST message */

int PKI_X509_EST_MSG_set_failinfo(PKI_X509_EST_MSG * msg,
		                           int                 fail);


/*! \brief Returns the failInfo attribute from a EST message */

EST_FAILURE PKI_X509_EST_MSG_get_failinfo(const PKI_X509_EST_MSG * const msg);


/*! \brief Returns the senderNonce attribute from a EST message */

PKI_MEM *PKI_X509_EST_MSG_get_sender_nonce(const PKI_X509_EST_MSG * const msg);


/*! \brief Returns the recipientNonce attribute from a EST message */

PKI_MEM *PKI_X509_EST_MSG_get_recipient_nonce(PKI_X509_EST_MSG * const msg);


/*! \brief Sets the proxyAuthenticator attribute from a EST message */

int PKI_X509_EST_MSG_set_proxy(PKI_X509_EST_MSG * msg,
		                               int                 auth);


/*! \brief Returns the proxyAuthenticator attribute from a EST message */

int PKI_X509_EST_MSG_get_proxy(const PKI_X509_EST_MSG * const msg);


#endif
