/*
 * OpenCA SCEP -- signed attributes handling routines
 * (c) 2003-2009 by Massimiliano Pala and OpenCA Group
 */

#ifndef _LIBPKI_SCEP_SIGNED_ATTRS_H
#define _LIBPKI_SCEP_SIGNED_ATTRS_H

void PKI_X509_SCEP_init(void);

SCEP_ATTRIBUTE_TYPE PKI_X509_SCEP_ATTRIBUTE_get_txt(const char * const txt);

PKI_ID PKI_X509_SCEP_ATTRIBUTE_get_nid(SCEP_ATTRIBUTE_TYPE num);

PKI_OID *PKI_X509_SCEP_MSG_get_oid(SCEP_ATTRIBUTE_TYPE scep_attribute);

int PKI_X509_SCEP_MSG_set_attribute(PKI_X509_SCEP_MSG   * msg,
                                    SCEP_ATTRIBUTE_TYPE   type,
									const unsigned char * const data,
									size_t                size);

int PKI_X509_SCEP_MSG_set_attribute_by_name(PKI_X509_SCEP_MSG   * msg,
                                            const char          * const name,
											const unsigned char * const data,
											size_t                size);

int PKI_X509_SCEP_MSG_set_attribute_int(PKI_X509_SCEP_MSG * msg,
                                        PKI_ID              id,
										int                 val);

PKI_MEM * PKI_X509_SCEP_MSG_get_attr_value(const PKI_X509_SCEP_MSG * const msg,
		                                   SCEP_ATTRIBUTE_TYPE       type);

int PKI_X509_SCEP_MSG_get_attr_value_int(const PKI_X509_SCEP_MSG * const msg,
		                                 SCEP_ATTRIBUTE_TYPE       type);

/* ------------------------ Specific Attributes ------------------------ */

PKI_MEM *PKI_X509_SCEP_MSG_new_trans_id(const PKI_X509_KEYPAIR * key);

int PKI_X509_SCEP_MSG_set_trans_id(PKI_X509_SCEP_MSG * msg,
		                           const PKI_MEM     * mem);

char * PKI_X509_SCEP_MSG_get_trans_id(const PKI_X509_SCEP_MSG * const msg);

/*! \brief Sets the messageType attribute in a SCEP message */

inline int PKI_X509_SCEP_MSG_set_type(PKI_X509_SCEP_MSG * msg,
		                              SCEP_MESSAGE_TYPE   type) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_MESSAGE_TYPE,
											   type);
};

/*! \brief Returns the messageType attribute from a SCEP message */

inline SCEP_MESSAGE_TYPE PKI_X509_SCEP_MSG_get_type(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                    SCEP_ATTRIBUTE_MESSAGE_TYPE);
};

/*! \brief Sets the pkiStatus attribute in a SCEP message */

inline int PKI_X509_SCEP_MSG_set_status(PKI_X509_SCEP_MSG * msg,
		                                SCEP_STATUS         status) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_PKI_STATUS,
											   status );
};


/*! \brief Returns the pkiStatus attribute from a SCEP message */

inline SCEP_STATUS PKI_X509_SCEP_MSG_get_status(const PKI_X509_SCEP_MSG * const msg) {

	return (SCEP_STATUS) PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                                  SCEP_ATTRIBUTE_PKI_STATUS);
};

/*! \brief Sets the failInfo attribute in a SCEP message */

inline int PKI_X509_SCEP_MSG_set_failinfo(PKI_X509_SCEP_MSG * msg,
		                                  int                 fail) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_FAIL_INFO,
											   fail);
};

/*! \brief Returns the failInfo attribute from a SCEP message */

inline SCEP_FAILURE PKI_X509_SCEP_MSG_get_failinfo(const PKI_X509_SCEP_MSG * const msg) {

	return (SCEP_FAILURE) PKI_X509_SCEP_MSG_get_attr_value_int(msg,
				                                               SCEP_ATTRIBUTE_FAIL_INFO);
};

int PKI_X509_SCEP_MSG_set_sender_nonce(PKI_X509_SCEP_MSG * msg,
		                               const PKI_MEM     * const mem);


/*! \brief Returns the senderNonce attribute from a SCEP message */

inline PKI_MEM *PKI_X509_SCEP_MSG_get_sender_nonce(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value(msg,
				                            SCEP_ATTRIBUTE_SENDER_NONCE);
};

int PKI_X509_SCEP_MSG_set_recipient_nonce(PKI_X509_SCEP_MSG * msg,
		                                  const PKI_MEM     * const mem);

/*! \brief Returns the recipientNonce attribute from a SCEP message */

inline PKI_MEM *PKI_X509_SCEP_MSG_get_recipient_nonce(PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value ( msg,
			SCEP_ATTRIBUTE_RECIPIENT_NONCE );
};

/*! \brief Sets the proxyAuthenticator attribute from a SCEP message */

inline int PKI_X509_SCEP_MSG_set_proxy(PKI_X509_SCEP_MSG * msg,
		                               int                 auth) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
			                                   SCEP_ATTRIBUTE_PROXY_AUTH,
											   auth );
};

/*! \brief Returns the proxyAuthenticator attribute from a SCEP message */

inline int PKI_X509_SCEP_MSG_get_proxy(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                    SCEP_ATTRIBUTE_PROXY_AUTH );

};

#endif
