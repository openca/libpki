/*
 * OpenCA SCEP -- signed attributes handling routines
 * (c) 2003-2009 by Massimiliano Pala and OpenCA Group
 */

#ifndef _LIBPKI_SCEP_SIGNED_ATTRS_H
#define _LIBPKI_SCEP_SIGNED_ATTRS_H

void PKI_X509_SCEP_init ( void );

SCEP_ATTRIBUTE_TYPE PKI_X509_SCEP_ATTRIBUTE_get_txt ( char * txt );
PKI_ID PKI_X509_SCEP_ATTRIBUTE_get_nid ( SCEP_ATTRIBUTE_TYPE num );
PKI_OID *PKI_X509_SCEP_MSG_get_oid ( SCEP_ATTRIBUTE_TYPE scep_attribute );

int PKI_X509_SCEP_MSG_set_attribute ( PKI_X509_SCEP_MSG *msg, 
		SCEP_ATTRIBUTE_TYPE type, unsigned char *data, size_t size );
int PKI_X509_SCEP_MSG_set_attribute_by_name ( PKI_X509_SCEP_MSG *msg, 
		char *name, unsigned char *data, size_t size );
int PKI_X509_SCEP_MSG_set_attribute_int ( PKI_X509_SCEP_MSG *msg, 
		PKI_ID id, int val );

PKI_MEM * PKI_X509_SCEP_MSG_get_attr_value ( PKI_X509_SCEP_MSG *msg,
		SCEP_ATTRIBUTE_TYPE type );
int PKI_X509_SCEP_MSG_get_attr_value_int ( PKI_X509_SCEP_MSG *msg,
		SCEP_ATTRIBUTE_TYPE type );

/* ------------------------ Specific Attributes ------------------------ */

PKI_MEM *PKI_X509_SCEP_MSG_new_trans_id ( PKI_X509_KEYPAIR *key );
int PKI_X509_SCEP_MSG_set_trans_id ( PKI_X509_SCEP_MSG *msg, PKI_MEM *mem );
char * PKI_X509_SCEP_MSG_get_trans_id ( PKI_X509_SCEP_MSG * msg );

int PKI_X509_SCEP_MSG_set_type ( PKI_X509_SCEP_MSG *msg, SCEP_MESSAGE_TYPE type );
SCEP_MESSAGE_TYPE PKI_X509_SCEP_MSG_get_type ( PKI_X509_SCEP_MSG *msg );

int PKI_X509_SCEP_MSG_set_status ( PKI_X509_SCEP_MSG *msg, SCEP_STATUS status );
SCEP_STATUS PKI_X509_SCEP_MSG_get_status ( PKI_X509_SCEP_MSG *msg );

int PKI_X509_SCEP_MSG_set_failinfo ( PKI_X509_SCEP_MSG *msg, int fail );
SCEP_FAILURE PKI_X509_SCEP_MSG_get_failinfo ( PKI_X509_SCEP_MSG *msg );

int PKI_X509_SCEP_MSG_set_sender_nonce ( PKI_X509_SCEP_MSG *msg, PKI_MEM *mem );
PKI_MEM *PKI_X509_SCEP_MSG_get_sender_nonce ( PKI_X509_SCEP_MSG *msg );

int PKI_X509_SCEP_MSG_set_recipient_nonce ( PKI_X509_SCEP_MSG *msg, PKI_MEM *mem );
PKI_MEM *PKI_X509_SCEP_MSG_get_recipient_nonce ( PKI_X509_SCEP_MSG *msg );

int PKI_X509_SCEP_MSG_set_proxy ( PKI_X509_SCEP_MSG *msg, int auth );
int PKI_X509_SCEP_MSG_get_proxy ( PKI_X509_SCEP_MSG *msg );

#endif
