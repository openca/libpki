/* SCEP msg handling
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#ifndef _LIBPKI_X509_SCEP_MSG_H
#define _LIBPKI_X509_SCEP_MSG_H

PKI_X509_SCEP_MSG *PKI_X509_SCEP_MSG_new ( SCEP_MESSAGE_TYPE type );
void PKI_X509_SCEP_MSG_free ( PKI_X509_SCEP_MSG *msg );

/* ----------------------------- Signer ------------------------------- */

int PKI_X509_SCEP_MSG_add_signer ( PKI_X509_SCEP_MSG *msg,
		PKI_X509_CERT *signer, PKI_X509_KEYPAIR *key,
			PKI_DIGEST_ALG *md );

int PKI_X509_SCEP_MSG_add_signer_sk ( PKI_X509_SCEP_MSG *msg,
		PKI_TOKEN *tk, PKI_DIGEST_ALG *md );

/* ---------------------------- Encode / Decode ------------------------ */

int PKI_X509_SCEP_MSG_encode ( PKI_X509_SCEP_MSG *msg, 
					PKI_X509_SCEP_DATA *data );

PKI_MEM *PKI_X509_SCEP_MSG_decode ( PKI_X509_SCEP_MSG *msg,
		PKI_X509_KEYPAIR * key, PKI_X509_CERT *x );

/* ---------------------------- SCEP helper Funcs ---------------------- */

PKI_X509_SCEP_MSG * PKI_X509_SCEP_MSG_new_certreq ( PKI_X509_KEYPAIR *key,
		PKI_X509_REQ *req, PKI_X509_CERT *signer,
		PKI_X509_CERT_STACK *recipients, PKI_DIGEST_ALG *md );

PKI_X509 *PKI_X509_SCEP_MSG_get_x509_obj ( PKI_X509_SCEP_MSG *msg,
		PKI_DATATYPE type, PKI_X509_KEYPAIR *key, PKI_X509_CERT *x );

#endif
