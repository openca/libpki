/* TOKEN Object Management Functions */

#ifndef _LIBPKI_TOKEN_DATA_HEADERS_H
#define _LIBPKI_TOKEN_DATA_HEADERS_H

/* Key data Retrieval */
PKI_MEM *PKI_TOKEN_get_keypair_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );
PKI_MEM *PKI_TOKEN_get_pubkey_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );
PKI_MEM *PKI_TOKEN_get_privkey_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );

/* Certificate data Retrieval */
PKI_MEM *PKI_TOKEN_get_cert_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );

/* Identities data Retrieval */
PKI_MEM *PKI_TOKEN_get_identity_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );

/* CA Certificate Data Retrieval */
PKI_MEM *PKI_TOKEN_get_cacert_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format );

/* Trusted Certs Stack Retrieval */
PKI_MEM_STACK *PKI_TOKEN_get_trustedCerts_data ( PKI_TOKEN *tk,
						PKI_DATA_FORMAT format );

/* Other Certs Stack Retrieval */
PKI_MEM_STACK *PKI_TOKEN_get_otherCerts_data ( PKI_TOKEN *tk,
						PKI_DATA_FORMAT format );

#endif

