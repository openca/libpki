/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001
 *
 * Copyright (c) 2001 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get_http ( URL *url,
		PKI_X509_PRQP_REQ *req, unsigned long max_size ) {

	PKI_MEM *mem = NULL;
	PKI_X509_PRQP_RESP *resp = NULL;
	PKI_MEM_STACK *mem_sk = NULL;

	if(( mem = PKI_X509_PRQP_REQ_put_mem ( req, 
			PKI_DATA_FORMAT_ASN1, NULL, NULL, NULL  )) == NULL ) {
		return NULL;
	}
	
	if ( URL_put_data_url ( url, mem, "application/prqp-request", 
				&mem_sk, 60, 0, NULL ) == PKI_ERR ) {
		PKI_MEM_free ( mem );
		return NULL;
	}

	PKI_MEM_free ( mem );

	if ( PKI_STACK_MEM_elements ( mem_sk ) <= 0 ) {
		PKI_log_debug ("No Responses received!");
	}

	if((mem = PKI_STACK_MEM_pop ( mem_sk )) == NULL ) {
		PKI_log_debug ("STACK Memory Error");
		PKI_STACK_MEM_free_all ( mem_sk );
		return NULL;
	}

	if((resp = PKI_X509_PRQP_RESP_get_mem ( mem, 
					PKI_DATA_FORMAT_UNKNOWN, NULL, NULL )) == NULL ) {
		PKI_log_debug ( "Can not read response from Memory.");
	}

	PKI_STACK_MEM_free_all ( mem_sk );

	return resp;
	
}
