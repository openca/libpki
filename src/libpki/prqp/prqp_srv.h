/* 
 * PKI Resource Query Protocol Message implementation
 * (c) 2006-2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 */
                                                                                
#ifndef _LIBPKI_X509_PRQP_SRV_H
#define _LIBPKI_X509_PRQP_SRV_H

PKI_STACK * PKI_get_ca_resources(PKI_X509_CERT *caCert, 
			PKI_X509_CERT *caIssuerCert, PKI_X509_CERT *issuedCert,
			PKI_STACK *sk_services, char *url_s );

PKI_STACK * PKI_get_ca_service_sk( PKI_X509_CERT *caCert, 
					char *srv, char *url_s );
PKI_STACK * PKI_get_cert_service_sk( PKI_X509_CERT *cert, 
					char *srv, char *url_s );
char * PKI_get_ca_service( PKI_X509_CERT *caCert, char *srv, char *url_s );

PKI_X509_PRQP_RESP * PKI_DISCOVER_get_resp ( PKI_X509_PRQP_REQ *p, char *url_s );
PKI_X509_PRQP_RESP * PKI_DISCOVER_get_resp_url ( PKI_X509_PRQP_REQ *p, URL *url );

#endif


