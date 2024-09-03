/* EST msg handling
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#ifndef _LIBPKI_X509_EST_DATA_H
#define _LIBPKI_X509_EST_DATA_H

PKI_X509_EST_DATA * PKI_X509_EST_DATA_new ( void );

void PKI_X509_EST_DATA_free ( PKI_X509_EST_DATA *data );

int PKI_X509_EST_DATA_add_recipient ( PKI_X509_EST_DATA *data,
			PKI_X509_CERT *recipient );

int PKI_X509_EST_DATA_set_recipients ( PKI_X509_EST_DATA *data,
			PKI_X509_CERT_STACK *sk  );

int PKI_X509_EST_DATA_set_x509_obj ( PKI_X509_EST_DATA *data,
			PKI_X509 *obj );

int PKI_X509_EST_DATA_set_ias ( PKI_X509_EST_DATA *data,
			EST_ISSUER_AND_SUBJECT *ias );

int PKI_X509_EST_DATA_set_raw_data ( PKI_X509_EST_DATA *data,
				unsigned char *raw_val, ssize_t size );

#endif
