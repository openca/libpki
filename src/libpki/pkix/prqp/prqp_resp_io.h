/* PKI_X509_PRQP_RESP I/O management */

#ifndef _LIBPKI_X509_PRQP_RESP_IO_H
#define _LIBPKI_X509_PRQP_RESP_IO_H

#define PKI_X509_PRQP_RESP_BEGIN_ARMOUR	"-----BEGIN PRQP RESPUEST-----"
#define PKI_X509_PRQP_RESP_END_ARMOUR		"-----END PRQP RESPUEST-----"

/* --------------------- PRQP RESP get (load) functions ------------------- */
PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get ( char *url_s, PKI_DATA_FORMAT format,
				PKI_CRED *cred, HSM *hsm );
PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get_url ( URL *url, PKI_DATA_FORMAT format,
				PKI_CRED *cred, HSM *hsm );
PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get ( char *url_s,
				PKI_DATA_FORMAT format, PKI_CRED *cred,	HSM *hsm );
PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get_url ( URL *url,
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm);

/* -------------------- PRQP RESP put (write) functions ------------------- */
int PKI_X509_PRQP_RESP_put ( PKI_X509_PRQP_RESP *x, PKI_DATA_FORMAT format, 
				char *url_string, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_RESP_put_url ( PKI_X509_PRQP_RESP *x, PKI_DATA_FORMAT format, URL *url,
				char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_RESP_STACK_put (PKI_X509_PRQP_RESP_STACK *sk, PKI_DATA_FORMAT format, 
				char *url_string, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_RESP_STACK_put_url (PKI_X509_PRQP_RESP_STACK *sk, PKI_DATA_FORMAT format, 
				URL *url, char *mime, PKI_CRED *cred, HSM *hsm );

/* ---------------------- PRQP_RESP mem Operations ------------------------ */

PKI_X509_PRQP_RESP * PKI_X509_PRQP_RESP_get_mem ( PKI_MEM *mem, 
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509_PRQP_RESP_STACK *PKI_X509_PRQP_RESP_STACK_get_mem(PKI_MEM *mem,
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm);

PKI_MEM * PKI_X509_PRQP_RESP_put_mem ( PKI_X509_PRQP_RESP *x,
				PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

PKI_MEM *PKI_X509_PRQP_RESP_STACK_put_mem (PKI_X509_PRQP_RESP_STACK *sk,
				PKI_DATA_FORMAT format, PKI_MEM **mem, PKI_CRED *cred, HSM *hsm);

#endif
