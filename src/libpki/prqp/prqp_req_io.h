/* PKI_X509_PRQP_REQ I/O management */

#ifndef _LIBPKI_X509_PRQP_REQ_IO_H
#define _LIBPKI_X509_PRQP_REQ_IO_H

#define PKI_X509_PRQP_REQ_BEGIN_ARMOUR	"-----BEGIN PRQP REQUEST-----"
#define PKI_X509_PRQP_REQ_END_ARMOUR		"-----END PRQP REQUEST-----"

/* --------------------- PRQP REQ get (load) functions ------------------- */
PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_get ( char *url_s, 
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_get_url ( URL *url, 
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_PRQP_REQ_STACK *PKI_X509_PRQP_REQ_STACK_get ( char *url_s,
				PKI_DATA_FORMAT format, PKI_CRED *cred,	HSM *hsm );
PKI_X509_PRQP_REQ_STACK *PKI_X509_PRQP_REQ_STACK_get_url ( URL *url,
				PKI_DATA_FORMAT format, PKI_CRED *cred,	HSM *hsm);

/* -------------------- PRQP REQ put (write) functions ------------------- */
int PKI_X509_PRQP_REQ_put ( PKI_X509_PRQP_REQ *x, PKI_DATA_FORMAT format, 
				char *url_string, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_REQ_put_url ( PKI_X509_PRQP_REQ *x, PKI_DATA_FORMAT format, URL *url,
				char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_REQ_STACK_put (PKI_X509_PRQP_REQ_STACK *sk, PKI_DATA_FORMAT format, 
				char *url_string, char *mime, PKI_CRED *cred, HSM *hsm );
int PKI_X509_PRQP_REQ_STACK_put_url (PKI_X509_PRQP_REQ_STACK *sk, PKI_DATA_FORMAT format, 
				URL *url, char *mime, PKI_CRED *cred, HSM *hsm );

/* ---------------------- PRQP_REQ mem Operations ------------------------ */

PKI_X509_PRQP_REQ * PKI_X509_PRQP_REQ_get_mem ( PKI_MEM *mem, 
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

PKI_X509_PRQP_REQ_STACK *PKI_X509_PRQP_REQ_STACK_get_mem(PKI_MEM *mem,
				PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm);

PKI_MEM * PKI_X509_PRQP_REQ_put_mem ( PKI_X509_PRQP_REQ *req,
		PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm );

PKI_MEM *PKI_X509_PRQP_REQ_STACK_put_mem (PKI_X509_PRQP_REQ_STACK *sk, PKI_DATA_FORMAT format, 
					PKI_MEM **mem, PKI_CRED *cred, HSM *hsm);

#endif
