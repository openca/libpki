/* PKI_X509_PKCS7 I/O management */

#ifndef _LIBPKI_X509_PKCS7_IO_H
#define _LIBPKI_X509_PKCS7_IO_H

#define PKI_X509_PKCS7_STACK		PKI_STACK

#define PKI_X509_PKCS7_BEGIN_ARMOUR	"-----BEGIN PKCS7-----"
#define PKI_X509_PKCS7_END_ARMOUR	"-----END PKCS7-----"

#define PKI_STACK_PKCS7_new() (PKI_STACK *) PKI_STACK_new(PKI_X509_PKCS7_free_void)
#define PKI_STACK_PKCS7_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_PKCS7_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_PKCS7_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_PKCS7_pop(p) (PKI_X509_PKCS7 *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_PKCS7_get_num(p,n) (PKI_X509_PKCS7 *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_PKCS7_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_PKCS7_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_PKCS7_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* ---------------------------- PKCS7 get operations ------------------ */

PKI_X509_PKCS7 *PKI_X509_PKCS7_get ( char *url_s, PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS7 *PKI_X509_PKCS7_get_url ( URL *url, PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS7 *PKI_X509_PKCS7_get_mem ( PKI_MEM *mem, PKI_CRED *cred);
PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get (char *url_s, 
						PKI_CRED *cred, HSM *hsm);
PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get_mem ( PKI_MEM *mem, 
						PKI_CRED *cred);

/* ---------------------------- PKCS7 put operations ------------------ */

int PKI_X509_PKCS7_put (PKI_X509_PKCS7 *p7, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_PKCS7_put_url(PKI_X509_PKCS7 *p7, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm);

PKI_MEM *PKI_X509_PKCS7_put_mem ( PKI_X509_PKCS7 *p7, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );

int PKI_X509_PKCS7_STACK_put (PKI_X509_PKCS7_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_PKCS7_STACK_put_url (PKI_X509_PKCS7_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime, 
				PKI_CRED *cred, HSM *hsm );

PKI_MEM * PKI_X509_PKCS7_STACK_put_mem ( PKI_X509_PKCS7_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );


#endif

