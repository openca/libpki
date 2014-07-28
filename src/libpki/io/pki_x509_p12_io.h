/* PKI_X509_PKCS12 I/O management */

#ifndef _LIBPKI_X509_PKCS12_IO_H
#define _LIBPKI_X509_PKCS12_IO_H

#define PKI_X509_PKCS12_STACK		PKI_STACK

#define PKI_X509_PKCS12_BEGIN_ARMOUR	"-----BEGIN PKCS12-----"
#define PKI_X509_PKCS12_END_ARMOUR	"-----END PKCS12-----"
#define PKI_X509_PKCS12_PEM_ARMOUR	"PKCS12"

#define PKI_STACK_X509_PKCS12_new() (PKI_X509_PKCS12_STACK *) \
				PKI_STACK_new(PKI_X509_PKCS12_free_void)
#define PKI_STACK_X509_PKCS12_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_PKCS12_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_PKCS12_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_PKCS12_pop(p) (PKI_X509_PKCS12 *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_PKCS12_get_num(p,n) (PKI_X509_PKCS12 *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_PKCS12_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_PKCS12_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_PKCS12_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* ---------------------------- PKCS12 get operations ------------------ */

PKI_X509_PKCS12 *PKI_X509_PKCS12_get ( char *url_s, PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS12 *PKI_X509_PKCS12_get_url ( URL *url, PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS12 *PKI_X509_PKCS12_get_mem ( PKI_MEM *mem, PKI_CRED *cred );

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get (char *url_s, 
						PKI_CRED *cred, HSM *hsm);
PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm );
PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_mem ( PKI_MEM *mem, 
						PKI_CRED *cred);

/* ---------------------------- PKCS12 put operations ------------------ */

int PKI_X509_PKCS12_put (PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_PKCS12_put_url(PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm);

PKI_MEM *PKI_X509_PKCS12_put_mem ( PKI_X509_PKCS12 *p12, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );

int PKI_X509_PKCS12_STACK_put ( PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, char *url_s, char *mime,
				PKI_CRED *cred, HSM *hsm);

int PKI_X509_PKCS12_STACK_put_url (PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
				PKI_CRED *cred, HSM *hsm );

PKI_MEM *PKI_X509_PKCS12_STACK_put_mem ( PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );

#endif

