/* PKI_X509_CMS I/O management */

#ifndef _LIBPKI_X509_CMS_IO_H
#define _LIBPKI_X509_CMS_IO_H

#define PKI_X509_CMS_STACK		PKI_STACK

#define PKI_X509_CMS_BEGIN_ARMOUR	"-----BEGIN CMS-----"
#define PKI_X509_CMS_END_ARMOUR	"-----END CMS-----"

#define PKI_STACK_CMS_new() (PKI_STACK *) PKI_STACK_new(PKI_X509_CMS_free_void)
#define PKI_STACK_CMS_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_CMS_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_CMS_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_CMS_pop(p) (PKI_X509_CMS *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_CMS_get_num(p,n) (PKI_X509_CMS *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_CMS_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_CMS_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_CMS_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* ---------------------------- CMS get operations ------------------ */

PKI_X509_CMS *PKI_X509_CMS_get ( char *url_s, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm );
PKI_X509_CMS *PKI_X509_CMS_get_url ( URL *url, PKI_DATA_FORMAT format,
						PKI_CRED *cred, HSM *hsm );
PKI_X509_CMS *PKI_X509_CMS_get_mem ( PKI_MEM *mem, PKI_DATA_FORMAT format,
						PKI_CRED *cred);
PKI_X509_CMS_STACK *PKI_X509_CMS_STACK_get (char *url_s, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm);
PKI_X509_CMS_STACK *PKI_X509_CMS_STACK_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );
PKI_X509_CMS_STACK *PKI_X509_CMS_STACK_get_mem ( PKI_MEM *mem, 
						PKI_DATA_FORMAT format, PKI_CRED *cred);

/* ---------------------------- CMS put operations ------------------ */

int PKI_X509_CMS_put (PKI_X509_CMS *cms, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_CMS_put_url(PKI_X509_CMS *cms, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm);

PKI_MEM *PKI_X509_CMS_put_mem ( PKI_X509_CMS *cms, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );

int PKI_X509_CMS_STACK_put (PKI_X509_CMS_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm);

int PKI_X509_CMS_STACK_put_url (PKI_X509_CMS_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime, 
				PKI_CRED *cred, HSM *hsm );

PKI_MEM * PKI_X509_CMS_STACK_put_mem ( PKI_X509_CMS_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm );

#endif

