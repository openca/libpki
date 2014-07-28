/* Library Initialization */

#ifndef _LIBPKI_INIT_H
#define _LIBPKI_INIT_H

#define PKI_STATUS_NOT_INIT			0
#define PKI_STATUS_INIT					1

int PKI_init_all( void );
void PKI_final_all ( void );

int PKI_get_init_status ( void );

int PKI_is_fips_mode();
int PKI_set_fips_mode(int k);

PKI_STACK * PKI_list_all_tokens ( char *dir );
PKI_STACK * PKI_list_all_tokens_dir ( char * dir, PKI_STACK *list );

PKI_TOKEN_STACK *PKI_get_all_tokens ( char *dir );
PKI_TOKEN_STACK *PKI_get_all_tokens_dir ( char *dir, PKI_TOKEN_STACK *list );
PKI_ID_INFO_STACK * PKI_list_all_id ( void );


#endif
