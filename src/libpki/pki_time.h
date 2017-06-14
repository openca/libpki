/* PKI_TIME */

#ifndef _LIBPKI_TIME_H
#define _LIBPKI_TIME_H

PKI_TIME *PKI_TIME_new( long long offset );

void PKI_TIME_free_void( void *time );
int PKI_TIME_free( PKI_TIME *time );

PKI_TIME * PKI_TIME_set(PKI_TIME *time, time_t new_time);
int PKI_TIME_adj( PKI_TIME *time, long long offset );

PKI_TIME * PKI_TIME_dup(const PKI_TIME *time );

char *PKI_TIME_get_parsed(const PKI_TIME *t );

int PKI_TIME_print (const PKI_TIME *time );
int PKI_TIME_print_fp (const FILE *fp, const PKI_TIME *time );


#endif
