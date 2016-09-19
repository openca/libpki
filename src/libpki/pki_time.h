/* PKI_TIME */

#ifndef _LIBPKI_TIME_H
#define _LIBPKI_TIME_H

PKI_TIME *PKI_TIME_new( long long offset );

void PKI_TIME_free_void( void *time );
int PKI_TIME_free( PKI_TIME *time );

PKI_TIME * PKI_TIME_set(PKI_TIME *time, time_t new_time);
int PKI_TIME_adj( PKI_TIME *time, long long offset );

PKI_TIME * PKI_TIME_dup ( PKI_TIME *time );

char *PKI_TIME_get_parsed ( PKI_TIME *t );

int PKI_TIME_print ( PKI_TIME *time );
int PKI_TIME_print_fp ( FILE *fp, PKI_TIME *time );


#endif
