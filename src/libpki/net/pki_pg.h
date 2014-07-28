/* libpki/net/pki_pg.h */

#ifndef _LIBPKI_URL_PG_H
#define _LIBPKI_URL_PG_H

#ifdef HAVE_PG

#include <libpq-fe.h>

PGconn *pg_db_connect ( URL *url );
int pg_db_close ( PGconn *sql );

#endif /* HAVE_PG */

char *pg_parse_url_table ( URL * url );
char *pg_parse_url_dbname ( URL *url );

PKI_MEM_STACK *URL_get_data_pg ( char *url_s, ssize_t size );
PKI_MEM_STACK *URL_get_data_pg_url ( URL *url, ssize_t size );

int URL_put_data_pg ( char *url_s, PKI_MEM *data );
int URL_put_data_pg_url ( URL *url, PKI_MEM *data );

#endif /* _LIBPKI_URL_PG_H */
