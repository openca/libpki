/* libpki/net/pki_pg.h */

#ifndef _LIBPKI_URL_PG_H
#define _LIBPKI_URL_PG_H

#ifdef HAVE_PG

#include <libpq-fe.h>

PGconn *pg_db_connect ( const URL *url );
int pg_db_close ( PGconn *sql );

#endif /* HAVE_PG */

char *pg_parse_url_table ( const URL * url );
char *pg_parse_url_dbname ( const URL *url );

PKI_MEM_STACK *URL_get_data_pg ( const char *url_s, ssize_t size );
PKI_MEM_STACK *URL_get_data_pg_url ( const URL *url, ssize_t size );

int URL_put_data_pg ( const char *url_s, const PKI_MEM *data );
int URL_put_data_pg_url ( const URL *url, const PKI_MEM *data );

#endif /* _LIBPKI_URL_PG_H */
