/* libpki/net/mysql.h */

#ifndef _LIBPKI_URL_MYSQL_H
#define _LIBPKI_URL_MYSQL_H

#ifdef HAVE_MYSQL

#include <mysql.h>

MYSQL *db_connect ( const URL *url );
int db_close ( MYSQL *sql );

#endif /* HAVE_MYSQL */

char *parse_url_table ( const URL * url );
char *parse_url_dbname ( const URL *url );

PKI_MEM_STACK *URL_get_data_mysql ( const char *url_s, ssize_t size );
PKI_MEM_STACK *URL_get_data_mysql_url ( const URL *url, ssize_t size );

int URL_put_data_mysql ( const char *url_s, const PKI_MEM *data );
int URL_put_data_mysql_url ( const URL *url, const PKI_MEM *data );

#endif /* _LIBPKI_URL_MYSQL_H */
