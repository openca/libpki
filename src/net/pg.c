/* src/net/pg.c */
/*
 * PostgreSQL URL Interface
 * Copyright (c) 2007 by Massimiliano Pala and OpenCA Project
 * OpenCA Licensed Code
 */
 
 
#include <libpki/pki.h>

char *pg_parse_url_query ( URL * url ) {

	char * ret = NULL;
	char * table = NULL;
	char * tmp_s = NULL;
	char * tmp_s2 = NULL;
	int where = 0;
	int add_and = 0;

	char col[1024];
	char val[1024];
	char tmp[1024];

	PKI_MEM *buf = NULL;

	if( !url || !url->path ) return( NULL );

	tmp_s = url->path;

	while((tmp_s2 = strchr(tmp_s, '/')) != NULL ) {
		tmp_s2++;
		tmp_s = tmp_s2;
	}

	if((table = parse_url_table ( url )) == NULL) {
		return (NULL);
	}

	if((buf = PKI_MEM_new_null()) == NULL ) {
		return ( NULL );
	}

	snprintf( tmp, sizeof( tmp ), "SELECT %s from %s ", url->attrs, table );
	PKI_Free (table);

	PKI_MEM_add( buf, tmp, strlen( tmp ));

	where = 0;
	while( sscanf(tmp_s, "(%[^)=]=%[^)])", col, val) > 1 ) {
		if( where == 0 ) {
			/* Let's add the WHERE clause */
			PKI_MEM_add(buf, "WHERE ", 6);
			where = 1;
		}
		/* The tmp_s should point to the next token */
		tmp_s += strlen(col) + strlen(val) + 3;

		/* Control if we need to add the AND in the SQL statement */
		if( add_and == 1 ) {
			PKI_MEM_add( buf, " AND ", 5);
		}

		PKI_MEM_add( buf, col, strlen( col ));
		PKI_MEM_add( buf, "='", 2);
		PKI_MEM_add( buf, val, strlen( val ));
		PKI_MEM_add( buf, "' ", 2);

		/* This triggers the adding of AND on the next iteration */
		add_and = 1;
	}

	if( (ret = PKI_Malloc (buf->size+1)) == NULL ) {
		PKI_MEM_free ( buf );
		return( NULL );
	}
	memcpy( ret, buf->data, buf->size );

	PKI_MEM_free ( buf );
	return( ret );
}

char *pg_parse_url_put_query ( URL * url, PKI_MEM *data ) {

	char * ret = NULL;
	char * table = NULL;
	char * tmp_s = NULL;
	char * tmp_s2 = NULL;

	int where = 0;
	int add_and = 0;

	char col[1024];
	char val[1024];
	char tmp[1024];

	// char buf[BUFF_MAX_SIZE];

	PKI_MEM *buf = NULL;

	if( !url || !url->path ) return( NULL );

	tmp_s = url->path;

	while((tmp_s2 = strchr(tmp_s, '/')) != NULL ) {
		tmp_s2++;
		tmp_s = tmp_s2;
	}

	if((table = parse_url_table ( url )) == NULL) {
		return (NULL);
	}

	if((buf = PKI_MEM_new_null()) == NULL ) {
		return ( NULL );
	}

	sprintf( tmp, "INSERT INTO %s (%s) VALUES ('", table, url->attrs );
	PKI_MEM_add( buf, tmp, strlen( tmp ));
	PKI_MEM_add( buf, (char * ) data->data, data->size );
	PKI_MEM_add( buf, "') ", 3);

	/*
	base=strlen(buf);
	for( i=0; i < data->size; i++ ) {
		sprintf(buf + base + i, "%c", data->data[i]);
	}
	sprintf(buf+base+i,"') ");
	*/

	where = 0;
	while( (sscanf(tmp_s, "(%[^)=]=\"%[^)\"]\")", col, val) > 1) ||
			(sscanf(tmp_s, "(%[^)=]=%[^)])", col, val) > 1)) {
		if( where == 0 ) {
			/* It is actually an update, let's update! */
			snprintf( tmp, sizeof( tmp ),
				"UPDATE %s SET %s='", table, url->attrs);
			if( buf ) PKI_MEM_free ( buf );

			buf = PKI_MEM_new_null();
			PKI_MEM_add( buf, tmp, strlen( tmp ));
			PKI_MEM_add( buf, (char *)data->data, data->size );
			PKI_MEM_add( buf, "' WHERE ", 8);

			/*
			base=strlen(buf);
			for( i=0; i < data->size; i++ ) {
				sprintf(buf + base + i, "%c", data->data[i]);
			}
			sprintf(buf+base+i,"' WHERE ");
			*/

			/* Let's add the WHERE clause */
			where = 1;
		}
		/* The tmp_s should point to the next token */
		tmp_s += strlen(col) + strlen(val) + 3;

		/* Control if we need to add the AND in the SQL statement */
		if( add_and == 1 ) {
			PKI_MEM_add( buf, " AND ", 5);
		}

		PKI_MEM_add( buf, col, strlen( col ));
		PKI_MEM_add( buf, "='", 2);
		PKI_MEM_add( buf, val, strlen( val ));
		PKI_MEM_add( buf, "' ", 2 );

		/*
		strncat( buf, col, BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, "='", BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, val, BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, "'", BUFF_MAX_SIZE - strlen(buf) );
		*/

		/* This triggers the adding of AND on the next iteration */
		add_and = 1;
	}

	PKI_Free (table);

	if( (ret = PKI_Malloc(buf->size) + 1) == NULL ) {
		if( buf ) PKI_MEM_free ( buf );
		return( NULL );
	}
	memcpy( ret, buf->data, buf->size );

	PKI_MEM_free ( buf );

	return( ret );
}


char *pg_parse_url_table ( URL * url ) {
	char *tmp_s = NULL;
	char *tmp_s2 = NULL;
	char *ret = NULL;
	char *dbname = NULL;

	size_t size = 0;

	if(!url || !url->path ) return (NULL);

	if((dbname = pg_parse_url_dbname( url )) == NULL ) {
		return (NULL);
	}

	tmp_s = url->path + strlen(dbname) + 1;	
	PKI_Free( dbname );

	if((tmp_s2 = strchr( tmp_s, '/' )) == NULL ) {
		size = strlen( tmp_s );
	} else {
		size = (size_t) (tmp_s2 - tmp_s);
	}

	if((ret = PKI_Malloc ( size + 1 )) == NULL ) {
		return(NULL);
	}

	memcpy(ret, tmp_s, size );
	ret[size] = '\x0';

	return( ret );
}

char *pg_parse_url_dbname ( URL *url ) {

	char *tmp_s = NULL;
	char *ret = NULL;
	size_t size = 0;

	if( !url || !url->path ) return (NULL);

	if((tmp_s = strchr( url->path, '/')) == NULL ) {
		return (NULL);
	}

	size = (size_t) (tmp_s - url->path);
	if((ret = PKI_Malloc ( size + 1 )) == NULL ) {
		return(NULL);
	}

	memcpy(ret, url->path, size );
	ret[size] = '\x0';

	return( ret );
}

#ifdef HAVE_PG

PGconn *pg_db_connect ( URL *url ) {

        PGconn *sql = NULL;
	char * dbname = NULL;

	dbname = pg_parse_url_dbname ( url );

	sql = PQsetdbLogin( url->addr, NULL, NULL, NULL,
       			                 dbname, url->usr, url->pwd );

	if(PQstatus(sql) == CONNECTION_BAD) {
		if( dbname ) PKI_Free (dbname);
		pg_db_close( sql );
	}

	if( dbname ) PKI_Free (dbname);

	return( sql );
}

int pg_db_close ( PGconn *sql ) {

        if( !sql ) return 0;

        PQfinish( sql );

        return (PKI_OK);
}


#endif

PKI_MEM_STACK *URL_get_data_pg ( char *url_s, ssize_t size ) {
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if(((url = URL_new( url_s )) == NULL) ||
		url->proto != URI_PROTO_PG ) {
		return (NULL);
	}

	return ( URL_get_data_pg_url( url, size ));
}

PKI_MEM_STACK *URL_get_data_pg_url ( URL *url, ssize_t size ) {

#ifdef HAVE_PG
	PGconn *sql;
        PGresult *res;

	int n_rows = 0;
	int i = 0;
	int n_fields = 0;

	PKI_MEM *tmp_mem = NULL;
	PKI_MEM_STACK *sk = NULL;

	char * query = NULL;

	if( !url ) return (NULL);

	query = pg_parse_url_query( url );

	if((sql = pg_db_connect ( url )) == NULL ) {
		PKI_Free( query );
		return(NULL);
	}

	/* Get the Data */
	if(((res = PQexec( sql, query )) == NULL) || 
			(PQresultStatus( res ) != PGRES_COMMAND_OK )) {

		PQclear( res );
		PKI_Free( query );
                return(NULL);
        }

        if( ((n_rows = PQntuples(res)) < 1 ) || 
			((sk = PKI_STACK_MEM_new()) == NULL)) {
		PKI_Free( query );
		return(NULL);
	}

	/* Count the number of fields retrieved */
	n_fields = PQnfields( res );

	for(i = 0; i < n_rows; i++ ) {

		if( n_fields > 0 ) {
			tmp_mem = PKI_MEM_new_null();
			if( (size == 0 ) || 
				    (( size > 0 ) && 
					( PQgetlength(res, i, 0) < size)) ) {

				PKI_MEM_add(tmp_mem,
					PQgetvalue ( res, i, 0 ),
					(size_t) PQgetlength( res, i, 0 )
				);

				/* For now, let's only deal with one 
				   field at the time */
				PKI_STACK_push( sk, tmp_mem );
			}
                }

        }

	PQclear( res );

	PKI_Free (query);
	pg_db_close ( sql );

	return ( sk );

#else
	return ( NULL );
#endif
}

int URL_put_data_pg ( char *url_s, PKI_MEM *data ) {

	URL *url = NULL;
	int ret = 0;

	if( !url_s ) return (PKI_ERR);

	if(((url = URL_new( url_s )) == NULL) ||
		url->proto != URI_PROTO_PG ) {
		return (PKI_ERR);
	}

	ret = URL_put_data_pg_url( url, data );
	if( url ) URL_free ( url );

	return ( ret );
}

int URL_put_data_pg_url ( URL *url, PKI_MEM *data ) {

#ifdef HAVE_PG
	PGconn * sql = NULL;
        PGresult *res = NULL;

	int ret = PKI_OK;
	char * query = NULL;

	if( !url ) return (PKI_ERR);

	if((query = pg_parse_url_put_query( url, data )) == NULL ) {
		return( PKI_ERR );
	}

	if((sql = pg_db_connect ( url )) == NULL ) {
		PKI_Free( query );
		return(PKI_ERR);
	}

	/* Get the Data */
	if(((res = PQexec( sql, query )) == NULL) || 
			(PQresultStatus( res ) != PGRES_COMMAND_OK )) {

		// PQclear( res );
		ret = PKI_ERR;
        }

	if( res ) PQclear( res );
	if( query ) PKI_Free (query);

	return ( ret );

#else
	return ( PKI_ERR );
#endif
}
