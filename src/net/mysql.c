/* src/net/mysql.c */
/*
 * MySQL URL Interface
 * Copyright (c) 2007 by Massimiliano Pala and OpenCA Project
 * OpenCA Licensed Code
 */
 
 
#include <libpki/pki.h>

char *parse_url_query ( URL * url ) {

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

/*
	fprintf(stderr, "DEBUG:::PKI_MEM_BUF => ");
	for ( i=0; i< buf->size; i++ ) {
		fprintf( stderr, "%c", buf->data[i]);
	} fprintf( stderr, "\n");
*/

		/*
		strncat( buf, col, BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, "='", BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, val, BUFF_MAX_SIZE - strlen(buf) );
		strncat( buf, "'", BUFF_MAX_SIZE - strlen(buf) );
		*/

		/* This triggers the adding of AND on the next iteration */
		add_and = 1;
	}

	if( (ret = PKI_Malloc (buf->size+1)) == NULL ) {
		PKI_MEM_free ( buf );
		return( NULL );
	}

	memcpy( ret, buf->data, buf->size );
	// fprintf( stderr, "DEBUG:::QUERY => %s\n\n", ret );

	/*
	strncpy( ret, buf, strlen( buf ));
	*/

	PKI_MEM_free ( buf );
	return( ret );
}

char *parse_url_put_query ( URL * url, PKI_MEM *data ) {

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
	PKI_MEM_add( buf, (char *) data->data, data->size );
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
			PKI_MEM_add( buf, (char *) data->data, data->size );
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

char *parse_url_table ( URL * url ) {
	char *tmp_s = NULL;
	char *tmp_s2 = NULL;
	char *ret = NULL;
	char *dbname = NULL;

	size_t size = 0;

	if(!url || !url->path ) return (NULL);

	if((dbname = parse_url_dbname( url )) == NULL ) {
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

char *parse_url_dbname ( URL *url ) {

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

#ifdef HAVE_MYSQL

MYSQL *db_connect ( URL *url ) {

	MYSQL *sql = NULL;
	char * table = NULL;
	char * dbname = NULL;

	if( (sql = mysql_init( NULL )) == NULL ) {
		return NULL;
	}

	dbname = parse_url_dbname ( url );
	table = parse_url_table ( url );

	/* The old mysql_connect is no more supported, it seems! */
	/* mysql_connect( sql, url->addr, url->usr, url->pwd ); */
	if((mysql_real_connect(sql, url->addr, url->usr, url->pwd,
			dbname, (unsigned int) url->port, NULL, 0 )) == NULL ) {
		if( dbname ) PKI_Free ( dbname );
		db_close( sql );
		return( NULL );
	}

	if( dbname ) PKI_Free (dbname);
	if( table ) PKI_Free (table);

	return( sql );

}

int db_close ( MYSQL *sql ) {

	if( !sql ) return (PKI_ERR);

	mysql_close( sql );

	return (PKI_OK);
}


#endif

PKI_MEM_STACK *URL_get_data_mysql ( char *url_s, ssize_t size )
{
	PKI_MEM_STACK *ret = NULL;
	URL *url = NULL;

	if( !url_s ) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	if ((url = URL_new(url_s)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (url->proto != URI_PROTO_MYSQL)
	{
		PKI_log_debug("Wrong protocol for MySQL queries (%d)", URI_PROTO_MYSQL);
		URL_free(url);

		return NULL;
	}

	// Get the results
	ret = URL_get_data_mysql_url( url, size );
	
	// Free the URL
	URL_free(url);

	// Return the results
	return ret;
}

PKI_MEM_STACK *URL_get_data_mysql_url ( URL *url, ssize_t size ) {

#ifdef HAVE_MYSQL
	MYSQL_ROW row;
	MYSQL * sql = NULL;
	MYSQL_FIELD *fields = NULL;
	MYSQL_RES *res = NULL;

	unsigned long *lengths = NULL;
	long long n_rows = 0;
	int n_fields = 0;

	PKI_MEM *tmp_mem = NULL;
	PKI_MEM_STACK *sk = NULL;

	char * query = NULL;

	if( !url ) return (NULL);

	if((sql = db_connect ( url )) == NULL )
	{
		return NULL;
	}

	if ((query = parse_url_query(url)) == NULL)
	{
		PKI_log_err("Can not parse URL query");
		goto end;
	}
	else mysql_query(sql, query);

	/* Get the Data */
	if((res = mysql_store_result( sql )) == NULL)
	{
		PKI_log_err("Can not retrieve SQL data");
		goto end;
	}

	if( ((n_rows = (long long) mysql_num_rows( res )) < 1 ) || 
			((sk = PKI_STACK_MEM_new()) == NULL))
	{
		PKI_log_err("No returned rows found");
		goto end;
	}

	while((row = mysql_fetch_row(res)) != NULL )
	{
		/* Count the number of fields retrieved */
		n_fields = (int) mysql_num_fields( res );
		lengths = mysql_fetch_lengths( res );
		fields = mysql_fetch_fields( res );
		if (!fields)
		{
			PKI_ERROR(PKI_ERR_GENERAL, "can not fetch query fields");
			break;
		}

		if (n_fields > 0)
		{
			tmp_mem = PKI_MEM_new_null();
			if (size == 0 || (( size > 0 ) && ( lengths[0] < size)))
			{
				PKI_MEM_add(tmp_mem,row[0],lengths[0]);

				/* For now, let's only deal with one 
				   field at the time */
				PKI_STACK_push( sk, tmp_mem );
			}
		}
	}

end:

	if (query) PKI_Free (query);
	db_close ( sql );

	return ( sk );

#else
	return ( NULL );
#endif
}

int URL_put_data_mysql ( char *url_s, PKI_MEM *data ) {

	int ret = 0;
	URL *url = NULL;

	// Parameter checking
	if( !url_s ) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (PKI_ERR);
	}

	// Allocates a new URL structure
	if ((url = URL_new(url_s)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	// Checks the protocol to by MySQL
	if (url->proto != URI_PROTO_MYSQL)
	{
		PKI_log_debug("Wrong protocol for MySQL queries (%d)", URI_PROTO_MYSQL);
		URL_free(url);

		return PKI_ERR;
	}

	// Gets the response
	ret = URL_put_data_mysql_url( url, data );

	// Frees the URL data structure
	URL_free (url);

	return ret;
}

int URL_put_data_mysql_url ( URL *url, PKI_MEM *data ) {

#ifdef HAVE_MYSQL
	MYSQL * sql = NULL;

	char * query = NULL;

	if( !url ) return (PKI_ERR);

	if((query = parse_url_put_query( url, data )) == NULL ) {
		return( PKI_ERR );
	}

	if((sql = db_connect ( url )) == NULL ) {
		PKI_Free( query );
		return(PKI_ERR);
	}

	if(mysql_query(sql, query ) != 0 ) {
		PKI_Free ( query );
		db_close( sql );

		return( PKI_ERR );
	}

	PKI_Free (query);
	db_close ( sql );

	return ( PKI_OK );

#else
	return ( PKI_ERR );
#endif
}
