/*
 * ====================================================================
 *
 * LibPKI - Easy-to-use PKI library
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001-2013
 *
 * Copyright (c) 2001-2013 by Massimiliano Pala and OpenCA Labs.
 * All rights reserved.
 *
 * ====================================================================
 *
 */

#include <libpki/pki.h>

/* Functions */

char * get_env_string(const char *str) {

	char * ret = NULL;
	char * p1 = NULL;
	char * p2 = NULL;
	char * p3 = NULL;

	size_t len = 0;

	PKI_MEM *mem = NULL;

	if( !str ) return ( NULL );

	if((mem = PKI_MEM_new_null()) == NULL ) {
		return ( NULL );
	}

	p1 = (char *) str;
	while((p1) && (p2 = strchr(p1, '$'))) {

		char var_name[1024];
		char *var_value = NULL;
		size_t var_len = 0;

		PKI_MEM_add ( mem, p1, (size_t) (p2-p1) );
		p3 = p2+1;

		while( isalnum(*p3) || *p3 == '_' ) { p3++; };

		var_len = (size_t) (p3-p2-1);
		memcpy(var_name, p2+1, var_len );
		var_name[var_len] = '\x0';

		/* Grabs and attaches the new (ENV) value */
		if(( var_value = PKI_get_env(var_name)) != NULL ) {
			PKI_MEM_add( mem, var_value, strlen(var_value));
		}

		/* move the pointers */
		p1 = p3;
	};
	if( p1 && strlen(p1)) {
		PKI_MEM_add( mem, p1, strlen(p1));
	}

	len = PKI_MEM_get_size( mem );
	ret = PKI_Malloc ( len + 1);
	memcpy( ret, (char *) mem->data, len );
	ret[len] = '\x0';

	PKI_MEM_free ( mem );
	return ret;
}

/*! \brief Set the ENV variable 'name' with the value 'value'
 */

int PKI_set_env(const char *name, const char *value ) {

	if( !name ) return ( PKI_ERR );

#ifdef HAVE_SETENV
	setenv( name, value, 1);
#else
	if((buf = PKI_Malloc ( strlen(name) + strlen(value) + 2 )) == NULL ) {
		return PKI_ERR;
	}

	sprintf(buf, "%s=%s", name, value);
	putenv (buf);

	PKI_Free ( buf );
#endif

	return ( PKI_OK );
}

/*! \brief Returns the value of the ENV variable 'name'
*/

char * PKI_get_env(const char * name) {

	if (!name) return NULL;

	return getenv(name);
}

int strcmp_nocase(const char * st1,
		          const char * st2) {

	if(!st1 | !st2 ) return (1);

	if( strlen(st1) != strlen(st2)) return (1);

	return strncmp_nocase(st1, st2, 0);
}

int strncmp_nocase(const char * st1,
		           const char * st2,
				   int          n) {
	int i;

	if(!st1) return(-1);
	if(!st2) return(1);

	i = 0;

	if( n < 1 ) {
		size_t st1_len, st2_len;

		st1_len = strlen(st1);
		st2_len = strlen(st2);
		
		n = (int)(st1_len > st2_len ? st2_len : st1_len);
	} else {
		size_t st1_len, st2_len, min;

		st1_len = strlen(st1);
		st2_len = strlen(st2);
		
		if( st1_len < st2_len ) {
			min = st1_len;
		} else {
			min = st2_len;
		}

		if ( n > min ) {
			return ( (min == st1_len ? 1 : -1 ) );
		}
	}

	while( st1[i] && st2[i] && i < n ) {

		unsigned char *pnt_a, *pnt_b;
		unsigned char a, b;

		pnt_a = (unsigned char *) st1+i;
		pnt_b = (unsigned char *) st2+i;

		if( !pnt_a &&  pnt_b ) return(-1);
		if(  pnt_a && !pnt_b ) return(1);
		if( !pnt_a && !pnt_b ) return(0);

		a = (unsigned char) tolower( (char) *pnt_a );
		b = (unsigned char) tolower( (char) *pnt_b );

		if( a != b ) {
			return ( a-b );
		}
		i++;
	}

	return(0);

}

const char * strstr_nocase(const char *buf, const char *string) {

	size_t buf_len, string_len;
	int j,k;
	int match;

	char *ret = NULL;

	if( !buf || !string ) return (NULL);

	if( (buf_len = strlen(buf)) == 0 ) return(NULL);
	if( (string_len = strlen(string)) == 0 ) return(NULL);
	
	j = 0; match = 0;
	while( j < buf_len ) {

		unsigned char a, b;

		for( k = 0; k < string_len; k++ ) {

			a = (unsigned char) tolower(*(buf+j+k));
			b = (unsigned char) tolower(*(string+k));

			if( b != a ) {
				match=0;
				break;
			} else {
				match=1;
			}
		}

		if( match == 1 ) return (buf+j);

		j++;
	}

	return(ret);
}

