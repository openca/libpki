/*
 * LIBPKI - Easy PKI Library
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2007
 *
 * Copyright (c) 2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>

#ifdef HAVE_LDAP


LDAP *URL_LDAP_connect(const URL *url, int tout ) {

	LDAP		*ld = NULL;
	int			protocol = -1;

	char		*ldap_server = NULL;

	struct berval cred;
	int			rc = 0;

    cred.bv_val = NULL;
    cred.bv_len = 0;

#if (LIBPKI_OS_CLASS == LIBPKI_OS_POSIX)
	(void) signal( SIGPIPE, SIG_IGN );
#endif

	if( (!url) || (!url->addr) || (!url->path)) {
		return NULL;
	}

#if defined(LDAP_VENDOR_OPENLDAP)
	if((ldap_server = PKI_Malloc ( strlen(url->addr) + 20 )) == NULL ) {
		return NULL;
	}

	snprintf( ldap_server, strlen(url->addr) + 19, 
			"ldap://%s:%d", url->addr, url->port );
	PKI_log_debug("LDAP: connecting to %s", ldap_server );

    if((ldap_initialize( &ld, ldap_server )) != LDAP_SUCCESS ) {
#else
	ldap_server = strdup( url->addr );
	if((ld = ldap_init( ldap_server, url->port)) == NULL ) {
#endif
		PKI_Free ( ldap_server );

		PKI_log_err ( "ERROR::Can not initialize LDAP connection to %s",
			url->addr );
		return ( NULL );
	}

	PKI_Free ( ldap_server );

	(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &protocol );

#if defined(LDAP_VENDOR_OPENLDAP)
    (void) ldap_set_option( ld, LDAP_OPT_TIMELIMIT, &tout );
#endif

#if defined(LDAP_VENDOR_MICROSOFT)
    (void) ldap_set_option( ld, LDAP_OPT_TCP_KEEPALIVE, LDAP_OPT_ON );
#endif

#if defined(LDAP_VENDOR_MICROSOFT) || defined(LDAP_VENDOR_SUN)
	PKI_log_debug("LDAP: bind");
    if( ldap_bind ( ld, url->usr, url->pwd, LDAP_AUTH_SIMPLE) != 
				LDAP_SUCCESS ) {
		PKI_log_err("LDAP::Can not bind to %s", url->addr );
		goto err;
        return NULL;
    };
#else
#  ifdef LDAP_OPT_X_KEEPALIVE_IDLE
    (void) ldap_set_option( ld, LDAP_OPT_X_KEEPALIVE_IDLE, LDAP_OPT_ON );
#  endif
	PKI_log_debug("LDAP: SASL bind_s");

	if(( rc = ldap_sasl_bind_s( ld, NULL, LDAP_SASL_SIMPLE, &cred,
                    NULL, NULL, NULL )) != LDAP_SUCCESS ) {

        switch ( rc ) {
            case LDAP_BUSY:
				PKI_log_err("LDAP: Server is Busy");
				break;
            case LDAP_UNAVAILABLE:
				PKI_log_err("LDAP: Server is Unavailable");
				break;
            default:
                PKI_log_err("LDAP: Can not bind to server");
        }

		goto err;
    }
# endif

	PKI_log_debug("LDAP::Initialization Successful!");
	return(ld);
err:
	/* Error, We have to free the LDAP structure */
#if defined(LDAP_VENDOR_OPENLDAP)
	if (ld) ldap_unbind_ext ( ld, NULL, NULL );
#else
	if (ld) ldap_unbind ( ld );
#endif
	return NULL;
}

PKI_MEM_STACK *URL_get_data_ldap_url(const URL *url, int timeout, ssize_t size ) {

#ifdef _WINDOWS
	struct l_timeval	zerotime;
	struct l_timeval	*time;
#else
	struct timeval		zerotime;
	struct timeval		*time;
#endif

	LDAP	*ld = NULL;
	int  	i,rc;
	char	*attrs[] = { url->attrs, NULL } ;
	char    *filter = "objectclass=*";
	struct berval **vals = NULL;
#if defined(LDAP_VENDOR_OPENLDAP) || defined(LDAP_VENDOR_MICROSOFT)
	// int		msgid = 0;
#endif
	LDAPMessage *res = NULL;
	PKI_MEM_STACK *ret = NULL;
	PKI_MEM *obj = NULL;

	if( (!url) || (!url->addr) || (!url->path)) {
		return NULL;
	}

	/* We search for the exact match, so LDAP_SCOPE_BASE is used here */
	if ( timeout > 0 ) {
		zerotime.tv_sec = timeout;
		zerotime.tv_usec = 0L;
		time = &zerotime;
	} else {
		time = NULL;
		timeout = 0;
		zerotime.tv_sec =  0L;
		zerotime.tv_usec = 0L;
	}

	PKI_log_debug("LDAP: Search Timeout is %d", timeout );

	if((ld = URL_LDAP_connect ( url, timeout )) == NULL ) {
		PKI_log_debug("LDAP: can not connect to server (%s)",
						url->url_s );
		return NULL;
	};


#if defined(LDAP_VENDOR_OPENLDAP) || defined(LDAP_VENDOR_MICROSOFT)
	if ((rc = ldap_search_ext_s(ld, url->path, LDAP_SCOPE_BASE,
			filter, attrs, 0, NULL, NULL, time, (int) size, &res )) != LDAP_SUCCESS)
	{
		PKI_log_err("LDAP: Search Error (0x%8.8x)", rc);
		goto end;
	}

	/*
	if (( rc = ldap_result (ld, msgid, LDAP_MSG_ONE,
                       				&zerotime, &res)) <= 0 ) {
		PKI_log_err("LDAP: [%s] object not found (0x%8.8x)", 
			url->path, rc);
		goto end;
	}
	*/

#else
	if (( rc = ldap_search_s( ld, url->path, LDAP_SCOPE_BASE,
			filter, attrs, 0, &res )) != LDAP_SUCCESS ) {

		PKI_log_err("LDAP: [%s] object not found (0x%8.8x)", url->path, rc);

		goto end;
	}
#endif

	if (( i = ldap_count_entries( ld, res )) <= 0 ) {
		PKI_log_err("No Returned Entries (%s)", i);
	}

	if((ret = PKI_STACK_MEM_new()) == NULL ) {
		/* ERROR: Allocating memory */
		goto end;
	}
	if((vals = ldap_get_values_len (ld, res, attrs[0])) != NULL ) {

		for( i=0; vals[i] != NULL; i++ ) {
			if((obj = PKI_MEM_new_null()) == NULL ) {
				goto end;
			}
			if(PKI_MEM_add( obj, (const unsigned char *) vals[i]->bv_val, 
					vals[i]->bv_len) == PKI_ERR) {
				/* ERROR in memory growth */;
				break;
			}
			PKI_STACK_MEM_push( ret, obj );
		}

		ldap_value_free_len( vals );
		vals = NULL;
	} else {
		return NULL;
	}

end:
	if(res) ldap_msgfree( res );
#if defined(LDAP_VENDOR_OPENLDAP)
	if(ld) ldap_unbind_ext( ld, NULL, NULL );
#else
	if(ld) ldap_unbind( ld );
#endif

	return (ret);
}

#endif /* LDAP */
