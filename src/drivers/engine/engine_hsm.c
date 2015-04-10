/* ENGINE HSM Support
*   ==================
*
*   Small Note: This code has been written by Massimiliano Pala sitting
*   on a Bench in Princeton's campus... if there is someone to blame...
*   blame Princeton!!!!
8
*/

#include <strings.h>
#include <libpki/pki.h>
#include <libpki/hsm_st.h>

/* Callbacks for Software OpenSSL HSM */
HSM_CALLBACKS engine_hsm_callbacks = {
		/* Get Error Number */
		HSM_ENGINE_get_errno,
		/* Get Error Description */
		HSM_ENGINE_get_errdesc,
		/* Init */
		HSM_ENGINE_init,
		/* Free */
		HSM_ENGINE_free,
		/* Login */
		NULL,
		/* Logout */
		NULL,
		/* Set Algorithm */
		NULL, /* HSM_ENGINE_algor_set, */
		/* Set fips mode */
		NULL,  // HSM_OPENSSL_set_fips_mode, 
		/* Fips operation mode */
		NULL, // HSM_OPENSSL_is_fips_mode, 
		/* General Sign */
		NULL, // HSM_ENGINE_sign,
		/* General Verify */
		NULL,
		/* Key Generation */
		HSM_ENGINE_X509_KEYPAIR_new,
		/* Key Free Function - Let's fall back to default
		   OpenSSL HSM one */
		HSM_ENGINE_X509_KEYPAIR_free,
		/* Key Wrap */
		NULL,
		/* Key Unwrap */
		NULL,
		/* Object stack Get Function */
		NULL, // HSM_ENGINE_OBJSK_get_url,
		/* Object stack Add Function */
		NULL, /* HSM_ENGINE_KEYPAIR_put_url, */
		/* Object stack Del Function */
		NULL, /* HSM_ENGINE_OBJSK_del_url, */
        	/* Get the number of available Slots */
		NULL, /* HSM_ENGINE_SLOT_num */
		/* Get Slot info */
		HSM_ENGINE_SLOT_INFO_get, /* HSM_ENGINE_SLOT_INFO_get */
		/* Free Slot info */
		NULL, /* HSM_ENGINE_SLOT_INFO_free */
		/* Set the current slot */
		NULL, /* HSM_ENGINE_SLOT_select */
		/* Cleans up the current slot */
		NULL, /* HSM_ENGINE_SLOT_clean */
		/* Returns the Callbacks */
		NULL /* HSM_OPENSSL_X509_get_cb */
};

/* Structure for PKI_TOKEN definition */
HSM engine_hsm = {

        /* Version of the token */
        1,

        /* Description of the HSM */
        "OpenSSL ENGINE",

        /* Manufacturer */
        "OpenSSL",

        /* Pointer to the HSM config file and parsed structure*/
        NULL, 

        /* One of PKI_HSM_TYPE value */
        HSM_TYPE_ENGINE,

	/* URL for the ID of the driver, this is filled at load time */
        NULL,

	/* Pointer to the driver structure */
	NULL,

	/* Pointer to the session */
	NULL,

	/* Pointer to the credentials */
	NULL,

        /* Callbacks Structures */
	&engine_hsm_callbacks
};

HSM_SLOT_INFO engine_slot_info = {

        /* Device Manufacturer ID */
	"OpenSSL",

        /* Device Description */
	"ENGINE interface",

        /* Hardware Version */
	1,
	0,

        /* Firmware Version */
        1,
	0,

	/* Initialized */
	1,

	/* Present */
	1,

	/* Removable */
	0,

	/* Hardware */
	0,

	/* Token Info */
	{
		/* Token Label */
		"Unknown Label\x0                ",
		/* ManufacturerID */
		"Unknown\x0                      ",
		/* Model */
		"Unknown\x0        ",
		/* Serial Number */
		"0\x0              ",
		/* Max Sessions */
		65535,
		/* Current Sessions */
		0,
		/* Max Pin Len */
		0,
		/* Min Pin Len */
		0,
		/* Memory Pub Total */
		0,
		/* Memory Pub Free */
		0,
		/* Memory Priv Total */
		0,
		/* Memory Priv Free */
		0,
		/* HW Version Major */
		1,
		/* HW Version Minor */
		0,
		/* FW Version Major */
		1,
		/* FW Version Minor */
		0,
		/* HAS Random Number Generator (RNG) */
		1,
		/* HAS clock */
		0,
		/* Login is Required */
		0,
		/* utcTime */
		""
	}

};

unsigned long HSM_ENGINE_get_errno ( void ) {
	unsigned long ret = 0;

	ret = ERR_get_error();

	return ret;
}

char * HSM_ENGINE_get_errdesc ( unsigned long err, char *str, size_t size ) {

	char * ret = NULL;

	if ( err == 0 ) {
		err = ERR_get_error();
	}

	if ( str && size > 0 ) {
		ERR_error_string_n ( err, str, size );
		ret = str;
	} else {
		ret = ERR_error_string ( err, NULL );
	}
	
	return ret;
}

HSM *HSM_ENGINE_new ( PKI_CONFIG *conf )
{
	HSM *hsm = NULL;
	char *engine_id = NULL;

	ENGINE_load_builtin_engines();
	ERR_load_ENGINE_strings();

	hsm = (HSM *) PKI_Malloc ( sizeof( HSM ));
	memcpy( hsm, &engine_hsm, sizeof( HSM ));

	/* Let's copy the right callbacks to call when needed! */
	hsm->callbacks = &engine_hsm_callbacks;

	/* Let's get the ID for the HSM */
	if((engine_id = PKI_CONFIG_get_value( conf, "/hsm/id" )) == NULL ) {
		PKI_log_debug("ERROR, Can not get ENGINE id from conf!\n");
		PKI_Free ( hsm );
		return( NULL );
	}

	if((hsm->id = URL_new ( engine_id )) == NULL ) {
		PKI_log_debug("ERROR, Can not convert id into URI (%s)", 
								engine_id);
		PKI_Free ( engine_id );
		PKI_Free ( hsm );
		return (NULL);
	}
	
	if((hsm->driver = ENGINE_by_id(hsm->id->addr)) == NULL) {
		PKI_log_debug("ERROR, invalid engine \"%s\"", hsm->id->addr);
		// ERR_print_errors_fp( stderr );
		PKI_Free ( hsm );
		return (NULL);
	}

	/* The ENGINE interface need to be initialized */
	if(( HSM_ENGINE_init ( hsm->driver, conf )) == PKI_ERR ) {
		PKI_log_debug("ERROR, Can not initialize ENGINE HSM!");
		PKI_Free( hsm );
		return( NULL );
	};

	return( hsm );
}

int HSM_ENGINE_free ( HSM *hsm, PKI_CONFIG *conf ) {

	if( hsm == NULL ) return (PKI_OK);

	return (PKI_ERR);
}

int HSM_ENGINE_init( HSM *hsm, PKI_CONFIG *conf ) {

	/* We need to initialize the driver by using the config
	   options. For the ENGINE, we do not need the driver
	   pointer really.
	*/

	ENGINE *e = NULL;
	int i = 0;

	PKI_STACK *pre_cmds = NULL;
	PKI_STACK *post_cmds = NULL;

	if( !hsm ) return ( PKI_ERR );

       	PKI_log_debug("INFO, Initialising HSM [%s]", 
		PKI_CONFIG_get_value(conf, "/hsm/name"));

	e = (ENGINE *) hsm;

	if( !conf ) {
		PKI_log_debug("WARNING, no PRECMDS provided (?!?!?)");
	} else {

		char *val = NULL;
		char *buf = NULL;

		pre_cmds = PKI_CONFIG_get_stack_value ( conf, 
							"/hsm/pre/cmd" );
		for( i=0; i < PKI_STACK_elements( pre_cmds ); i++ ) {
			buf = PKI_STACK_get_num( pre_cmds, i );

			if((val = strchr( buf, ':')) != NULL ) {
				/* This changes the value in the stack element,
				   so don't rely on the modified value */
				*val = '\x0';
				val++;
			}

			PKI_log_debug("ENGINE, PRE COMMAND (%d) => %s:%s", 
								i, buf, val);

			if(!ENGINE_ctrl_cmd_string(e, buf, val, 0)) {
				PKI_log_debug("ENGINE COMMAND Failed (%s:%s)!",
								buf, val);
				ERR_print_errors_fp( stderr );
			} else {
				PKI_log_debug("ENGINE, COMMAND SUCCESS!");
			}
		}

		PKI_STACK_free_all( pre_cmds );
	}

	if(!ENGINE_init(e)) {
		PKI_log_debug("ERROR, Can not init the ENGINE!");
		return (PKI_ERR);
	} else {
		PKI_log_debug("INFO, ENGINE init Success!");
	}

	if( !conf ) {
		PKI_log_debug("WARNING, POSTCMDS not provided (?!?!?)");
	} else {
		char *val = NULL;
		char *buf = NULL;

		post_cmds = PKI_CONFIG_get_stack_value(conf, "/hsm/post/cmd");

		for( i=0; i < PKI_STACK_elements( post_cmds ); i++ ) {
			buf = PKI_STACK_get_num( post_cmds, i );

			if((val = strchr( buf, ':')) != NULL ) {
				/* This changes the value in the stack element,
				   so don't rely on the modified value */
				*val = '\x0';
				val++;
			}

			// PKI_log_debug("ENGINE, PRE CMD (%d) => %s:%s", 
			// 					i, buf, val);

			if(!ENGINE_ctrl_cmd_string(e, buf, val, 0)) {
				PKI_log_debug("ENGINE, COMMAND Failed (%s:%s)",
								buf, val );
			} else {
				PKI_log_debug("ENGINE, COMMAND Success (%s:%s)",
						buf, val );
			}
		}

		PKI_STACK_free_all( post_cmds );
	}

	if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
		PKI_log_debug("ERROR, Can't use HSM ENGINE!");
		// ERR_print_errors_fp(stderr);
		ENGINE_free(e);
		return ( PKI_ERR );
	}

	PKI_log_debug("INFO, ENGINE HSM init Successful!");

	return (PKI_OK);
}


/* General Signing function */
/*
int HSM_ENGINE_sign (PKI_OBJTYPE type, 
				void *x, 
				void *it_pp, 
				PKI_ALGOR *alg,
				PKI_STRING *bit,
				PKI_X509_KEYPAIR *key, 
				PKI_DIGEST_ALG *digest, 
				void *driver ) {


	int ret = PKI_OK;
	ASN1_ITEM *it = NULL;

	if( !x || !key ) {
		PKI_log_debug("ENGINE, missing required param for signature "
						"generation");
		return (PKI_ERR);
	}

	if( !digest ) digest = PKI_DIGEST_ALG_SHA1;

	if( !driver ) {
		PKI_log_debug("WARNING, ENGINE signature called, but no "
				"driver pointer has been provided!");
	}

	ERR_clear_error();

	switch ( type ) {
		case PKI_OBJTYPE_X509_REQ:
			ret = X509_REQ_sign( (X509_REQ *) x, 
				(EVP_PKEY *) key, (EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_X509_CERT:
			ret = X509_sign( (X509 *) x, (EVP_PKEY *) key, 
				(EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_X509_CRL:
			ret = X509_CRL_sign( (X509_CRL *) x, (EVP_PKEY *) key, 
				(EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_PKCS7:
		case PKI_OBJTYPE_PKCS12:
		case PKI_OBJTYPE_PKI_MSG:
		case PKI_OBJTYPE_SCEP_MSG:
		case PKI_OBJTYPE_CMS_MSG:
			PKI_log_debug("ERROR, DRIVER::ENGINE::OBJ sign not "
							"supported, yet!");
			ret = 0;
			break;
		default:
			if( !it_pp || !bit || !alg ) {
				PKI_log_debug("Missing required params to "
					"complete the generic signature");
				return ( PKI_ERR );
			}

			it = (ASN1_ITEM *) it_pp;
			ret = ASN1_item_sign(it, alg, NULL,
				bit, x, (EVP_PKEY *) key, (EVP_MD *) digest );
			break;
	}
			
	if( ret == 0 ) {
		PKI_log_debug("ERROR, Generating Signature (ENGINE HSM)!");
		ret = PKI_ERR;
	} else {
		ret = PKI_OK;
	}

	PKI_log_debug("ENGINE, Signature successful");

	return (ret);
}
*/

/* ---------------------- ENGINE Slot Management Functions ---------------- */

HSM_SLOT_INFO * HSM_ENGINE_SLOT_INFO_get ( unsigned long num, HSM *hsm ) {

	HSM_SLOT_INFO *ret = NULL;
	ENGINE *e = NULL;

	if( !hsm || !hsm->driver ) return ( NULL );

	e = hsm->driver;

	ret = (HSM_SLOT_INFO *) PKI_Malloc ( sizeof (HSM_SLOT_INFO));
	memcpy( ret, &engine_slot_info, sizeof( HSM_SLOT_INFO ));

	snprintf(ret->token_info.label, LABEL_SIZE, "%s", ENGINE_get_name( e ));
	snprintf(ret->token_info.model, MODEL_SIZE, "%s", ENGINE_get_id ( e ));

	return (ret);
}

