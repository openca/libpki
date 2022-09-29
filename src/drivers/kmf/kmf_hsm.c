/* KMF HSM implementation for LibPKI */

#include <strings.h>
#include <libpki/pki.h>

HSM kmf_hsm = {
	/* HSM Version */
	1,
	/* Description of the HSM */
	"OpenSSL ENGINE",
	/* Manufacturer */
	"OpenSSL",
	/* Pointer to the HSM config file and parsed structure*/
	NULL, 
	/* HSM type */
	HSM_TYPE_KMF,
	/* Engine Pointer */
	NULL,
	/* PKI Store */
	NULL,
	/* Pre Commands */
	NULL,
	/* Post Commands */
	NULL,
	/* is Logged In ? */
	0,
	/* is Cred Set ? */
	0,
	/* is Login Required ? */
	0,
	/* Callbacks */
	{
		/* New */
		HSM_KMF_new,
		/* Init */
		HSM_KMF_init,
		/* Free */
		HSM_KMF_free,
		/* Certificate Sign */
		NULL, // HSM_KMF_CERT_sign,
		/* Certificate Verify */
		NULL,
		/* Request Sign */
		NULL, // HSM_KMF_REQ_sign,
		/* General Sign */
		NULL,
		/* Key Generation */
		NULL, // HSM_KMF_KEYPAIR_new,
		/* Key Free */
		NULL, // HSM_KMF_KEYPAIR_free,
		/* Key Remove Function */
		NULL
	}
};

HSM * HSM_KMF_new() {

	return NULL;

	// HSM *hsm_pnt = NULL;

	// if(( hsm_pnt = (HSM *) malloc (sizeof( HSM ))) == NULL ) {
	// 	return NULL;
	// }

	// /* Zeroize the structure */
	// memset( hsm_pnt, 0, sizeof( openssl_hsm ));
	// memcpy( hsm_pnt, &openssl_hsm, sizeof( openssl_hsm ));

	// hsm_pnt->id = "KMF";

	// return hsm_pnt;
}

int HSM_KMF_free ( HSM *hsm, PKI_CONFIG *conf ) {
	if( !hsm ) return 1;

	free( hsm );

	return 1;
}

int HSM_KMF_init( HSM *hsm, PKI_STACK *pre_cmds, PKI_STACK *post_cmds ) {
	if( !hsm ) return (PKI_ERR);

	return (PKI_ERR);

}

HSM *HSM_KMF_new_init( char *e_id, PKI_STACK *pre_cmds, PKI_STACK *post_cmds ) {

	return NULL;

	// HSM *hsm = NULL;
	// KMF_HANDLE_T *e = NULL;

	// KMF_RETURN rv;

	/*
	if((hsm = HSM_new( NULL )) == NULL ) {
		return NULL;
	}
	*/

	/* If engine is passed, then use it, otherwise instantiate
	   a new one using the e_id */
	/*
	rv = KMF_Initialize( &lib_h, NULL, NULL );
	if( rv != KMF_OK ) return (NULL);

	memset(&cfg_par, 0, sizeof(KMF_CONFIG_PARAMS));
	// cfg_par.kstype = KMF_KEYSTORE_PK11TOKEN;
	// cfg_par.pkcs11config.label = "Sun Metaslot";
	// cfg_par.pkcs11config.readonly = B_FALSE;
	cfg_par.kstype = KMF_KEYSTORE_OPENSSL;

	rv = KMF_ConfigureKeystore( lib_h, &cfg_par );
	if( rv != KMF_OK ) return (NULL);

	return( lib_h );
	if(( e = (PKI_ENGINE *) PKI_ENGINE_new( e_id )) == NULL ) {
		if( hsm ) HSM_free( hsm );
		return NULL;
	}
	hsm->engine = (PKI_ENGINE *) e;
	
	if ( e_id != NULL )
		hsm->id = strdup( e_id );

	if( PKI_ENGINE_init( (ENGINE *) hsm->engine, pre_cmds, 
						post_cmds ) == 0 ) {
		if( hsm ) HSM_free ( hsm );
		return NULL;
	}
	*/

	// return hsm;
}

