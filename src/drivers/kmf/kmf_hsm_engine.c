/* HSM Object Management Functions */

#include <libpki/pki.h>

int _exec_engine_cmds ( PKI_ENGINE *e, PKI_STACK *cmds ) {
        int ret = 1;
        int i, val, num;

	if( !cmds ) return (ret);

        /* Check if there are some commands to be executed */
        val = PKI_STACK_elements(cmds);
        if(val < 1) {
		/* HSM hs no commands to execute in stack */
                return (ret);
        }

        /* Check if the loaded ENGINE has CTRL FUNCTION */
	/*
        if(!ENGINE_ctrl(ee, ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, NULL, NULL) ||
                	((num = ENGINE_ctrl(ee, ENGINE_CTRL_GET_FIRST_CMD_TYPE,
                                                0, NULL, NULL)) <= 0)) {
		return (ret);
	}
	*/

	/* Now executes the STACK of commands */
	for(i = 0; i < val; i++) {
		char buf[256];
		const char *cmd = NULL;
		const char *arg = NULL;

		if( (cmd = (char *) PKI_STACK_get_num(cmds, i)) == NULL ) {
			continue;
		}

		/* Check if this command has no ":arg" */
		if((arg = strstr(cmd, ":")) == NULL) {
			/*
			if(!ENGINE_ctrl_cmd_string(ee, cmd, NULL, 0)) {
				// Error in command
				ret = 0;
			}
			*/
		} else {
			if((int)(arg - cmd) > 254) {
				/* Command Name too long */
				return (ret);
			}
			memcpy(buf, cmd, (int)(arg - cmd));
			buf[arg-cmd] = '\0';
			arg++;

			/* Call the command with the argument */
			/*
			if(!ENGINE_ctrl_cmd_string(ee, buf, arg, 0)) {
				// Error in command
				ret = 0;
			}
			*/
		}

		/* Check the return code */
		if(ret != 1) {
			/* Error in Command */
		}
	}
	return ( ret );
}

PKI_ENGINE *PKI_KMF_ENGINE_new ( char *e_id ) {

	PKI_ENGINE *e = NULL;

	if( !e_id ) return NULL;

	/*
	if((e = (ENGINE * ) ENGINE_by_id(e_id)) == NULL) {
		fprintf(stderr,"invalid engine \"%s\"", e_id);
		return NULL;
	}
	*/

	return ( e );
}

int PKI_KMF_ENGINE_free ( PKI_ENGINE *e ) {

	// if( ee ) ENGINE_free( ee );

	return (PKI_ERR);
}

int PKI_KMF_ENGINE_init ( PKI_ENGINE *e, PKI_STACK *pre, PKI_STACK *post ) {

	int ret = PKI_ERR;

	/* Execute Pre Commands */
        // if( _exec_engine_cmds( e, pre ) == 0 ) return 0;

	/* Perform Initialization */
	// if(!ENGINE_init((ENGINE *) e)) return 0;

	/* Free the ENGINE instance */
	// ENGINE_free( (ENGINE *) e );

	/* Perform POST commands */
	// if( _exec_engine_cmds( e, post ) == 0 ) return 0;

	/* Set Default to the ENGINE for Crypto operations */
	/*
	if(!ENGINE_set_default((ENGINE *) e, ENGINE_METHOD_ALL)) {
		return 0;
        }
	*/

	/* ok */
        // return (PKI_OK);

	return (PKI_ERR);
}
