
#include <libpki/pki.h>

int log_operations ( void ) {

	PKI_log( PKI_LOG_NONE, 
			"%s:%d:%d:: LOG_NONE\n", __FILE__, __LINE__, 
				PKI_LOG_NONE );

	PKI_log( PKI_LOG_ERR, 
			"%s:%d:%d:: LOG_ERR\n", __FILE__, __LINE__,
				PKI_LOG_ERR );

	PKI_log( PKI_LOG_WARNING, 
			"%s:%d:%d:: LOG_WARNING\n", __FILE__, __LINE__,
				PKI_LOG_WARNING );

	PKI_log( PKI_LOG_NOTICE, 
			"%s:%d:%d:: LOG_NOTICE\n", __FILE__, __LINE__,
				PKI_LOG_NOTICE );

	PKI_log( PKI_LOG_INFO, 
			"%s:%d:%d:: LOG_INFO\n", __FILE__, __LINE__ ,
				PKI_LOG_INFO);

	return 1;
}

int main (int argc, char *argv[] ) {

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	log_operations();

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}
	log_operations();
	PKI_log_end();


	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}
	log_operations();
	PKI_log_end();


	if(( PKI_log_init (PKI_LOG_TYPE_FILE, PKI_LOG_NOTICE, 
		"results/test9.log", PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) 
								== PKI_ERR ) {
		exit(1);
	}
	log_operations();
	PKI_log_end();

	printf("\n\n[ Test Ended Succesfully ]\n\n");

	return (0);
}

