
#include <libpki/pki.h>

// ==============
// Global Defines
// ==============

#define test_name "Test Eight (8) - Log Interface"
#define log_name  "results/8-log-interface.log"

// ===================
// Function Prototypes
// ===================

int subtest1();
int subtest2();

// ====
// Main
// ====

int main (int argc, char *argv[] ) {

	// Changes the current directory to be the working
	// main directory to make sure all file paths are correct
	chdir("../..");

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if ((PKI_log_init(PKI_LOG_TYPE_STDERR,
					  PKI_LOG_ALWAYS,
					  log_name,
					  PKI_LOG_FLAGS_ENABLE_DEBUG,
					  NULL)) == PKI_ERR ) {
		fprintf(stderr, "ERROR: cannot initialize the log file!\n");
		exit(1);
	}

	// Info
	PKI_log(PKI_LOG_INFO, "===== %s Test Begin =====", test_name);

	// SubTests Execution
	int success = (
		subtest1()
		&& subtest2()
	);

	if ((PKI_log_init(PKI_LOG_TYPE_STDERR,
					  PKI_LOG_ALWAYS,
					  log_name,
					  PKI_LOG_FLAGS_ENABLE_DEBUG,
					  NULL)) == PKI_ERR ) {
		fprintf(stderr, "ERROR: cannot initialize the log file!\n");
		exit(1);
	}

	// Info
	if (success) {
		PKI_log(PKI_LOG_INFO, "===== %s: Passed Successfully =====", test_name);
	} else {
		PKI_log(PKI_LOG_INFO, "===== %s: Failed =====", test_name);
	}

	// Error Condition
	if (!success) return 1;

	// Success
	return 0;
}

int subtest1() {

	PKI_log( PKI_LOG_NONE, "%s:%d:%d:: LOG_NONE", __FILE__, __LINE__, 	PKI_LOG_NONE );

	PKI_log( PKI_LOG_MSG, "%s:%d:%d:: LOG_MSG", __FILE__, __LINE__, PKI_LOG_MSG );

	PKI_log( PKI_LOG_ERR, "%s:%d:%d:: LOG_ERR", __FILE__, __LINE__,	PKI_LOG_ERR );

	PKI_log( PKI_LOG_WARNING, "%s:%d:%d:: LOG_WARNING", __FILE__, __LINE__,	PKI_LOG_WARNING );

	PKI_log( PKI_LOG_NOTICE, "%s:%d:%d:: LOG_NOTICE", __FILE__, __LINE__, PKI_LOG_NOTICE );

	PKI_log( PKI_LOG_INFO, "%s:%d:%d:: LOG_INFO", __FILE__, __LINE__ , PKI_LOG_INFO);

	return 1;
}

int subtest2() {

	if ((PKI_log_init (PKI_LOG_TYPE_FILE, 
					   PKI_LOG_NOTICE, 
					   log_name, 
					   PKI_LOG_FLAGS_ENABLE_DEBUG, 
					   NULL)) == PKI_ERR ) {
		fprintf(stderr, "Can not initialize the log file (%s)\n", log_name);
		return 0;
	}

	PKI_log( PKI_LOG_NONE, "%s:%d:%d:: LOG_NONE\n", __FILE__, __LINE__, PKI_LOG_NONE );

	PKI_log( PKI_LOG_MSG, "%s:%d:%d:: LOG_MSG", __FILE__, __LINE__, PKI_LOG_MSG );

	PKI_log( PKI_LOG_ERR, "%s:%d:%d:: LOG_ERR\n", __FILE__, __LINE__, PKI_LOG_ERR );

	PKI_log( PKI_LOG_WARNING, "%s:%d:%d:: LOG_WARNING\n", __FILE__, __LINE__, PKI_LOG_WARNING );

	PKI_log( PKI_LOG_NOTICE, "%s:%d:%d:: LOG_NOTICE\n", __FILE__, __LINE__, PKI_LOG_NOTICE );

	PKI_log( PKI_LOG_INFO, "%s:%d:%d:: LOG_INFO\n", __FILE__, __LINE__, PKI_LOG_INFO);

	PKI_log_end();

	return 1;
}