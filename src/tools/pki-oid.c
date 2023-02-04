#include <libpki/pki.h>

#define BOLD     "\x1B[1m"
#define NORM     "\x1B[0m"
#define BLACK    "\x1B[30m"
#define RED      "\x1B[31m"
#define GREEN    "\x1B[32m"
#define BLUE     "\x1B[34m"

#define BG       "\x1B[47m"
#define BG_BOLD  "\x1B[31;47m"
#define BG_NORM  "\x1B[30;47m"
#define BG_RED   "\x1B[31;47m"
#define BG_GREEN "\x1B[32;47m"
#define BG_BLUE  "\x1B[34;47m"

char banner[] = 
	"\n   " BOLD "PKI OID Lookup Tool " NORM "(pki-oid)\n"
	"   (c) 2008-2023 by " BOLD "Massimiliano Pala" NORM
			" and " BOLD "Open" RED "CA" NORM BOLD " Labs\n" NORM
	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software\n\n";

char usage_str[] =
	"     " BG "                                                " NORM "\n"
	"     " BG_BOLD "  USAGE: " BG_NORM "pki-oid "
		BG_GREEN "[options]                      " NORM "\n"
	"     " BG "                                                " NORM "\n\n";

void usage ( void ) {

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf("   Where options are:\n");
	printf(BLUE "    -nid "    NORM " ...........: Use ID (number) for lookup\n");
	printf("\n");

	exit (1);
}

PKI_OID_STACK * get_oid(int oid_number) {

	PKI_OID_STACK * ret_sk = NULL;
	PKI_OID * oid_pnt = NULL;

	// Allocates a new Stack
	if ((ret_sk = PKI_STACK_OID_new()) == NULL) return NULL;

	// Retrieves the OID object for the NID
	if ((oid_pnt = OBJ_nid2obj(oid_number)) == NULL) return NULL;	

	// Pushes the OID object
	PKI_STACK_OID_push(ret_sk, oid_pnt);

	// All Done
	return ret_sk;
}

PKI_OID_STACK * search_oid(const char * filter) {
	
	PKI_OID_STACK * ret_sk = NULL;
	PKI_OID * oid_pnt = NULL;

	// Upper Bound
	const int OID_UPPER_BOUND_MAX = 65535;

	// Buffer for text
	char buffer[512] = { 0x0 };

	// Memory Allocation
	if ((ret_sk = PKI_STACK_OID_new()) == NULL) return NULL;

	// Search through all the OIDs
	for (int idx = 1; idx < OID_UPPER_BOUND_MAX; idx++) {

		// Get the idx-th entry in the table
		if ((oid_pnt = OBJ_nid2obj(idx)) == NULL) continue;

		// Checks the Name
		if (OBJ_obj2txt(buffer, sizeof(buffer), oid_pnt, 0)) {
			// Compares the name and continues if no match
			if (strncmp_nocase(buffer, filter, (int)strlen(filter)) == 0) {
				// Here we should have a match, let's add it to the queue
				PKI_STACK_OID_push(ret_sk, oid_pnt);
				continue;
			}
		}

		// Checks the OID representation
		if (OBJ_obj2txt(buffer, sizeof(buffer), oid_pnt, 1)) {
			// Compares the OID and continues if not match
			if (strncmp_nocase(buffer, filter, (int)strlen(buffer)) == 0) {
				// Here we should have a match, let's add it to the queue
				PKI_STACK_OID_push(ret_sk, oid_pnt);
				continue;
			}
		}

	}

	// All Done
	return ret_sk;
}

void print_oid_info (const PKI_OID * oid, const int idx) {

	if (!oid) return;

	char buff[256];

	printf("  - [%d] ", idx);

	if (!OBJ_obj2txt(buff, sizeof(buff), oid, 0)) {
		printf("<ERROR::Cannot Retrieve OID name>");
	} else {
		printf("%s: ", buff);
	}

	if (!OBJ_obj2txt(buff, sizeof(buff), oid, 1)) {
		printf("<ERROR: Cannot Retrieve the Dotted Notation> ");
	} else {
		printf("%s ", buff);
	}

	printf("(OpenSSL NID: %d)\n", OBJ_obj2nid(oid));
}

void print_oid_stack(PKI_OID_STACK * oid_sk) {

	if (oid_sk != NULL && PKI_STACK_OID_elements(oid_sk) > 0) {
		printf("> OID Search: %d result(s)\n", 
			oid_sk == NULL || PKI_STACK_OID_elements(oid_sk) <= 0 ? 0 : PKI_STACK_OID_elements(oid_sk));
	} else {
		printf("> OID Search: No results.\n\n");
		return;
	}

	for (int idx = 0; ((oid_sk != NULL) && (idx < PKI_STACK_OID_elements(oid_sk))); idx++) {

		PKI_OID * oid_obj = NULL;
			// Pointer to individual element

		// Retrieves the individual OID
		if ((oid_obj = PKI_STACK_get_num(oid_sk, idx)) == NULL) continue;

		// Prints the OID
		print_oid_info(oid_obj, idx);
	}

	printf("\n");
	fflush(stdout);

	return;
}

int main (int argc, char *argv[] ) {

	int verbose = 0;

	PKI_init_all();

	int use_number = 0;

	PKI_OID_STACK * oid_sk = NULL;

	const char * oid_string = NULL;
	
	// Checks we have at least an argument
	if (argc <= 1) {
		usage();
	}

	// Checks the input switches, if any
	for(int i = 1; i < argc - 1; i++ ) {

		if ( strncmp_nocase ( argv[i], "-nid", 4) == 0) {
			use_number = 1;
		} else if(strncmp_nocase(argv[i], "-help", 5) == 0 ) {
			usage();
		} else if(strncmp_nocase(argv[i], "-h", 2) == 0 ) {
			usage();
		} else if(strncmp_nocase(argv[i],"-verbose", 8) == 0 ) {
			verbose=1;
		} else {
			if(verbose) fprintf(stderr, "%s", banner );
			fprintf( stderr, BOLD RED "\n    ERROR: "
				NORM "Unrecognized parameter \'" BOLD BLUE
						"%s" NORM "\'\n\n",
				argv[i]);
			usage();
			exit(1);
		}
	}

	// Gets the string to check
	oid_string = argv[argc - 1];

	// Input Checks
	if (argc < 1) {
		fprintf(stderr, BOLD RED "\n    ERROR: "
						NORM "Cannot convert the OID number (-id was used) \'" BOLD BLUE
							"%s" NORM "\'\n\n",	oid_string);
		exit(1);
	}

	// Verbose
	printf("%s", banner);

	// Let's execute the search
	if (use_number == 1) {

		// Parse the number
		int oid_number = atoi(oid_string);

		// Checks the number's valid range
		if (oid_number <= 0 || oid_number > 65535) {
			fprintf( stderr, BOLD RED "\n    ERROR: "
				NORM "Cannot convert the OID number (-id was used) \'" BOLD BLUE
						"%s" NORM "\'\n\n",	oid_string);
			exit(1);
		}

		// Let's perform the search by ID
		oid_sk = get_oid(oid_number);

	} else {

		// Let's perform the search by TXT
		oid_sk = search_oid(oid_string);
	}

	// Let's print the results
	print_oid_stack(oid_sk);

	// Let's free the memory
	while (oid_sk && PKI_STACK_OID_elements(oid_sk) > 0) {
		PKI_OID * tmp_oid = NULL;

		tmp_oid = PKI_STACK_OID_pop(oid_sk);

		if (tmp_oid) PKI_OID_free(tmp_oid);
		tmp_oid = NULL;
	}
	PKI_STACK_OID_free(oid_sk);
	oid_sk = NULL;

	return(0);
}


