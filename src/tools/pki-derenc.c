/* ASN1 (DER) Encoder
 * (c) 2011 by Massimiliano Pala and OpenCA Labs
 * OpenCA Licensed Software
 */

#include <libpki/pki.h>

// #include <openssl/asn1.h>
// #include <openssl/asn1t.h>
// #include <openssl/conf_api.h>

typedef struct der_st {
	char *data;
	long int size;
} DER;

static char *banner = "\n"
 "  OpenCA ASN1Der Encoder Tool - v" VERSION "\n"
 "  (c) 2011-2022 by Massimiliano Pala and OpenCA Labs\n"
 "  All Rights Reserved\n\n";

DER *PKI_ASN1_encode_txt ( char *file, char *section ) {

	long len = 0;
	long int errorline = -1;
    unsigned char *encoded = NULL;
	char root[256];

	DER *ret = NULL;

	ASN1_TYPE *t = NULL;
	CONF *conf=NULL;

	if( !file ) return NULL;
	if( !section  ) section = "asn1";

	// ------------ Now Use Internals from OpenSSL ------------- //
	conf = NCONF_new(NULL);
    if (NCONF_load(conf, file, &errorline) <= 0) {
		printf("ERROR: can not parse file (line %ld)\n\n", errorline);
		return NULL;
	};

	printf("  * Using section ....: [%s]\n", section);

	snprintf(root, sizeof(root), "SEQUENCE:%s", section);

	t = ASN1_generate_nconf( root, conf);

    if(t == NULL ) {
		fprintf(stderr, "ERROR, can not encode!\n");
		return NULL;
	};
    len = i2d_ASN1_TYPE(t, &encoded);
    ASN1_TYPE_free(t);
	
	if((ret = (DER *) malloc ( sizeof(ret) )) != NULL ) {
		ret->data = (char *) encoded;
		ret->size = len;
	};

	return ret;

};

int main(int argc, char *argv[] ) {

	char *file_s = NULL;
	char *section_s = NULL;
	FILE *out_file = stdout;
	char *out_file_s = "encoded.asn";
	DER *der = NULL;

	ERR_load_crypto_strings();

	printf("%s", banner);

	if( argc < 2 ) {
		fprintf( stderr, "\n   USAGE: %s <filename> [ section ] [ outfile ]\n\n", argv[0]);
		exit(1);
	};

	file_s = argv[1];
	if ( argc > 1 ) section_s = argv[2];
	if ( argc > 2 ) out_file_s = argv[3];
	

	printf("  * Encoding file ....: [%s]\n", file_s);
	if((der = PKI_ASN1_encode_txt( file_s, section_s )) == NULL ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	};

	printf("  * Saving data ......: [%s]\n", out_file_s);
	if((out_file = fopen( out_file_s, "w+")) == NULL ) {
		printf("ERROR: can not open file for writing!\n\n");
		exit(1);
	};

	if (fwrite(der->data, (size_t) der->size, 1, out_file) <= 0)
	{
		printf("ERROR: can not write file contents!\n\n");
		exit(1);
	};

	fclose( out_file );

	printf("  * Op Completed .....: [Success]\n\n");

	exit(0);
};

