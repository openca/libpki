
#include <libpki/pki.h>

const char * data = "This is the data to be encrypted, the answer is 42.";

int main (int argc, char *argv[] ) {

	PKI_MEM * enc_data = NULL;
	PKI_MEM * dec_data = NULL;
		// Pointer to encrypted data structure

	PKI_X509_KEYPAIR * key_pair = NULL;
		// Keypair Pointer

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006-2023 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	// Info
	printf("* RSA Key Generation:\n");
	printf("  - Generating RSA Keypair ......: ");
	fflush(stdout);

	// Generates a new RSA key
	key_pair = PKI_X509_KEYPAIR_new(PKI_SCHEME_RSA, 2048, NULL, NULL, NULL );
	if (!key_pair) {
		fprintf(stderr, "\n    ERROR::Can not generate RSA 2048 bit keypair, aborting.\n");
		exit (1);
	}

	// // Info
	// printf("Ok\n  - Extracting RAW value ........: ");

	// // Let's extract the low-level pointer
	// key_pair_value = PKI_X509_get_value(key_pair);
	// if (!key_pair_value) {
	// 	fprintf(stderr, "\n    ERROR: Cannot get the key pair lower layer value, aborting.");
	// 	exit(1);
	// }

	PKI_MEM * out_mem = NULL;
	printf("* Extracting the RAW public key ... :");
	if (PKI_X509_KEYPAIR_get_public_bitstring(key_pair, &out_mem) == NULL) {
		fprintf(stderr, "ERROR!\n");
	}
	printf("Ok.\n");

	printf("* Freeing memory for the RAW public key ... :");
	if (out_mem) PKI_MEM_free(out_mem);
	out_mem = NULL;

	// Info
	printf("Ok\n\n");
	
	printf("* Public Key Encryption:\n  - Encrypting Data Value .......: ");

	// Perform public key encryption operation
	enc_data = PKI_X509_KEYPAIR_encrypt(key_pair, (const unsigned char *)data, strlen(data), RSA_PKCS1_OAEP_PADDING);
	if (enc_data == NULL) {
		fprintf(stderr, "\n    ERROR: Cannot perform public key encryption.\n\n");
		exit(1);
	}

	// Info
	printf("Ok\n  - Encrypted Data Length .......: %zu\n\n", enc_data->size);

	// Info
	printf("* Public Key Decryption:\n");
	printf("  - Decrypting Data Value .......: ");

	// Perform public key encryption operation
	dec_data = PKI_X509_KEYPAIR_decrypt(key_pair, (const unsigned char *)enc_data->data, enc_data->size, RSA_PKCS1_OAEP_PADDING);
	if (dec_data == NULL) {
		fprintf(stderr, "\n    ERROR: Cannot perform public key encryption.\n\n");
		exit(1);
	}

	// Info
	printf("Ok\n  - Decrypted Data Length .......: %zu\n", dec_data->size);
	printf("  - Decrypted Data ..............: %s\n", (const char *)dec_data->data);

	// All Done
	printf("\n* All Done.\n\n");
	return (0);
}

