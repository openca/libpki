#include <libpki/pki.h>

int main() {

	int arr[11] = {
		1297, 1298, 1299, 1300, 1301, 1302, 1303, 1307, 
		1308, 1309, 1310
	};

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, 
					   PKI_LOG_ALWAYS,
					   NULL,
					   PKI_LOG_FLAGS_ENABLE_DEBUG,
					   NULL )) == PKI_ERR ) {
		exit(1);
	}

	const EVP_PKEY_ASN1_METHOD *ameth_one;
	// const EVP_PKEY_ASN1_METHOD *ameth_two;

	for (int idx = 0; idx < 11; idx++) {
		ameth_one = EVP_PKEY_asn1_find(NULL, arr[idx]);
		if (!ameth_one) {
			printf("ERROR, can not find method for %s (%d)!\n",
				PKI_ID_get_txt(arr[idx]), arr[idx]);
			exit(1);
		}
	}

	return 0;
}

