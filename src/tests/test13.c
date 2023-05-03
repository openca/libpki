
#include <libpki/pki.h>

/* Function Prototypes */
int sign_ocsp_response();

// ====
// Main
// ====

int main (int argc, char *argv[] ) {

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

	if (sign_ocsp_response() != PKI_OK) {
		printf("\nERROR: Cannot sign OCSP responses without a certificate.\n\n");
		exit(1);
	}

	printf("Done.\n\n");

	return (0);
}

int sign_ocsp_response() {

	PKI_KEYPARAMS * kp = PKI_KEYPARAMS_new(PKI_SCHEME_RSA, NULL);

	PKI_X509_KEYPAIR * k = PKI_X509_KEYPAIR_new_kp(kp, NULL, NULL, NULL);
	if (!k) return 0;

	PKI_X509_OCSP_RESP * resp = PKI_X509_OCSP_RESP_new();
	if (!resp) {
		if (k) PKI_X509_free(k);
		return 0;
	}
	PKI_X509_OCSP_REQ * req = PKI_X509_get("tmp/ocsp-req.der", PKI_DATATYPE_X509_OCSP_REQ, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
	if (!req) {
		if (k) PKI_X509_free(k);
		if (resp) PKI_X509_free(resp);
		return 0;
	}

	for (int i = 0; i < PKI_X509_OCSP_REQ_elements(req); i++) {
		
		OCSP_CERTID * cid = PKI_X509_OCSP_REQ_get_cid(req, i);
		PKI_TIME * thisUpdate = PKI_TIME_new(- PKI_VALIDITY_ONE_DAY);
		PKI_TIME * nextUpdate = PKI_TIME_new(PKI_VALIDITY_ONE_MONTH);
		PKI_TIME * revocationDate = NULL; // PKI_TIME_new(- PKI_VALIDITY_ONE_YEAR);

		PKI_X509_OCSP_RESP_add(resp, cid, PKI_OCSP_CERTSTATUS_GOOD, revocationDate, thisUpdate, nextUpdate, PKI_X509_CRL_REASON_UNSPECIFIED, NULL);

		if (thisUpdate) PKI_TIME_free(thisUpdate);
		if (nextUpdate) PKI_TIME_free(nextUpdate);
		if (revocationDate) PKI_TIME_free(revocationDate);
	}

	if (PKI_X509_OCSP_REQ_has_nonce(req))	{
		if (PKI_X509_OCSP_RESP_copy_nonce(resp, req) == PKI_ERR) {
			printf("Error while copying the NONCE");
			exit(1);
		}
	}

	PKI_OCSP_RESP * r = PKI_X509_get_value(resp);
	if (!r) {
		printf("Internal Pointer Error");
		exit(1);
	}

	if (PKI_OK != PKI_X509_OCSP_RESP_sign(resp,
											k,
											NULL,
											NULL,
											NULL,
											PKI_DIGEST_ALG_SHA256,
											PKI_X509_OCSP_RESPID_TYPE_BY_KEYID)) {
		printf("Error while signing the response\n\n");
		exit(1);
	}

	if (req) PKI_X509_free(req);
	if (resp) PKI_X509_free(resp);
	if (k) PKI_X509_free(k);

	return 1;
}

