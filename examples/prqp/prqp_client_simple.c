
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_X509_CERT *cacert = NULL;

	char *url_s = NULL;
	char *service = NULL;
	int debug = 0;
	int i, error;

	PKI_STACK *sk_services = NULL;
	PKI_STACK *ret_sk = NULL;

	char *cacertfile = NULL;

	PRQP_init_all_services();

	sk_services = PKI_STACK_new_null();
	
	error = 0;
	for(i=1; i < argc; i++ ) {
		if ( strcmp ( argv[i], "-cacert" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-connect" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			url_s = argv[++i];
		} else if ( strcmp ( argv[i], "-service" ) == 0) {
			if( (argv[i+1] == NULL) || ( service != NULL )) {
				error=1;
				break;
			}
			service = argv[++i];
		} else {
			printf("ERROR:Unreckognized parameter %s\n",
				argv[i]);
			error=1;
		}
	}

	if( !cacertfile && !service ) {
		printf("\nERROR: -cacert  and -service are needed!\n");
		error = 1;
	}

	if( error == 1 ) {
		printf("\nUSAGE: %s options\n\n", argv[0]);
		printf("Where options are:\n");
		printf(" -cacert <file>       - Certificate to find CA services for (optional if\n                       issuer is provided)\n");
		printf(" -connect <host[:port]> - Host to connect to (if blank the contents of /etc/pki.conf will be used)\n");
		printf(" -service <id>        - Service which URL is to be asked (optional, multiple\n                       accepted)\n");
		printf("\nWhere service <id> can be:\n\n");
		printf(" * General Services\n");
		printf("     [ocsp] OCSP Service\n");
		printf("     [caIssuers] CA Information\n");
		printf("     [timeStamping] TimeStamping Service\n");
		printf("     [scvp] SCVP Service\n");
		printf("\n * Repositories Location:\n");
		printf("     [caRepository] CA Certificate Repository\n");
		printf("     [httpCertRepository] HTTP Certificate Repository\n");
		printf("     [httpCrlRepository] HTTP CRL Repository\n");
		printf("     [crlRepository] Other CRL Repository\n");
		printf("     [deltaCrl] Delta CRL Base Address\n");
		printf("\n * Policy Pointers:\n");
		printf("     [certPolicy] Certificate Policy (CP)\n");
		printf("     [certPracticesStatement] Certificate CPS\n");
		printf("     [certLOAPolicy] Certificate LOA Policy\n");
		printf("     [certLOALevel] Certificate LOA Modifier\n");
		printf("\n * PKI Service Gateways:\n");
		printf("     [cmsGateway] CMS Gateway\n");
		printf("     [scepGateway] SCEP Gateway\n");
		printf("     [xkmsGateway] XKMS Gateway\n");
		printf("\n * HTML (Browsers) Services:\n");
		printf("     [htmlRequest] Certificate Request via HTML\n");
		printf("     [htmlRevoke] Certificate Revocation via HTML\n");
		printf("     [htmlRenew] Certificate Renewal via HTML\n");
		printf("     [htmlSuspend] Certificate Suspension via HTML\n");
		printf("\n * Grid Service Location:\n");
		printf("     [xkmsGateway] XKMS Gateway\n");
		printf("\n * PKI Basic Services Location:\n");
		printf("     [revokeCertificate] Certificate Revocation Service\n");
		printf("     [requestCertificate] Certificate Revocation Service\n");
		printf("     [suspendCertificate] Certificate Suspension Service\n");
		printf("\n * Extended Services Location:\n");
		printf("     [webdavCert] Webdav Certificate Validation Service\n");
		printf("     [webdavRev] Webdav Certificate Revocation Service\n");
		printf("\n");
		return(-1);
	}

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_DEBUG, NULL,
                        PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
                exit(1);
        }

	if((cacert = PKI_X509_CERT_get ( cacertfile )) == NULL ) {
		fprintf( stderr, "ERROR::Can not load the CA Cert (%s)!\n",
			cacert );
		return ( 1 );
	}

	if( url_s ) {
		printf("Retrieving Results from %s ... ", url_s );
	}

	if (( ret_sk = PKI_get_ca_service_sk( cacert, service, url_s )) != NULL ) {
		printf( "Ok.\n\nService Details:\n");
		for ( i=0; i < PKI_STACK_elements( ret_sk ); i++ ) {
			printf("[%d] %s at %s\n", i, service, 
					PKI_STACK_get_num( ret_sk, i ));
		}
	} else {
		printf("Error!\n\n");
		return (1);
	}

	printf("\nDone.");

	return(0);
}


