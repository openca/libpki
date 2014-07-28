
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {
	PRQP_REQ *p = NULL;
	PRQP_RESP *r = NULL;
	BIO *bio = NULL;
	BIO *cert = NULL;
	URL *url = NULL;
	int i, error;

	PKI_STACK *sk_services = NULL;

	char *cacertfile = NULL;
	char *cacertissuerfile = NULL;
	char *clientcertfile = NULL;
	char *subject_s = NULL;
	char *serial_s = NULL;

	PRQP_init_all_services();

	sk_services = PKI_STACK_new_null();
	
	error = 0;
	for(i=1; i < argc; i++ ) {
		if( strcmp( argv[i], "-clientcert" ) == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			clientcertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-cacertissuer" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertissuerfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-cacert" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-serial") == 0 ) {
			if( argv[i+1] == NULL ) {
				error = 1;
				break;
			}
			serial_s = argv[++i];
		} else if ( strcmp ( argv[i], "-casubject") == 0 ) {
			if( argv[i+1] == NULL ) {
				error = 1;
				break;
			}
			subject_s = argv[++i];
		} else if ( strcmp ( argv[i], "-connect" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			url=getParsedUrl(argv[++i]);
		} else if ( strcmp ( argv[i], "-service" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			PKI_STACK_push( sk_services, argv[++i] );
		} else {
			printf("ERROR:Unreckognized parameter %s\n",
				argv[i]);
			error=1;
		}
	}

	/*
	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
                        PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
                exit(1);
        }
	*/

	if( !cacertfile && !subject_s && !clientcertfile ) {
		printf("\nERROR: one of -cacert, -casubject or -clientcert is needed!\n");
		error = 1;
	}

	if( error == 1 ) {
		printf("\nUSAGE: %s options\n\n", argv[0]);
		printf("Where options are:\n");
		printf(" -casubject <dn>      - Issuer's of the CA certificate DN (optional if certfile\n                       or cacertfile is provided)\n");
		printf(" -serial <num>        - Serial Number of the CA certificate (optional)\n");
		printf(" -cacert <file>       - Certificate to find CA services for (optional if\n                       issuer is provided)\n");
		printf(" -cacertissuer <file> - CA certificate to find serviced of (optional)\n");
		printf(" -clientcert <file>   - A certificate issued by the CA you are requesting\n                        information for\n");
		printf(" -service <id>[:ver]  - Service which URL is to be asked (optional, multiple\n                       accepted)\n");
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

	p = PRQP_REQ_new_url( cacertfile, cacertissuerfile, clientcertfile,
						subject_s, serial_s, NULL );

	if(!p ) {
		printf("%s::%d::ERROR::Cannot generate request!\n", 
				__FILE__, __LINE__ );
		return(-1);
	}

	for( i = 0; i < PKI_STACK_elements(sk_services); i++ ) {
		char *ss = NULL;
		int  nid = 0;
		char *ss2=NULL;
		ASN1_OBJECT *obj = NULL;
		// RESOURCE_IDENTIFIER *ri = NULL;

		ss = PKI_STACK_get_num( sk_services, i);
		if(PRQP_REQ_add_service( p, ss ) == PKI_ERR ) {
			fprintf( stderr, "ERROR::Can not add %s\n", ss );
		}
	}

	if( p ) {
		BIO *out = NULL;

		PRQP_REQ_print ( p );
		out = BIO_new_fp ( stderr, BIO_NOCLOSE );
		PEM_write_bio_PRQP_REQ( out, p );
		BIO_free ( out );
	}


	if ( url ) {
		r = PRQP_http_get_resp ( url, p, 0 );
		if( !r ) {
			fprintf( stderr, "ERROR::can not read response!\n");
		} else {
			BIO *st = NULL;

			printf("\r\n\r\n");

			PRQP_RESP_print ( r );

			st = BIO_new_fp ( stderr, BIO_NOCLOSE );
			PEM_write_bio_PRQP_RESP( st, r );
			BIO_free_all( st );
		}
	} else {
		PEM_write_bio_PRQP_REQ( bio, p );
	}
	if( bio ) BIO_free (bio);

	PRQP_REQ_free( p );

	return(0);

}


