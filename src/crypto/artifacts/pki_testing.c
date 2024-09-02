
/* OpenCA libpki package
 * (c) 2000-2012 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 *
 * ===================================================================
 * Released under OpenCA LICENSE
 */

#include <libpki/pki.h>

#ifdef HAVE_LIBRESOLV
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#ifndef T_AAAA
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>
#endif

// get_dnsRecords() - Returns an array of char * of requested records
// @name - requested domain name
// @type - Type of records. Supported types are:
//         T_A = 1 - Internet Address; 
//         T_NS = 2 - Name Server;
//         T_MX = 15 - Mail Routing;
//         T_TXT = 16 - Used for different purposes (SPF, etc.);
//         T_AAAA = 28 - IPv6 Addresses;
//         T_SRV = 33 - Service Records;
//         T_CERT = 36 - Certificates)
// @result - Returned Array. NULL if none are found.
//
// Return value is -1 on Error and 0 on success

/*! \brief Returns a MEM STACK with the requested DNS records */
PKI_MEM_STACK *URL_get_data_dns_url(const URL * url,
		                            ssize_t     size) {

	PKI_MEM_STACK *ret = NULL;

#ifdef HAVE_LIBRESOLV

	int type = T_A;
	PKI_MEM *obj = NULL;

	if( (!url) || (!url->addr)) {
		return NULL;
	}

	unsigned char response[NS_PACKETSZ];

	ns_msg dnsMessage;
	ns_rr dnsRecord;

	int dnsRecordSection = ns_s_an;
	int dns_msgCount = 0;
	int len = 0;

	// Check the Type of record
	if ((type = URL_get_dns_type(url->attrs)) == -1) return NULL;

	PKI_log_debug("DNS URI: Searching for %s (%s/%d)",
		url->addr, url->attrs, type);

	if ((len = res_search(url->addr, C_IN, type, response, sizeof(response))) < 0)
	{
		// An Error Occurred
		PKI_log_err("DNS URI: search failed\n");
		return NULL;
	}

	if (ns_initparse(response, len, &dnsMessage) < 0)
	{
		// This should not happen if the record is correct
		PKI_log_err("DNS URI: can not init DNS parsing of the dnsMessage\n");
		return NULL;
	}

	len = ns_msg_count(dnsMessage, dnsRecordSection);
	PKI_log_debug("DNS_URI: msg count ==> %d\n", len);

	if (len <= 0) return NULL;

	if((ret = PKI_STACK_MEM_new()) == NULL ) {
		PKI_log_debug ("DNS URI: Memory Failure");
		return NULL;
	}

	for (dns_msgCount = 0; dns_msgCount < len; dns_msgCount++)
	{
		PKI_log_debug("DNS URI: Retrieving DNS record #%d",dns_msgCount);

		if (ns_parserr(&dnsMessage, dnsRecordSection, dns_msgCount, &dnsRecord))
		{
			// ERROR: ns_parserr failed, let's continue to the next record
			PKI_log_err("DNS URI: Can not parse record %d of %d", dns_msgCount, len);
			continue;
		}

		PKI_log_debug("DNS URI: type = %d (req: %d)\n", ns_rr_type(dnsRecord), type);

		if (type == pki_ns_t_address)
		{
			switch (ns_rr_type(dnsRecord))
			{
				case T_A:
				case T_AAAA:
				case T_CNAME:
					break;
				default:
					continue;
			}
		}
		else if (type != ns_rr_type(dnsRecord))
		{
			PKI_log_debug("DNS URI: recived type %d is different from requested (%d)", 
				type, ns_rr_type(dnsRecord));
			// continue;
		}

		// int i = 0;
		int rv = 0;
		// int len = 0;
		int offset = 0;

		char dnsRecordName[MAXDNAME];

		memset(dnsRecordName, '\x0', MAXDNAME);
		// Parse the different types of DNS records
		if ((ns_rr_type(dnsRecord) == T_A) || (ns_rr_type(dnsRecord) == T_AAAA))
		{
			// These require Translation using IPv4/IPv6 functions
			int family = AF_INET;

			if (ns_rr_type(dnsRecord) == T_A) family = AF_INET;
			else family = AF_INET6;

			if(inet_ntop(family, ns_rr_rdata(dnsRecord), dnsRecordName, 
				sizeof(dnsRecordName)) == NULL)
			{
				// Can not convert
				continue;
			}
		}
		else if ((ns_rr_type(dnsRecord) == T_CNAME) || (ns_rr_type(dnsRecord) == T_MX) ||
			(ns_rr_type(dnsRecord) == T_NS))
		{
			if (ns_rr_type(dnsRecord) == T_MX) offset = NS_INT16SZ;

			rv = ns_name_uncompress(ns_msg_base(dnsMessage), ns_msg_end(dnsMessage),
				ns_rr_rdata(dnsRecord) + offset, dnsRecordName, MAXDNAME);

			// ERROR, can not uncompress the names
			if (rv < 0) continue;
		}
		else if (ns_rr_type(dnsRecord) == T_SRV)
		{
			// This requires special handling, the format is [SHORT][SHORT][SHORT][DATA]
			// unsigned short *pri = (unsigned short *) ns_rr_rdata(dnsRecord);
			// unsigned short *weight = (unsigned short *) &(ns_rr_rdata(dnsRecord)[2]);
			// unsigned short *port = (unsigned short *) &(ns_rr_rdata(dnsRecord)[4]);

			// Shall we return the additional data too ?
			// printf("PRI : %d\n", *pri);
			// printf("WEIGHT : %d\n", ntohs(*weight));
			// printf("PORT : %d\n", ntohs(*port));

			offset = 6;
			rv = ns_name_uncompress(ns_msg_base(dnsMessage), ns_msg_end(dnsMessage),
				ns_rr_rdata(dnsRecord) + offset, dnsRecordName, MAXDNAME);

			if (rv < 0) continue;
		}
		else if (ns_rr_type(dnsRecord) == T_TXT)
		{
			// Special handling required. Format is [BYTE][DATA]
			unsigned char *p = (unsigned char *)ns_rr_rdata(dnsRecord);

			snprintf(dnsRecordName, (size_t) *p+1, "%s", &ns_rr_rdata(dnsRecord)[1]);
		}
		else
		{
			PKI_log_debug("DNS URI: record type not supported [%d]", ns_rr_type(dnsRecord));
			continue;
		}

		if((obj = PKI_MEM_new_null()) == NULL ) {
			// Memory Allocation Error, we abort
			break;
		}

		if (strlen(dnsRecordName) > 0) {
			// If it is a printable value, we add the parsed version of the
			// record
			if(PKI_MEM_add(obj, (char *) dnsRecordName, strlen(dnsRecordName)) == PKI_ERR) {
				/* ERROR in memory growth */;
				PKI_log_err("DNS URI: Memory Allocation Error");
				break;
			}
		} else {
			// The value is not parsed/parsable, we return the raw data
			// the application should know what to do with the data!
			if(PKI_MEM_add(obj, (char *) ns_rr_rdata(dnsRecord), 
					ns_rr_rdlen(dnsRecord)) == PKI_ERR) {
				/* ERROR in memory growth */;
				PKI_log_err("DNS URI: Memory Allocation Error");
				break;
			}
		}

/*
		printf("MSG Data [%d]:\n", ns_rr_rdlen(dnsRecord));
		for (i=0; i < ns_rr_rdlen(dnsRecord); i++)
		{
			unsigned char *kk;

			kk = (unsigned char *) &ns_rr_rdata(dnsRecord)[i];
			printf("%x:", *kk);
		};
		printf("\n");

		fprintf(stderr, "DEBUG: RV => %d (err: %d, %s)\n", rv, h_errno, hstrerror(h_errno));
		fprintf(stderr, "DEBUG: name => %s (%s)\n", ns_rr_name(dnsRecord), url->addr);
		fprintf(stderr, "DEBUG: value => %s\n", dnsRecordName);
		fprintf(stderr, "DEBUG: type => %d\n", ns_rr_type(dnsRecord));
		fprintf(stderr, "DEBUG: class => %d\n", ns_rr_class(dnsRecord));
*/

		PKI_STACK_MEM_push(ret, obj);

		// PKI_log_debug("DNS URI: Added object #%d to stack", PKI_STACK_MEM_elements(ret));
	}

#endif

	return ret;
};

/*! \brief Returns the type of DNS records identified by the passed char * arg */
int URL_get_dns_type(const char *str) {

	int ret = -1;
	if (!str) return ret;

#ifdef HAVE_LIBRESOLV

	if (strncmp_nocase(str, "AAAA", 4) == 0) {
		ret = T_AAAA;
	} else if (strncmp_nocase(str, "A", 1) == 0) {
		ret = T_A;
	} else if (strncmp_nocase(str, "NS", 2) == 0) {
		ret = T_NS;
	} else if (strncmp_nocase(str, "MX", 2) == 0) {
		ret = T_MX;
	} else if (strncmp_nocase(str, "CNAME", 5) == 0) {
		ret = T_CNAME;
	} else if (strncmp_nocase(str, "SRV", 3) == 0) {
		ret = T_SRV;
	} else if (strncmp_nocase(str, "TXT", 3) == 0) {
		ret = T_TXT;
	} else if (strncmp_nocase(str, "CERT", 4) == 0) {
		ret = T_CERT;
	} else if (strncmp_nocase(str, "ANY", 3) == 0) {
		ret = T_ANY;
	} else if (atoi(str) > 0) {
		ret = atoi(str);
	} else {
		PKI_log_err("DNS URI: record type (%s) not supported.", str);
	}

	PKI_log_debug("DNS URI: record type (%s=%d) parsed", str, ret);
#else
  PKI_log_debug("DNS URI: dns support disabled at compile time");
#endif
	return ret;
}
