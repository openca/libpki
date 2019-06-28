## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

LIBPKI_MYCFLAGS	 = -D__LIB_BUILD__ -I$(TOP) @pthread_opts@ @my_cflags@ @sys_cflags@
LIBPKI_MYLDFLAGS = @my_ldflags@ @rpath@

AM_CPPFLAGS = -I$(TOP)
MYLDADD = ../.libs/libpki.la

bin_PROGRAMS   = \
	pki-tool \
	url-tool \
	pki-xpair \
	pki-query \
	pki-request \
	pki-cert \
	pki-crl \
	pki-derenc \
	pki-siginfo

PKI_TOOL = pki-tool.c
pki_tool_SOURCES = $(PKI_TOOL)
pki_tool_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_tool_LDADD = $(MYLDADD)
pki_tool_LDFLAGS = $(LIBPKI_MYLDFLAGS)

URL_TOOL = url-tool.c
url_tool_SOURCES = $(URL_TOOL)
url_tool_CPPFLAGS = $(LIBPKI_MYCFLAGS)
url_tool_LDADD = $(MYLDADD)
url_tool_LDFLAGS = $(LIBPKI_MYLDFLAGS)

XPAIR_TOOL = pki-xpair.c
pki_xpair_SOURCES = $(XPAIR_TOOL)
pki_xpair_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_xpair_LDADD = $(MYLDADD)
pki_xpair_LDFLAGS = $(LIBPKI_MYLDFLAGS)

PRQP_TOOL = pki-query.c
pki_query_SOURCES = $(PRQP_TOOL)
pki_query_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_query_LDADD = $(MYLDADD)
pki_query_LDFLAGS = $(LIBPKI_MYLDFLAGS)

REQUEST_TOOL = pki-request.c
pki_request_SOURCES = $(REQUEST_TOOL)
pki_request_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_request_LDADD = $(MYLDADD)
pki_request_LDFLAGS = $(LIBPKI_MYLDFLAGS)

PKI_CERT = pki-cert.c
pki_cert_SOURCES = $(PKI_CERT)
pki_cert_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_cert_LDADD = $(MYLDADD)
pki_cert_LDFLAGS = $(LIBPKI_MYLDFLAGS)

PKI_CRL = pki-crl.c
pki_crl_SOURCES = $(PKI_CRL)
pki_crl_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_crl_LDADD = $(MYLDADD)
pki_crl_LDFLAGS = $(LIBPKI_MYLDFLAGS)

PKI_DERENC = pki-derenc.c
pki_derenc_SOURCES = $(PKI_DERENC)
pki_derenc_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_derenc_LDADD = $(MYLDADD)
pki_derenc_LDFLAGS = $(LIBPKI_MYLDFLAGS)

PKI_SIGINFO = pki-siginfo.c
pki_siginfo_SOURCES = $(PKI_SIGINFO)
pki_siginfo_CPPFLAGS = $(LIBPKI_MYCFLAGS)
pki_siginfo_LDADD = $(MYLDADD)
pki_siginfo_LDFLAGS = $(LIBPKI_MYLDFLAGS)

