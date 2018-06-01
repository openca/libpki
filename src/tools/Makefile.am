## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

BUILD_LIBPKI_CFLAGS	= -D__LIB_BUILD__ @pthread_opts@ @my_cflags@ @sys_cflags@
BUILD_LIBPKI_LDFLAGS	= @my_ldflags@ @rpath@
BUILD_LIBPKI_LDADD	= @my_ldadd@

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
	pki-siginfo \
	pki-lirt

PKI_TOOL = pki-tool.c
pki_tool_SOURCES = $(PKI_TOOL)
pki_tool_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_tool_LDADD = $(MYLDADD)
pki_tool_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

URL_TOOL = url-tool.c
url_tool_SOURCES = $(URL_TOOL)
url_tool_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
url_tool_LDADD = $(MYLDADD)
url_tool_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

XPAIR_TOOL = pki-xpair.c
pki_xpair_SOURCES = $(XPAIR_TOOL)
pki_xpair_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_xpair_LDADD = $(MYLDADD)
pki_xpair_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PRQP_TOOL = pki-query.c
pki_query_SOURCES = $(PRQP_TOOL)
pki_query_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_query_LDADD = $(MYLDADD)
pki_query_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

REQUEST_TOOL = pki-request.c
pki_request_SOURCES = $(REQUEST_TOOL)
pki_request_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_request_LDADD = $(MYLDADD)
pki_request_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PKI_CERT = pki-cert.c
pki_cert_SOURCES = $(PKI_CERT)
pki_cert_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_cert_LDADD = $(MYLDADD)
pki_cert_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PKI_CRL = pki-crl.c
pki_crl_SOURCES = $(PKI_CRL)
pki_crl_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_crl_LDADD = $(MYLDADD)
pki_crl_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PKI_DERENC = pki-derenc.c
pki_derenc_SOURCES = $(PKI_DERENC)
pki_derenc_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_derenc_LDADD = $(MYLDADD)
pki_derenc_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PKI_SIGINFO = pki-siginfo.c
pki_siginfo_SOURCES = $(PKI_SIGINFO)
pki_siginfo_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_siginfo_LDADD = $(MYLDADD)
pki_siginfo_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

PKI_LIRT = pki-lirt.c
pki_lirt_SOURCES = $(PKI_LIRT)
pki_lirt_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_lirt_LDADD = $(MYLDADD)
pki_lirt_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

# SCEP_TOOL = scep.c
# scep_SOURCES = $(SCEP_TOOL)
# scep_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
# scep_LDADD = -L../.libs -lpki
# scep_LDFLAGS = $(BUILD_LIBPKI_LIBS)

