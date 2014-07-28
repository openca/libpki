## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

PKI_TOOL = \
	pki-tool.c

URL_TOOL = \
	url-tool.c

XPAIR_TOOL = \
	pki-xpair.c

PRQP_TOOL = \
	pki-query.c

REQUEST_TOOL = \
	pki-request.c

SCEP_TOOL = \
	scep.c

PKI_CERT = \
	pki-cert.c

PKI_CRL = \
	pki-crl.c

PKI_DERENC = \
	pki-derenc.c

PKI_SIGINFO = \
	pki-siginfo.c

PKI_LIRT = \
	pki-lirt.c

INCLUDES = -I$(TOP)

# 	$(openssl_cflags) \
# 	$(libxml2_cflags) \
# 	$(COND_INCLUDES)

# MYLDFLAGS = $(RPATH)

MYLDADD = ../.libs/libpki.la

# bin_PROGRAMS = scep
# scep_SOURCES = $(MYSCEP) scep.c
# scep_LDADD   = $(OPENSSL_LIBS)
# scep_CFLAGS  = $(BUILD_LIBPKI_CFLAGS)


# noinst_LTLIBRARIES = libpki-scep.la
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

pki_tool_SOURCES = $(PKI_TOOL)
pki_tool_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_tool_LDADD = $(MYLDADD)
pki_tool_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

url_tool_SOURCES = $(URL_TOOL)
url_tool_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
url_tool_LDADD = $(MYLDADD)
url_tool_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_xpair_SOURCES = $(XPAIR_TOOL)
pki_xpair_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_xpair_LDADD = $(MYLDADD)
pki_xpair_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_query_SOURCES = $(PRQP_TOOL)
pki_query_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_query_LDADD = $(MYLDADD)
pki_query_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_request_SOURCES = $(REQUEST_TOOL)
pki_request_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_request_LDADD = $(MYLDADD)
pki_request_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_cert_SOURCES = $(PKI_CERT)
pki_cert_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_cert_LDADD = $(MYLDADD)
pki_cert_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_crl_SOURCES = $(PKI_CRL)
pki_crl_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_crl_LDADD = $(MYLDADD)
pki_crl_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_derenc_SOURCES = $(PKI_DERENC)
pki_derenc_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_derenc_LDADD = $(MYLDADD)
pki_derenc_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_siginfo_SOURCES = $(PKI_SIGINFO)
pki_siginfo_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_siginfo_LDADD = $(MYLDADD)
pki_siginfo_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

pki_lirt_SOURCES = $(PKI_LIRT)
pki_lirt_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
pki_lirt_LDADD = $(MYLDADD)
pki_lirt_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)

# scep_SOURCES = $(SCEP_TOOL)
# scep_CPPFLAGS = $(BUILD_LIBPKI_CFLAGS)
# scep_LDADD = -L../.libs -lpki
# scep_LDFLAGS = $(BUILD_LIBPKI_LIBS)

