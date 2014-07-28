## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = .
include $(TOP)/global-vars

CRYPTO_SRC_PREFIX = openssl

EXTRA_DIST = \
	tests

# HSMS = $(HSM_SOFTWARE) $(HSM_KMF) $(HSM_OPENSSL_ENGINE)
DRIVERS = drivers

if LIBPKI_ENABLE_IPHONE
TOOLS_AND_TESTS =
else
TOOLS_AND_TESTS = tools tests
endif

SUBDIRS = $(DRIVERS) $(CRYPTO_SRC_PREFIX) scep prqp lirt . $(TOOLS_AND_TESTS)

INCLUDES = \
	-I$(top_srcdir)/src/libpki \
	$(COND_INCLUDES)
 
nobase_include_HEADERS = \
	libpki/*.h \
	libpki/net/*.h \
	libpki/io/*.h \
	libpki/scep/*.h \
	libpki/prqp/*.h \
	libpki/lirt/*.h \
	libpki/cms/*.h \
	libpki/openssl/*.h \
	libpki/drivers/*.h \
	libpki/drivers/openssl/*.h \
	libpki/drivers/engine/*.h \
	libpki/drivers/pkcs11/*.h \
	libpki/drivers/pkcs11/rsa/*.h \
	libpki/drivers/kmf/*.h

SRCS = \
	pki_init.c \
	stack.c \
	pki_mem.c \
	pki_cred.c \
	pki_err.c \
	pki_log.c \
	pki_threads_vars.c \
	pki_threads.c \
	token.c \
	token_id.c \
	token_data.c \
	net/url.c \
	net/sock.c \
	net/ssl.c \
	net/pki_socket.c \
	net/http_s.c \
	net/ldap.c \
	net/mysql.c \
	net/pg.c \
	net/pkcs11.c \
	net/dns.c \
	support.c \
	profile.c \
	pki_config.c \
	extensions.c \
	pki_x509.c \
	pki_x509_mem.c \
	pki_x509_mime.c \
	io/pki_x509_io.c \
	io/pki_keypair_io.c \
	io/pki_x509_req_io.c \
	io/pki_x509_cert_io.c \
	io/pki_x509_crl_io.c \
	io/pki_x509_xpair_io.c \
	io/pki_x509_pkcs7_io.c \
	io/pki_x509_p12_io.c \
	io/pki_ocsp_req_io.c \
	io/pki_ocsp_resp_io.c \
	cms/asn1.c \
	cms/cms_simple.c \
	cms/cms_cert_req.c \
	pki_msg_req.c \
	io/pki_msg_req_io.c \
	pki_msg_resp.c \
	io/pki_msg_resp_io.c

lib_LTLIBRARIES = libpki.la

libpki_la_SOURCES = $(SRCS)

libpki_la_LDFLAGS = \
	$(BUILD_LIBPKI_LDFLAGS) \
	-version-number "$(PACKAGE_VERSION)" \
	-version-info "$(INTERFACE_CURRENT):$(INTERFACE_REVISION):$(INTERFACE_AGE)"

#	-version-number "$(INTERFACE_CURRENT):$(INTERFACE_REVISION):$(INTERFACE_AGE)"

# -release "$(VERSION)"
# -version-info "$(INTERFACE_CURRENT):$(INTERFACE_REVISION):$(INTERFACE_AGE)"

libpki_la_CFLAGS   = $(BUILD_LIBPKI_CFLAGS) $(SYSTEM_CFLAGS)

libpki_la_LIBADD   = \
			$(CRYPTO_SRC_PREFIX)/libpki-openssl.la \
			drivers/libpki-token.la \
			scep/libpki-scep.la \
			prqp/libpki-prqp.la \
			lirt/libpki-lirt.la \
			$(BUILD_LIBPKI_LDADD)

bin_SCRIPTS = scripts/libpki-config

