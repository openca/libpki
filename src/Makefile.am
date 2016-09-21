## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = .
-include $(TOP)/global-vars

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

SUBDIRS = . $(DRIVERS) $(CRYPTO_SRC_PREFIX) io net scep cms prqp lirt . $(TOOLS_AND_TESTS)

AM_CPPFLAGS = \
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
	support.c \
	profile.c \
	pki_config.c \
	extensions.c \
	pki_x509.c \
	pki_x509_mem.c \
	pki_x509_mime.c \
	pki_msg_req.c \
	pki_msg_resp.c

lib_LTLIBRARIES = libpki.la

libpki_la_SOURCES = $(SRCS)

libpki_la_LDFLAGS = \
	$(BUILD_LIBPKI_LDFLAGS) \
	-version-number "$(PACKAGE_VERSION)" \
	-version-info "$(INTERFACE_CURRENT):$(INTERFACE_REVISION):$(INTERFACE_AGE)"

libpki_la_CFLAGS   = $(BUILD_LIBPKI_CFLAGS) $(SYSTEM_CFLAGS)

libpki_la_LIBADD   = \
			$(CRYPTO_SRC_PREFIX)/libpki-openssl.la \
			drivers/libpki-token.la \
			io/libpki-io.la \
			net/libpki-net.la \
			cms/libpki-cms.la \
			scep/libpki-scep.la \
			prqp/libpki-prqp.la \
			lirt/libpki-lirt.la \
			$(BUILD_LIBPKI_LDADD)

bin_SCRIPTS = scripts/libpki-config

