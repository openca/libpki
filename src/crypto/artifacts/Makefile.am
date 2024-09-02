## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2024 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	pki_testing.c        \
	docsis/test_keys.c   \
	docsis/test_certs.c
	x9f/test_keys.c   \
	x9f/test_certs.c

noinst_LTLIBRARIES = libpki-testing.la
libpki_testing_la_SOURCES = $(SRCS)
libpki_testing_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

