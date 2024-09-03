## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)
PRQP_VERSION = 0.1.0

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

PRQP_SRCS = \
	asn1_req.c \
	asn1_res.c \
	http_client.c \
	prqp_lib.c \
	prqp_bio.c \
	prqp_req_io.c \
	prqp_resp_io.c \
	prqp_srv.c

noinst_LTLIBRARIES = libpki-prqp.la
libpki_prqp_la_SOURCES = $(PRQP_SRCS)
libpki_prqp_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)
# libpki_prqp_la_LIBADD = $(OPENSSL_LIBS) 

