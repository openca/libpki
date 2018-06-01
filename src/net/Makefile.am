## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2014 by Massimiliano Pala and OpenCA Project
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
	dns.c \
	ldap.c \
	pg.c \
	pki_socket.c ssl.c \
	http_s.c \
	mysql.c \
	pkcs11.c \
	sock.c \
	url.c

noinst_LTLIBRARIES = libpki-net.la
libpki_net_la_SOURCES = $(SRCS)
libpki_net_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

