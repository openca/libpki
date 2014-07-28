## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

if STATIC_COMPILE
# testLDFLAGS=-L../.libs $(LIBPKI_LIBS) -lpki
testLDFLAGS=$(BUILD_LIBPKI_LDFLAGS)
testLDADD=../libpki.la ../openssl/libpki-openssl.la
else
# testLDFLAGS=-L../.libs $(LIBPKI_LIBS) -lpki
testLDFLAGS=$(BUILD_LIBPKI_LDFLAGS)
testLDADD=../libpki.la ../openssl/libpki-openssl.la
endif

SUBDIRS =

EXTRA_DIST =

check_PROGRAMS = \
	test1 \
	test2 \
	test3 \
	test4 \
	test5 \
	test6 \
	test7 \
	test8 \
	test9

test1_SOURCES = test1.c
test1_LDFLAGS = $(testLDFLAGS)
test1_LDADD   = $(testLDADD)
test1_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test2_SOURCES = test2.c
test2_LDFLAGS = $(testLDFLAGS)
test2_LDADD   = $(testLDADD)
test2_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test3_SOURCES = test3.c
test3_LDFLAGS = $(testLDFLAGS)
test3_LDADD   = $(testLDADD)
test3_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test4_SOURCES = test4.c
test4_LDFLAGS = $(testLDFLAGS)
test4_LDADD   = $(testLDADD)
test4_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test5_SOURCES = test5.c
test5_LDFLAGS = $(testLDFLAGS)
test5_LDADD   = $(testLDADD)
test5_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test6_SOURCES = test6.c
test6_LDFLAGS = $(testLDFLAGS)
test6_LDADD   = $(testLDADD)
test6_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test7_SOURCES = test7.c
test7_LDFLAGS = $(testLDFLAGS)
test7_LDADD   = $(testLDADD)
test7_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test8_SOURCES = test8.c
test8_LDFLAGS = $(testLDFLAGS)
test8_LDADD   = $(testLDADD)
test8_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS)

test9_SOURCES = test9.c
test9_LDFLAGS = $(testLDFLAGS)
test9_LDADD   = $(testLDADD)
test9_CFLAGS = -I$(TOP) $(LIBPKI_CFLAGS) -ggdb
