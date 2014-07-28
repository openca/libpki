# Simple Makefile for libPKI test application
# All it is needed for the developer is the availability
# of the configuration tool from libPKI package

LIBPKI_PREFIX="/usr"
CNF_TOOL="$(LIBPKI_PREFIX)/bin/libpki-config"

CFLAGS=`(bash $(CNF_TOOL) --cflags)`
LDFLAGS=`(bash $(CNF_TOOL) --libs)`
CC=gcc

SRCS = \
	prqp_client.c

SRCS2= \
	prqp_client_simple.c

all:
	@echo
	@echo -n "Build and Link prqp_client.c and prqp_client_simple.c ... " 
	@gcc $(CFLAGS) $(LDFLAGS) -o prqp_client $(SRCS) && \
			echo "Ok"
	@gcc $(CFLAGS) $(LDFLAGS) -o prqp_client_simple $(SRCS2) && \
			echo "Ok"
	@echo

run:
	@echo
	@echo "Running test ... "
	LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib  ./prqp_client \
		-cacert certs/openca_cacert.crt -connect localhost:830
	@echo

run:
	@echo
	@echo "Running test ... "
	LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib  ./prqp_client \
		-cacert certs/openca_cacert.crt -connect localhost:830 \
		-service timeStamping -service cmsGateway
	@echo

run2:
	@echo
	@echo "Running test ... "
	LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib  ./prqp_client \
		-cacert certs/openca_cacert2.crt -connect localhost:830 \
		-service cmsGateway:2 -service timeStamping:2 \
		-service tampUpdate
	@echo

simple:
	@echo
	@echo "Running test ... "
	LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib  ./prqp_client_simple \
		-cacert certs/openca_cacert.crt -service tampUpdate
	@echo

debug:
	@echo
	@[ -d "results" ] || mkdir results
	@echo "Debugging test ... "
	@LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib gdb ./test
	@echo

clean:
	rm -rf core prqp_client *.o results

