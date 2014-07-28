# Simple Makefile for libPKI test application
# All it is needed for the developer is the availability
# of the configuration tool from libPKI package

LIBPKI_PREFIX="/usr"
CNF_TOOL="$(LIBPKI_PREFIX)/bin/libpki-config"

CFLAGS=`(bash $(CNF_TOOL) --cflags)`
LDFLAGS=`(bash $(CNF_TOOL) --libs)`
CC=gcc

test:
	@echo
	@echo -n "Building and Linking test.c ... " 
	@gcc $(CFLAGS) $(LDFLAGS) -o test test.c && echo "Ok" && make run
	@echo

run: test
	@echo
	@[ -d "results" ] || mkdir results
	@echo "Running test ... "
	@LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib ./test
	@echo

debug:
	@echo
	@[ -d "results" ] || mkdir results
	@echo "Debugging test ... "
	@LD_LIBRARY_PATH=$(LIBPKI_PREFIX)/lib gdb ./test
	@echo

clean:
	rm -rf core test *.o results

