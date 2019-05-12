#include <libpki/banners.h>

// LibPKI Specific Banner
const char * libpki_banner = 
	"\n   " BOLD "OpenCA PKI Library " NORM "(" LIBPKI_VERSION_TEXT ")\n" 
	"   (c) 2008-" LIBPKI_BUILD_DATE_YEAR_TEXT " by " BOLD "Massimiliano Pala" NORM
			" and " BOLD BLUE "Open" RED "CA" NORM BOLD " Labs\n" NORM
//	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software\n\n"
	"       [ Built with " OPENSSL_VERSION_TEXT " from " BOLD BLACK "Open" RED "SSL" NORM " ]\n\n";

// Generic Banner for Any Programs
const char * prog_banner =
	"\n   " BOLD "%s " NORM "(%s)\n"
	"   (c) %d by " BOLD "%s" NORM "\n"
	"       [ Built with " LIBPKI_VERSION_TEXT " " LIBPKI_BUILD_DATE_TEXT_PRETTY " from " BOLD BLUE "Open" RED "CA" NORM " Labs ]\n"
	"       [ Built with " OPENSSL_VERSION_TEXT " from " BOLD BLACK "Open" RED "SSL" NORM " ]\n\n";
