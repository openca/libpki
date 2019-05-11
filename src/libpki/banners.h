// file: libpki/banners.h

#ifndef LIBPKI_VERSION_H
#include <libpki/libpkiv.h>
#endif

#ifndef HEADER_OPENSSLV_H
#include <openssl/opensslv.h>
#endif

#ifndef LIBPKI_HEADER_BANNERS_H
#define LIBPKI_HEADER_BANNERS_H

#ifdef  __cplusplus
extern "C" {
#endif

#define BOLD     "\x1B[1m"
#define NORM     "\x1B[0m"
#define BLACK    "\x1B[30m"
#define RED      "\x1B[31m"
#define GREEN    "\x1B[32m"
#define BLUE     "\x1B[34m"

#define BG       "\x1B[47m"
#define BG_BOLD  "\x1B[31;47m"
#define BG_NORM  "\x1B[30;47m"
#define BG_RED   "\x1B[31;47m"
#define BG_GREEN "\x1B[32;47m"
#define BG_BLUE  "\x1B[34;47m"

const char * libpki_banner;
const char * prog_banner;

#define LIBPKI_BANNER_PRINT(a) \
	fprintf(a, libpki_banner)

#define LIBPKI_BANNER_PRINT_STDOUT() fprintf(stdout, libpki_banner)

#define PROGRAM_BANNER_PRINT(filePointer, progName, version, year, copyright) \
	fprintf(filePointer, prog_banner, progName, version, year, copyright)

#define PROGRAM_BANNER_PRINT_STDOUT(progName, version, year, copyright) \
	fprintf(stdout, prog_banner, progName, version, year, copyright)

#ifdef  __cplusplus
}
#endif

#endif