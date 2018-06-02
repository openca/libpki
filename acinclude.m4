dnl Check for library paths and if static-dynamic linking is
dnl supported
AC_DEFUN([AC_CHECK_OPENSSL_PATH],
[
_package=OPENSSL
_version=$1
_prefix=$2
_dirs=$3
_arch=$4
_libs="crypto ssl"

library_prefix=
library_ldflags=
library_ldadd=
library_cflags=
library_path=
library_setup=no

if ! [[ "x${_prefix}" = "x" ]] ; then

   if [[ "x${_version}" = "x" ]] ; then
	_version=0.0.0
   fi

   if [[ -d "/opt/csw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=/opt/csw/lib/pkgconfig:$PKG_CONFIG_PATH
   fi

   if [[ -d "/usr/sfw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/sfw/lib/pkgconfig
   fi
	
   if [[ "$enable_shared" = "yes" ]] ; then
   ifdef([PKG_CHECK_MODULES],
	[
		if ! [[ x${HAS_PKGCONF} = x  ]]; then
			PKG_CHECK_MODULES( OPENSSL, openssl >= $_version, 
			[
            	AC_MSG_RESULT([ OPENSSL $_version or greater found via pkg-config])
                library_cflags=$OPENSSL_CFLAGS
                library_ldflags=$OPENSSL_LDFLAGS
                library_ldadd=$OPENSSL_LIBS
                library_prefix=$prefix

				if [[ "x$library_prefix" = "x" ]] ; then
					my_path=${library_libs#-L}
					my_path=`echo "${my_path}" | sed "s| .*||"`
					library_path=$my_path
		   		else
		   			library_path=$library_prefix/lib$_arch
		   		fi
            	library_setup=yes
			],
			[
				AC_MSG_RESULT( [good openssl not found via pkgconfig])
				library_setup=no
			])
            dnl End of PKG_CHECK macro
		fi
	],
	[
		## Skipping pkg-config macros...
		AC_MSG_RESULT( [ Skipping pkg-config macros ])
	])
	fi
fi

if [[ "$library_setup" = "no" ]] ; then
	if [[ "x${_prefix}" = "x" ]]; then
		_path=$_dirs
	else
		if [[ -d "$_prefix/lib$_arch" ]] ; then
			_path=$_prefix/lib$_arch
		else
			_path=$_prefix/lib
		fi
	fi

	_shared=0
	_static=0

	curr_arch=

	for _i in $_path; do

		AC_MSG_RESULT([OpenSSL Checking Path: $_i])

		if [[ "$library_setup" = "yes" ]] ; then
		 	break
		fi

		dnl curr_arch=$_arch

		dir=${_i%/lib}
		if ! [[ "$dir" = "$_i" ]] ; then
			curr_arch=
		else
			curr_arch=$_arch
		fi

		AC_MSG_RESULT([OpenSSL Current Arch: .............. $curr_arch])

		library_prefix=${_i%/lib${curr_arch}}
		if [[ "$library_prefix" = "$_i" ]] ; then
			library_prefix=${library_prefix%/include}
		fi
		library_includes=${library_prefix}/include/openssl/opensslv.h

		AC_MSG_RESULT([OpenSSL Library Prefix: $library_prefix])

		if ! [[ -f "$library_includes" ]] ; then
			AC_MSG_RESULT([OpenSSL Checking Path: ${library_includes} does not exists!])
			continue;
		fi;


		AC_MSG_RESULT([Searching OpenSSL Version: $library_includes]);
		ver=`grep "^ *# *define  *OPENSSL_VERSION_NUMBER" "$library_includes" | sed 's/.*0x/0x/g' | sed 's|\L||g'`;
		detected_v=`echo $((ver))`
		required_v=`echo $(($_version))`

		dnl ver=`grep "^ *# *define  *SHLIB_VERSION_NUMBER" $library_includes | sed 's/[#_a-zA-Z" ]//g' | sed 's|\.|0|g'`;
		dnl my_ver=`echo $_version | sed "s|\.|0|g"`;

		AC_MSG_RESULT([Detected Version: $ver (required > $_version )]);

		if [[ $detected_v -ge $required_v ]] ; then
			AC_MSG_RESULT([OpenSSL Version $ver: Ok.]);
			library_cflags="-I${library_prefix}/include"

			dnl if [[ -f "${library_prefix}/openssl/opensslv.h" ]] ; then
			dnl 	library_cflags="-I${library_prefix}"
			dnl else 
			dnl 	if [[ -f "${library_prefix}/include/openssl/opensslv.h" ]] ; then
			dnl 		library_cflags="-I${library_prefix}/include"
			dnl 	fi
			dnl fi
			AC_MSG_RESULT([OpenSSL CFlags: $library_cflags ($_shared)])

			dir="$library_prefix/lib${curr_arch}"

			dnl crypto_name="${dir}/libcrypto*.$shlext*"
			dnl ssl_name="${dir}/libssl*.$shlext*"
			_static=0

			AC_MSG_RESULT([OpenSSL: Looking for $crypto_name and $ssl_name])

			if [[ $_static -gt 0 ]] ; then
				ext_list="$libext";
			else
				ext_list="$shlext $shlext.* $libext";
			fi

			for ext in $ext_list ; do
				crypto_lib=`ls "${dir}/libcrypto.${ext}" | head -n 1`;
				ssl_lib=`ls "${dir}/libssl.${ext}" | head -n 1`;

				dnl crypto_lib=`find "${dir}" -name "libcrypto.${ext}" -type f -maxdepth 0 | head -n 1`;
				dnl ssl_lib=`find "${dir}" -name "libssl.${ext}" -type f -maxdepth 0 | head -n 1`;

				echo "CRYPTO => $crypto_lib";
				echo "SSL => $ssl_lib";

				if ! [[ "${crypto_lib}" = "${ssl_lib}" ]] ; then
					library_setup=yes
					library_ldflags="-L${dir}"
					if [[ "$ext_list" = "$libext" ]] ; then
						library_shared=no
						_static=1
					else
						library_shared=yes
						_static=0
					fi
					break;
				fi
			done

			if [[ "library_setup" = "yes" ]] ; then
				AC_MSG_RESULT([OpenSSL: Found Libs in ${dir} ... ${library_ldflags}])
				break;
			fi

			continue;

dnl	# for _i in $_path ; do

dnl		dnl if [[ "$library_setup" = "yes" ]] ; then
dnl		dnl 	break
dnl		dnl fi
dnl
dnl		_i=`echo ${_i} | sed 's| |\\ |g'`
dnl		crypto_so=`ls ${_i}/libcrypto.$shlext 2>/dev/null`
dnl		if [[ "x$crypto_so" = "x" ]] ; then
dnl			crypt_so=`ls ${_i}/libcrypto-*.shlext 2>/dev/null`
dnl		fi
dnl		ssl_so=`ls ${_i}/libssl.$shlext 2>/dev/null`
dnl		if [[ "x$ssl_so" = "" ]] ; then
dnl			ssl_so=`ls ${_i}/libssl-*.$shlext 2>/dev/null`
dnl		fi
dnl
dnl		for _k in $crypto_so ; do
dnl			crypto_so=$_k;
dnl		done
dnl
dnl		for _k in $ssl_so ; do
dnl			ssl_so=$_k
dnl		done
dnl
dnl		dnl AC_MSG_RESULT([*** DEBUG _i = ${_i}]);
dnl		dnl AC_MSG_RESULT([*** DEBUG crypto_so = $crypto_so]);
dnl		dnl AC_MSG_RESULT([*** DEBUG ssl_so = $ssl_so]);
dnl		dnl AC_MSG_RESULT([*** DEBUG arch = $myarch]);
dnl		dnl AC_MSG_RESULT([*** DEBUG shlext = $shlext]);
dnl
dnl		if ! [[ -z "${crypto_so}" ]] ; then
dnl			if ! [[ -z "${ssl_so}" ]] ; then
dnl				_shared=1
dnl				library_shared=yes
dnl				library_ldflags="-L${_i}"
dnl				library_ldadd="-lssl -lcrypto "
dnl				library_path=${_i}
dnl				library_prefix=${_i%/lib$_arch}
dnl				if [[ "x$library_prefix" = "x" ]] ; then
dnl					library_prefix=/
dnl				fi
dnl
dnl				library_setup=yes
dnl			fi
dnl		fi
dnl
dnl		if [[ "$enable_shared" = "no" ]] ; then
dnl			_library_setup=no
dnl			_library_shared=no
dnl			_shared=0
dnl		fi
dnl
dnl		if [[ $_shared -eq 0 ]] ; then
dnl			if [[ -r "${_i}/libcrypto.$libext" ]] ; then
dnl				if [[ -r "${_i}/libssl.$libext" ]] ; then
dnl					_static=1
dnl				fi
dnl			fi

dnl			if [[ $_static = 1 ]] ; then
dnl				library_shared=no
dnl				library_path=${_i}
dnl				library_prefix=${_i%/lib$_arch}
dnl				if [[ "x$library_prefix" = "x" ]] ; then
dnl					library_prefix=/
dnl				fi
dnl				dnl # if [[ -d "${library_prefix}/include" ]] ; then
dnl				dnl # 	library_cflags="-I${library_prefix}/include"
dnl				dnl # else
dnl				dnl # 	library_cflags="-I${library_prefix}"
dnl				dnl # fi
dnl				library_ldflags="-L${library_prefix}"
dnl				library_ldadd="-lcrypto -lssl "
dnl				dnl # library_ldflags="${_i}/libcrypto.$libext ${_i}/libssl.$libext"
dnl				if [[ "${enable_shared}" = "yes" ]] ; then
dnl					AC_MSG_RESULT([ *** WARNING: non-shared libs found, try using "--disable-shared" to use them])
dnl					continue;
dnl				fi
dnl
dnl				library_setup=yes
dnl				AC_MSG_RESULT([ *** DEBUG: lib setup ok $library_ldflags / $library_ldadd])
dnl				break
dnl			fi
dnl		fi

		else
			AC_MSG_RESULT([OpenSSL Version $ver: Too old, skipping.]);
			library_prefix=
			library_includes=
			library_setup=no
			library_shared=no
			continue;
		fi

dnl		# done
	done
fi

if ! [[ "$library_setup" = "no" ]] ; then

if test "$cross_compiling" = yes; then
	library_setup=yes
else

old_cflags=$CFLAGS
old_ldflags=$LDFLAGS
old_libs=$LIBS

export CFLAGS=$library_cflags
export LDFLAGS=$library_ldflags
export LIBS=$library_ldadd
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$library_path

dnl AC_MSG_RESULT([LD_LIBRARY_PATH=$library_path]);

AC_RUN_IFELSE([AC_LANG_SOURCE([
#include <openssl/x509.h>
int main(void) {
	X509 *x = NULL;
	return(0);
}])], [ ok=1 ], [ ok=0 ])

CFLAGS=$old_cflags
LDFLAGS=$old_ldflags
LIBS=$old_libs

if [[ $ok = 0 ]] ; then
	AC_MSG_ERROR([*** ERROR::Can not configure OPENSSL library!])
	library_shared=
	library_prefix=
	library_cflags=
	library_ldflags=
	library_ldadd=
	library_libs=
	library_setup=no
else
	AC_MSG_RESULT([Library OPENSSL prefix... $library_prefix ])
	AC_MSG_RESULT([Library OPENSSL is SHARED... $library_shared ])
	AC_MSG_RESULT([Library OPENSSL C flags... $library_cflags ])
	AC_MSG_RESULT([Library OPENSSL LD flags... $library_ldflags ])
	AC_MSG_RESULT([Library OPENSSL LIBS flags ... $library_libs ])
	library_setup=yes
fi

fi # End of Cross Compiling Check

fi # End of Library Setup 

])


dnl Check for extra support libraries and options 
AC_DEFUN([AC_CHECK_C_OPTION],
[ 
old_cflags=$CFLAGS
CFLAGS="$CFLAGS $1"

AC_MSG_CHECKING([checking for $1 support]);

AC_RUN_IFELSE([AC_LANG_SOURCE([
#include <stdlib.h>
int main(void)
{
        return(0);
}])], [ _supported=yes ], [ _supported=no])

if [[ $_supported = no ]] ; then
        AC_MSG_RESULT([not supported]);
	CFLAGS=$old_cflags
else
        AC_MSG_RESULT([yes]);
fi])

AC_DEFUN([AC_LDAP_VENDOR],
[
_prefix=$1


dnl old_cflgas="$CFLAGS"
dnl old_ldflags="$LDFLAGS"

dnl export CFLAGS="-I$_prefix/include"
dnl export LDFLAGS="-L$_prefix/lib -lldap"

dnl AC_MSG_RESULT([LDAP VENDOR ===> prefix = $_prefix])

AC_MSG_CHECKING([checking for ldap vendor]);

if ! [[ "$_prefix" = "" ]] ; then
	if $EGREP "Sun" "$_prefix/include/ldap.h" 2>&1 >/dev/null ; then
	AC_DEFINE(LDAP_VENDOR_SUN)
	AC_MSG_RESULT([yes])
	ldap_vendor="SUN"
   else
   	if $EGREP "OpenLDAP" "$_prefix/include/ldap.h" 2>&1 >/dev/null ; then
		AC_DEFINE(LDAP_VENDOR_OPENLDAP)
		ldap_vendor="OPENLDAP"
		library_ldflags=[-L$_prefix/lib]
		library_ldadd=[-lldap_r]
	else
		AC_MSG_ERROR([*** LDAP::No supported vendors found in ($_prefix)***])
	fi
   fi

	if [[ "$ldap_vendor" = "SUN" ]] ; then
    	ldap_lib=`ls "${_prefix}/lib/libldap.${shlext}" | head -n 1`;
		if [[ -z "$ldap_lib" ]] ; then
			AC_MSG_ERROR([*** LDAP: missing $_prefix/lib/libldap.$shlext!])
		fi
		library_ldflags=[-L$_prefix/lib]
		library_ldadd=[-lldap]
	fi

	library_prefix=$_prefix;
	library_cflags=[-I${_prefix}/include]

old_cflags=$CFLAGS
old_ldflags=$LDFLAGS
old_ldadd=$LDADD

CFLAGS=$library_cflags
LDFLAGS=$library_ldflags
LDADD=$library_ldadd

AC_MSG_RESULT([LDAP SEARCH: CFLAGS: $library_cflags])
AC_MSG_RESULT([LDAP SEARCH: LDFLAGS: $library_ldflags])
AC_MSG_RESULT([LDAP SEARCH: LDADD: $library_ldadd])

dnl AC_MSG_RESULT([LDAP VENDOR ===> searching for Sun])
   AC_EGREP_CPP( [Sun],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  	[
	   AC_DEFINE(LDAP_VENDOR_SUN)
	   ldap_vendor="SUN"
        ])

   if ! [[ "$ldap_vendor" = "SUN" ]] ; then
   	dnl AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
   	AC_EGREP_CPP( [OpenLDAP],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  		[
		   AC_DEFINE(LDAP_VENDOR_OPENLDAP)
   		   dnl AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
		   ldap_vendor="OPENLDAP"
		])
   fi

LDFLAGS=$old_ldflags
CFLAGS=$old_cflags
LDADD=$old_ldadd

else

   AC_MSG_RESULT([LDAP VENDOR ($_prefix) ===> searching for Sun])
   AC_EGREP_CPP( [Sun],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  	[
	   AC_DEFINE(LDAP_VENDOR_SUN)
	   ldap_vendor="SUN"
		library_ldadd="-lldap"
        ])

   if ! [[ "x$ldap_vendor" = "SUN" ]] ; then
   	AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
   	AC_EGREP_CPP( [OpenLDAP],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  		[
		   AC_DEFINE(LDAP_VENDOR_OPENLDAP)
		   ldap_vendor="OPENLDAP"
			library_ldadd="-lldap_r"
		])
   fi
fi

   AC_MSG_RESULT([LDAP VENDOR: $ldap_vendor]);

])

AC_DEFUN([CHECK_EC], [
ossl_prefix=$1

if [[ "$cross_compiling" = yes ]]; then
	activate_ecdsa=yes
else
	_path=${ossl_prefix%/include}
	includes=${_path}/include/openssl


	if ! [[ -f "$includes/ec.h" ]] ; then
		AC_MSG_RESULT([OpenSSL EC: Missing Support for EC ($includes/ec.h)])
		activate_ecdsa=no;
	else
		activate_ecdsa=yes;

		files="$includes/opensslconf.h $includes/opensslconf-*.h"
		for i in files ; do
			AC_MSG_RESULT([OpenSSL EC/ECDSA: Checking support in $i])
			if [[ -f "$i" ]] ; then
				if $EGREP "define OPENSSL_NO_EC" "$i" 2>&1 >/dev/null ; then
					AC_MSG_RESULT([OpenSSL EC: Support disabled in $i])
					activate_ecdsa=no
					break
				fi
				if $EGREP "define OPENSSL_NO_ECDSA" "$i" 2>&1 >/dev/null ; then
					AC_MSG_RESULT([OpenSSL ECDSA: Support disabled in $i])
					activate_ecdsa=no
					break
				fi
			fi
		done
	fi

	AC_MSG_RESULT([OpenSSL Support for EC/ECDSA: ............ $activate_ecdsa])
fi

])

dnl AC_DEFUN(CHECKEC,
dnl [ 
dnl _path=$1
dnl 
dnl if [[ "$cross_compiling" = yes ]]; then
dnl 	activate_ecdsa=yes
dnl else
dnl 
dnl 	_path=${_path%/include}
dnl 	includes=${path}/include/openssl
dnl 
dnl 	if ! [[ -f "$includes/ec.h" ]] ; then
dnl 		activate_ecdsa=no;
dnl 	else
dnl 		activate_ecdsa=yes;
dnl 
dnl 		files="$includes/opensslconf.h $includes/opensslconf-*.h"
dnl 		for i in files ; do
dnl 			if [ -f "$i" ]] ; then
dnl 				if $EGREP "define OPENSSL_NO_EC" "$i" 2>&1 >/dev/null ; then
dnl 					AC_MSG_RESULT([OpenSSL ECDSA: Support disabled in $i])
dnl 					activate_ecdsa=no
dnl 				fi
dnl 			fi
dnl 		done
dnl 	fi
dnl fi
dnl ])

dnl AC_RUN_IFELSE( [
dnl #include <openssl/ec.h>
dnl #include <openssl/ecdsa.h>
dnl #include <openssl/opensslconf.h>
dnl int main(void)
dnl {
dnl #ifdef OPENSSL_NO_EC
dnl -garbage!
dnl #endif
dnl 	EC_KEY *d = NULL;
dnl 	return(0);
dnl }], [ 
dnl 	AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
dnl 	activate_ecdsa=yes
dnl ], [activate_ecdsa=no])
dnl fi

dnl if [[ "$activate_ecdsa" = "no" ]] ; then
dnl 	AC_MSG_RESULT([checking for OpenSSL ECDSA support ... no])
dnl 	AC_MSG_ERROR(
dnl [*** ECDSA support]
dnl [*** missing support for ECDSA, please update OpenSSL version]
dnl )
dnl else
dnl 	AC_MSG_RESULT([OpenSSL ECDSA support    : yes]);
dnl fi

AC_DEFUN([AC_OPENSSL_OCSP],
[ AC_RUN_IFELSE([ AC_LANG_SOURCE([
#include <openssl/ocsp.h>
int main(void)
{
	OCSP_CERTID *cid = NULL;
	return(0);
}])], [ AC_DEFINE(HAVE_OCSP) ], [ocsp_error=1])

if [[ ocsp_error = 1 ]] ; then
	AC_MSG_RESULT([checking for OpenSSL OCSP support ... no])
	AC_MSG_ERROR(
[*** OCSP support]
[*** missing support for ocsp, please update OpenSSL version]
[*** to 0.9.7 (or SNAPs). More info on http://www.openssl.org]
)
else
	AC_MSG_RESULT([OpenSSL OCSP support    : yes]);
fi])

AC_DEFUN([AC_OPENSSL_VERSION],
[ AC_EGREP_HEADER( [\#define\sOPENSSL_VERSION_NUMBER\s0x],
	[ $openssl_prefix/include/openssl.h ],
	[ openssl_ver="0.9.8+"], 
    	[ openssl_ver="0.9.7"]
)

if [[ $openssl_ver = "0.9.8+" ]] ; then
	AC_DEFINE(OPENSSL_VER_00908000)
else
	AC_DEFINE(OPENSSL_VER_00907000)
fi
	AC_MSG_RESULT([OpenSSL Detected Version: $openssl_ver])
])

AC_DEFUN([AC_GCC_CHECK_PRAGMA_IGNORED],
[ AC_RUN_IFELSE([ AC_LANG_SOURCE([
#include <stdio.h>
#pragma GCC diagnostic ignored "-Wconversion"
int main(void)
{
	return(0);
}
])],[ AC_DEFINE(HAVE_GCC_PRAGMA_IGNORED, 1, [GCC pragma ignored]) ], [])

])

AC_DEFUN([AC_GCC_CHECK_PRAGMA_POP],
[ AC_RUN_IFELSE([ AC_LANG_SOURCE([
#include <stdio.h>
#pragma GCC diagnostic ignored "-Wconversion"
int main(void)
{
	return(0);
}
#pragma GCC diagnostic pop
])], [ AC_DEFINE(HAVE_GCC_PRAGMA_POP, 1, [GCC pragma pop]) ], [])

])

