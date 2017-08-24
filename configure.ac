AC_REVISION($Revision: 1.19 $)

AC_COPYRIGHT([Copyright 2007-2017 by Massimiliano Pala and OpenCA Labs])
# AC_CONFIG_SUBDIRS(src/core/openca.c)

dnl Autoconf
AC_INIT(libpki, 0.9.0, [libpki-users@lists.sourceforge.net], [libpki])
AC_PREREQ(2.13)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])

dnl Release Subversion (for binary packages)
RC=1
AC_SUBST(RC)

dnl Set Version Numbers
# PACKAGE_NAME="libpki"
TODAY=`/bin/date +%Y%m%d`

AC_SUBST(TODAY)

mybits="32"
mybits_install=""
is_sparc="no"
is_aix="no"
my_arch=`uname -m`

case "$my_arch" in
  *i686)
    mybits="32"
    ;;
  *i386)
    mybits="32"
    ;;
  *86_64)
    mybits="64"
    mybits_install="64"
    ;;
  *sparc*)
    mybits="64"
    mybits_install="64"
    is_sparc="yes"
    ;;
  *aix*)
    mybits="64"
    mybits_install="64"
    is_aix="yes"
    ;;
  *powerpc*)
    mybits="64"
    mybits_install="64"
    is_aix="yes"
    ;;
  *)
    AC_MSG_ERROR([Not supported arch ($my_arch)])
    ;;
esac

if [[ "$mybits" = "64" ]] ; then
  AC_DEFINE(ENABLE_ARCH_64, 1, [Forces 64bits builds])
else
  AC_DEFINE(ENABLE_ARCH_32, 1, [Forces 32bits builds])
fi

AC_SUBST(mybits)

v=$PACKAGE_VERSION
dnl v=`cat IFACE_VERSION`

revision=`echo $v | sed -e 's|[[0-9]]\.[[0-9]]\.[[0-9]]\.||'`
v=`echo ${v%.${revision}}`

minor=`echo $v | sed -e 's|[[0-9]]\.[[0-9]].||'`
tmp=`echo $v | sed -e 's|[[0-9]]\.[[0-9]]*||'`
major=`echo ${v%.$minor} | sed -e 's|^0*||' | sed -e 's|\.||g'`

let "iface_version=$major * 10 + $minor"

# Most Recent Implemented Interface
iface_current=$iface_version

# Implementation number of the current interface
iface_revision=$iface_current

# Oldest Interface Supported
iface_oldest=80

# Range of supported interfaces (current - oldest)
let "iface_age=$iface_current - $iface_oldest"

#iface_version="$iface_current$iface_revision"
dnl export iface_version

dnl AC_MESSAGE([>>>>>>>>> let "iface_version=${iface_current} + ${iface_revision} + ${iface_age}" ])
dnl let "iface_version=${iface_current} + ${iface_revision} + ${iface_age}"

# if [[ "x$iface_age" = "x$v" ]] ; then
# 	iface_age=0
# fi

AC_SUBST(iface_current)
AC_SUBST(iface_revision)
AC_SUBST(iface_age)
AC_SUBST(iface_version)

# Checks for header files.

dnl #### For iPhone Support we use the special gcc from Apple ###############
dnl enable_iphone_build=no

AC_ARG_ENABLE(iphone,
	AC_HELP_STRING( [--enable-iphone],
		[enable iPhone build support ( default is yes)]),
		iphone_build=$enableval, iphone_build=no )

AC_ARG_WITH(sdk,
	AC_HELP_STRING( [--with-sdk=LIBPREFIX],
			[uses the iPhone SDK (default is 5.0)]),
			sdkver=$withval, sdkver=5.0 )
AC_SUBST(sdkver)

AC_ARG_ENABLE(extra-checks,
	AC_HELP_STRING( [--enable-extra-checks=LIBPREFIX],
		[enables extra compile-time checks (GCC) (for devel only)]),
			extra_checks=$enableval, extra_checks=no )
AC_SUBST(extra_checks)

enable_rpath=yes

# Export variables to prevent autoconf to use rpl_malloc instead
# of malloc (it won't link properly otherwise!) - needed for iPhone
# build (cross compiling)
jm_cv_func_working_malloc=yes
ac_cv_func_malloc_0_nonnull=yes

if [[ "x$iphone_build" = "xyes" ]] ; then
	AC_MSG_RESULT([*** WARNING: iPhone Development Selected])
	AC_MSG_RESULT([***          Selected SDK is ${sdkver}])

	iphone_dev=/Developer/Platforms/iPhoneOS.platform/Developer
	iphone_sdk=$iphone_dev/SDKs/iPhoneOS${sdkver}.sdk
	iphone_include=$iphone_sdk/usr/include
	iphone_bin=$iphone_dev/usr/bin
	default_path=$iphone_bin
	build_os=arm-apple-iphone
	if ! [[ "$host" = "arm-apple-darwin" ]] ; then
		AC_MSG_RESULT([*** ERROR: Please add the '--host=arm-apple-darwin' option (now used '$host') *** ])
	fi

	CC=$iphone_bin/arm-apple-darwin9-gcc-4.0.1
	CC=$iphone_bin/arm-apple-darwin10-llvm-gcc-4.2
	dnl CPP=$iphone_bin/arm-apple-darwin9-g++-4.0.1
	CFLAGS="-arch armv6 -bundle -isysroot $iphone_sdk -miphoneos-version-min=2.0"
	dnl CXX=$iphone_bin/arm-apple-darwin9-g++-4.0.1
	CXX=$iphone_bin/arm-apple-darwin10-llvm-g++-4.2
	CXXFLAGS="-arch armv6 -bundle -isysroot $iphone_sdk -miphoneos-version-min=2.0 -std=c99"
	LDFLAGS="-dead_strip -framework Foundation -framework UIKit -dynamic"
	CPPFLAGS="$CFLAGS"
	enable_rpath="no"
else
	jm_cv_func_working_malloc=yes
	ac_cv_func_malloc_0_nonnull=yes
fi

AC_CANONICAL_SYSTEM

dnl AC_CONFIG_SRCDIR([src/drivers/openssl/pki_x509.c])

dnl ifdef ([LT_INIT], [LT_INIT],[AC_PROG_LIBTOOL])
AC_PROG_LIBTOOL

AC_PROG_EGREP

CPU=`uname -p`
AC_SUBST(CPU)

AM_INIT_AUTOMAKE([subdir-objects])

myarch=

dnl Select OS specific versions of source files.
rpath_opt="-Wl,-rpath -Wl,"
rpath=
shlext=so
dnl enable_shared=yes
case "${build_os}" in
 *linux*) 
		myarch=linux
		shlext=so
		;;
 *bsd*) myarch=bsd
		shlext=so
		;;
 *iphone*)
		myarch=iphone
		shlext=dylib
		;;
 *darwin*)
		myarch=darwin
		shlext=dylib
		mybits_install=""
		;;
 *sun*) myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *solaris*)
		myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *hpux*)        myarch=hpux
		shlext=so
		;;
 *aix*)
    myarch=aix
		shlext=so
		;;
 *) AC_MSG_ERROR([Operating system ${build_os} not supported]) ;;
esac

arch_target=

case "$target" in
	i*86-*)
		arch_target=x86
		;;
	x86_64-*)
		arch_target=x86_64
		;;
	sparc*-*)
		arch_target=Sparc
		;;
	powerpc*-*)
		arch_target=PowerPC
		;;
	*sparc*solaris*)
		arch_target=Sparc
		;;
	*arm*)
		arch_target=armv6
		;;
	*)
		[ `uname -p` ] && arch_target=`uname -p` || \
			arch_target="Unknown" ;;
esac

AC_SUBST(shlext)
AC_SUBST(arch_target)
AC_SUBST(myarch)
AC_SUBST(mybits_install)

AM_CONDITIONAL(LIBPKI_ARCH_LINUX, test x$myarch = xlinux)
AM_CONDITIONAL(LIBPKI_ARCH_BSD, test x$myarch = xbsd)
AM_CONDITIONAL(LIBPKI_ARCH_OSX, test x$myarch = xdarwin)
AM_CONDITIONAL(LIBPKI_ARCH_SOLARIS, test x$myarch = xsolaris)
AM_CONDITIONAL(LIBPKI_ARCH_HPUX, test x$myarch = xhpux)
AM_CONDITIONAL(LIBPKI_ARCH_AIX, test x$myarch = xaix)
AM_CONDITIONAL(LIBPKI_ENABLE_IPHONE, test x$enable_iphone = xyes)

if [[ "x$myarch" = "xsolaris" ]] ; then
	DIST_VERSION=`uname -r`
else
	if [[ -f "/etc/issue" ]] ; then
	   DIST_VERSION=`$EGREP -o [[0-9.]]+ /etc/issue | head -n 1`
	else
	   DIST_VERSION=`echo ${build_os} | $EGREP -o [[0-9.]]+`
	fi
fi

AC_SUBST(DIST_VERSION)

if [[ -f "/etc/issue" ]] ; then
   DIST_NAME=`head -n 1 /etc/issue | cut -f 1,1 -d ' '`
else
   DIST_NAME=`echo ${build_os} | $EGREP -o [[A-Za-z]]+`
fi

AC_SUBST(DIST_NAME)

default_path=$PATH
if [[ "x$is_sparc" = "xyes" ]] ; then
  AC_PATH_PROG(CC, CC, , $default_path)
  AC_PATH_PROG(CXX, CC, , $default_path)
fi

if [[ "x$is_aix" = "xyes" ]] ; then
  AC_PATH_PROG(CC, cc, , $default_path)
  AC_PATH_PROG(CXX, cc, , $default_path)
  arch_opt="-q"
  ar_opt="-X$mybits"
fi

AC_PATH_PROG(MAKE, make, , $default_path)
AC_PATH_PROG(AR, ar, , $default_path)
AR="$AR $ar_opt"

if [[ "x$iphone_build" = "xno" ]] ; then
	AC_MSG_RESULT([Not an iPhone Build])
	AM_PROG_CC_C_O
fi

AM_MAINTAINER_MODE

dnl Check for install program
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
AC_PROG_MAKE_SET

dnl Automatically update the libtool script if it becomes out-of-date.
AC_SUBST(LIBTOOL_DEPS)

dnl Setup dist stuff
AC_SUBST(ac_aux_dir)

AC_CHECK_LIB(c, calloc,
        [ AC_DEFINE(HAVE_CALLOC, 1, [Calloc in C library])],
        [ AC_MSG_RESULT([no calloc was found]) ]
)

if [[ "x$iphone_build" = "xno" ]] ; then
	dnl check for libraries
	dnl AC_CHECK_LIB(nsl, gethostbyname)
	dnl AC_CHECK_LIB(socket, socket)
	dnl AC_CHECK_LIB(resolv, res_query)

	AC_HEADER_STDC
	AC_HEADER_SYS_WAIT
	AC_CHECK_HEADERS([stdlib.h string.h sys/socket.h syslog.h])

	# Checks for the POSIX.1-2001 net includes
	AC_CHECK_HEADERS([sys/select.h])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero memset setenv socket strcasecmp strchr strrchr strstr])

old_cflags="$CFLAGS"

dnl check for stack protection of gcc
if [[ "$CC" = "gcc" ]] ; then
	AC_CHECK_C_OPTION(-fstack-check)
	AC_CHECK_C_OPTION(-maccumulate-outgoing-args)
	AC_CHECK_C_OPTION(-Werror)
	AC_CHECK_C_OPTION(-Wfatal-errors)
	if [[ "x${extra_checks}" = "xyes" ]] ; then
		AC_CHECK_C_OPTION(-Wall)
		AC_CHECK_C_OPTION(-Wmissing-field-initializers)
		AC_CHECK_C_OPTION(-Wmissing-parameter-type)
		AC_CHECK_C_OPTION(-Wtype-limits)
		AC_CHECK_C_OPTION(-Wuninitialized)
		AC_CHECK_C_OPTION(-Wconversion)
		AC_CHECK_C_OPTION(-fsanitize=address)
	fi

	if [[ "$DIST_NAME" = "darwin" ]] ; then
		AC_CHECK_C_OPTION(-Wno-deprecated)
		AC_CHECK_C_OPTION(-Wno-unknown-pragmas)
	fi

	AC_GCC_CHECK_PRAGMA_IGNORED
	AC_GCC_CHECK_PRAGMA_POP

	dnl AC_CHECK_C_OPTION(-m64)
	dnl AC_CHECK_C_OPTION(-rdynamic)
	dnl AC_CHECK_C_OPTION(--export-dynamic)
	dnl AC_CHECK_C_OPTION(--export-all-symbols)
fi

EXTRA_CFLAGS=$CFLAGS
CFLAGS="$old_cflags"

dnl Check for package and related programs
AC_PATH_PROG(DATE, date)
AC_PATH_PROG(CHMOD, chmod)
AC_PATH_PROG(PKGMK, pkgmk)
AC_PATH_PROG(RPM, rpm)
if test -n "${PKGMK}"
then
        PKGMK=package
else
        if test -n "${RPM}"
        then
                PKGMK=rpm
        fi
fi
AC_SUBST(PKGMK)
AC_PATH_PROG(PERL, perl)
AC_SUBST(PERL)

dnl ============================ Pthread Support =======================

AC_CHECK_LIB(pthread, pthread_create,
        [ AC_DEFINE(HAVE_LIBPTHREAD, 1, [PTHREAD Library])],
        [ AC_MSG_ERROR([pthread library is needed!]) ]
)

pthread_opts=""
AC_MSG_RESULT([Detecting pthread cflags ... ])
AC_TRY_COMPILE( [
#include <sys/types.h>
#include <pthread.h>],
[ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;]
[ return (0); ],
[ pthread_rw=yes ] , 
[ pthread_rw=no ] )

if [[ x"$pthread_rw" = xno ]] ; then
	AC_MSG_RESULT([Detecting pthread cflags (2) ... ])
	AC_TRY_COMPILE([
#define _BSD_SOURCE
#define _XOPEN_SOURCE 500
#define __USE_UNIX98
#include <sys/types.h>
#include <pthread.h>] ,
[ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;]
[ return (0); ],
[ pthread_rw=yes ] , [ pthread_rw=no ])

	if test x"$pthread_rw" = xyes ; then
		pthread_opts="-D_BSD_SOURCE -D_XOPEN_SOURCE=500 -D__USE_UNIX98"
	fi
fi

if [[ x"$pthread_opts" = x ]] ; then
	AC_MSG_RESULT([pthread cflags ... none])
else
	AC_MSG_RESULT([pthread cflags ... $pthread_opts])
fi

AC_SUBST(pthread_opts)

if [[ x"$pthread_rw" = xyes ]] ; then
	AC_DEFINE(HAVE_PTHREAD_RWLOCK, 1, [HAVE_PTHREAD_RWLOCK])
fi

dnl ================= enable package building specific option ================

AC_ARG_WITH( package-prefix,
   [  --with-package-prefix=DIR         installed package prefix directory],
   [ package_prefix_cnf=$withval ] , [ package_prefix_cnf= ] )

if ! [[ "x$package_prefix_cnf" = "x" ]] ; then
	package_prefix=$package_prefix_cnf
else if [[ "x$prefix" = "xNONE" ]] ; then
		prefix=/usr
		package_prefix=${prefix}
	else
		package_prefix=${prefix}
	fi
fi

AC_ARG_WITH( libdir,
   [  --with-libdir=DIR         installed package prefix directory],
   [ libdir=$withval ] , [ libdir=$prefix/lib$mybits_install ] )

AC_SUBST(package_prefix)
AC_SUBST(prefix)
AC_SUBST(libdir)

dnl =========================== Global Report Variables ================

# rpath="-rpath=${prefix}/lib$myarch"
supported_urls="file http https"

dnl =========================== Include and lib prefixes ===============

AC_ARG_WITH( lib-prefix,
  AC_HELP_STRING( [--with-lib-prefix=LIBPREFIX],
                  [sets library prefix (default is PREFIX/lib)]),
	lib_prefix=$withval, lib_prefix=${prefix}/lib${mybits_install})
AC_SUBST( lib_prefix)

dnl databases, tmp, crypto, mails
AC_ARG_WITH( include-prefix,
	AC_HELP_STRING( [--with-include-prefix=INCLUDEPREFIX],
			[sets include prefix (default is PREFIX/include)]),
			include_prefix=$withval, include_prefix=${prefix}/include)
AC_SUBST(include_prefix)

dnl ############################## BEGIN #############################
dnl                   definitions for distribution building

AC_ARG_WITH( dist-user,
	AC_HELP_STRING( [--with-dist-user=madwolf],
		[sets user for distribution building(default is madwolf)]),
			dist_user=$withval, dist_user=madwolf)
AC_SUBST( dist_user)

AC_ARG_WITH( dist-group,
	AC_HELP_STRING( [--with-dist-group=openca],
		[sets group for distribution building(default is openca)]),
			dist_group=$withval, dist_group=openca)
AC_SUBST( dist_group)

AC_ARG_ENABLE( package-build,
	AC_HELP_STRING( [--enable-package-build],
		[enable package build (default is no)]),
			package_build=$enableval, package_build=no)
AC_SUBST(package_build)

default_path=$PATH:/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin:/opt/csw/bin

dnl Check for program paths
AC_PATH_PROG( SHELL, bash, sh, $default_path)
AC_PATH_PROG( POD2MAN, pod2man,pod2man, $default_path)
AC_PATH_PROG( MKDIR, mkdir, , $default_path)
AC_PATH_PROG( SED, sed, , $default_path)
AC_PATH_PROG( GZIP, gzip, , $default_path)
AC_PATH_PROG( ZIP, gzip, , $default_path)
AC_PATH_PROG( TAR, tar, , $default_path)
AC_PATH_PROG( PWD, pwd, , $default_path)
AC_PATH_PROG( CHMOD, chmod, , $default_path)
AC_PATH_PROG( CHOWN, chown, , $default_path)
AC_PATH_PROG( CP, cp, , $default_path)
AC_PATH_PROG( ECHO, echo, , $default_path)
AC_PATH_PROG( DOXYGEN, doxygen, , $default_path)
AC_PATH_PROG( PDFLATEX, pdflatex, , $default_path)

AC_CHECK_PROG( HAS_PKGCONF, pkg-config, yes, [] , $PATH)

dnl ========================== Install Builder Path Search ===================

builder_path=$default_path:$HOME/installbuilder/bin:$HOME/installbuilder-5.4.10/bin:$HOME/installbuilder/bin/Builder.app/Contents/MacOS/

ibuilder="builder"

if [[ "x$DIST_NAME" = "xdarwin" ]] ; then
	ibuilder="installbuilder.sh"
fi
AC_PATH_PROG(INSTALL_BUILDER, $ibuilder, , $builder_path )
AC_SUBST(INSTALL_BUILDER)

dnl AC_MSG_ERROR( [****** ($DIST_NAME) IBUILDER is : $ibuilder and INSTALL_BUILDER is $INSTALL_BUILDER] );

dnl ==================== BEGIN LDAP Support =======================

ldap_vendor=
ldap="yes"
ldap_prefix=""
ldap_path=""
ldap_cflags=""
ldap_deprecated=
ldap_ldadd=
ldap_ldflags=

library_prefix=
library_ldflags=
library_cflags=
library_ldadd=

AC_ARG_ENABLE(ldap,
	AC_HELP_STRING( [--enable-ldap],
		[enable ldap support ( default is yes)]),
		ldap=$enableval, ldap=yes )

if [[ "x$enable_iphone" = "xyes" ]] ; then
	ldap="no"
fi

if ! [[ "x$ldap" = "xno" ]] ; then
   AC_ARG_WITH( ldap-prefix,
	AC_HELP_STRING( [--with-ldap-prefix],
		[ldap prefix directory)]),
		[ldap_prefix=$withval],[ldap_prefix=])

   if [[ "x$ldap_prefix" = "x" ]] ; then
	case "${myarch}" in
		bsd)
			ldap_prefix="/usr/local";
			;;
		solaris)
			ldap_prefix="/usr";
			;;
		*)
			ldap_prefix=
			;;
	esac

	dnl if [[ "${myarch}" = "bsd" ]] ; then
	dnl 	ldap_prefix="/usr/local"
	dnl fi
   fi

   	dnl Now we have to check which LDAP vendor is available
	AC_LDAP_VENDOR( $ldap_prefix )

   if [[ "x$ldap_vendor" = "x"  ]] ; then
	AC_MSG_RESULT([*** ERROR: No supported LDAP vendor found.])
	AC_MSG_ERROR([*** ERROR: Do you have the *devel* package installed ?])
   fi

	AC_DEFINE( HAVE_LDAP, 1, [HAVE LDAP])

	ldap_ldadd=$library_ldadd
	ldap_ldflags=$library_ldflags
	ldap_cflags=$library_cflags

	AC_MSG_RESULT([LDAP Vendor......: $ldap_vendor])
	AC_MSG_RESULT([LDAP CFLAGS......: $library_cflags])
	AC_MSG_RESULT([LDAP LDADD.......: $library_ldadd])
	AC_MSG_RESULT([LDAP LDFLAGS.....: $library_ldflags])

else
   ldap_cflags=
   ldap_libs=
   ldap_ldadd=
fi

AM_CONDITIONAL(LDAP_PREFIX, test ! x$ldap_prefix = x )

if [[ "x$ldap_vendor" = "xOPENLDAP" ]] ; then
	AC_DEFINE( LDAP_VENDOR_OPENLDAP, 1, [HAVE OPENLDAP])
	dnl AC_DEFINE( LDAP_DEPRECATED,      1, [LDAP DEPRECATED])
	dnl ldap_deprecated="yes";
fi

if [[ "x$ldap_vendor" = "xSUN" ]] ; then
	AC_DEFINE( LDAP_VENDOR_SUN, 1, [HAVE SUN LDAP])
fi

dnl Should be checked..
if ! [[ "x${ldap}" = "xno" ]] ; then
	supported_urls="$supported_urls ldap"
fi

if [[ "x${ldap_deprecated}" = "xyes" ]] ; then
	ldap_cflags="${ldap_cflags} -DLDAP_DEPRECATED=1"
fi

AC_SUBST(ldap_vendor)
AC_SUBST(ldap_ldadd)
AC_SUBST(ldap_ldflags)
AC_SUBST(ldap_cflags)
AC_SUBST(ldap_prefix)

dnl ====================== xml2 - xml LIBRARIES ===================

dnl Defaults
xml2_config=xml2-config
xml2_cflags=
xml2_prefix=/usr
xml2_ldflags=
xml2_ldadd=

dnl xml2 with prefix
AC_ARG_WITH( xml2-prefix,
[  --with-xml2-prefix=DIR         xml2 lib prefix directory],
[ xml2_prefix=$withval ] , [ xml2_prefix= ] )

if ! [[ "x$xml2_prefix" = "x" ]]; then
	if [[ -d "$xml2_prefix/lib$mybits_install" ]] ; then
		rpath="$rpath ${rpath_opt}\"$xml2_prefix/lib$mybits_install\""
	else
		rpath="$rpath ${rpath_opt}\"$xml2_prefix/lib$mybits_install\""
	fi
	ld_lib_path="$xml2_path:$ld_lib_path"
fi

if [[ "x$iphone_build" = "xno" ]] ; then
	AC_PATH_PROG(xml2_config, xml2-config, ,
 		$xml2_prefix/bin:/opt/csw/bin:$PATH:/bin:/usr/bin:/usr/local/bin )

	if ! [[ "x$xml2_config" = "x" ]] ; then
		xml2_prefix=`$xml2_config --prefix`
		xml2_config=$xml2_config
	else
		xml2_prefix=/usr
	fi
else
	xml2_prefix=$iphone_sdk/usr
	xml2_config=
fi

AC_SUBST(xml2_prefix)

if ! [[ "x$xml2_config" = "x" ]] ; then
	xml2_cflags=`$xml2_config --cflags`
 	xml2_ldadd=`$xml2_config --libs`
  xml2_ldflags=-L`$xml2_config --prefix`/lib$mybits_install 
  XML2_LIBTOOL_LIBS=`$xml2_config --libtool-libs`
else
  xml2_cflags=-I${xml2_prefix}/include/libxml2
	xml2_ldflags="-L${xml2_prefix}/lib$mybits_install"
	xml2_ldadd="-lxml2"
	XML2_LIBTOOL_LIBS=
fi

xml2_config="$xml2_prefix/bin/xml2-config"

AC_MSG_RESULT([with xml2-prefix      : $xml2_prefix])
AC_MSG_RESULT([with xml2-cflags      : $xml2_cflags])
AC_MSG_RESULT([with xml2-ldflags     : $xml2_ldflags])
AC_MSG_RESULT([with xml2-ldadd       : $xml2_ldadd])

AM_CONDITIONAL(xml2_prefix, test ! x$xml2_prefix = x )

if ! [[ -d "$xml2_prefix/include/libxml2/libxml" ]] ; then
	AC_MSG_ERROR([*** ERROR: Missing include files for libxml2! ***])
fi

dnl Export our XML2 build settings
AC_DEFINE(HAVE_XML2, 1, [LIBXML2])

AC_SUBST(xml2_config)
AC_SUBST(xml2_prefix)
AC_SUBST(xml2_cflags)
AC_SUBST(xml2_ldadd)
AC_SUBST(xml2_ldflags)

dnl ====================== mySQL LIBRARIES ===================

   	dnl Defaults
	MYSQL_CONFIG=mysql_config
	mysql_cflags=-I/usr/include/mysql
	mysql_prefix=/usr
	mysql_prefix_SPECIFIED=
	mysql_ldflags=
	mysql_ldadd=
	mysql_cflags=
	mysql_libs=


	enablemysql=yes

	AC_ARG_ENABLE(mysql,
		AC_HELP_STRING( [--enable-mysql],
			[enable mysql support ( default is yes)]),
				enablemysql=$enableval, enablemysql= )

	if [[ "x$iphone_build" = "xyes" ]] ; then
		enablemysql=no
	fi

   if ! [[ "${enablemysql}" = "no" ]] ; then

   	dnl xmlsec with prefix
   	AC_ARG_WITH( mysql-prefix,
   	[  --with-mysql-prefix=DIR         mysql lib prefix directory],
   	[ mysql_prefix_SPECIFIED=$withval ] , [ mysql_prefix_SPECIFIED= ] )

   	AC_PATH_PROG(mysql_config, mysql_config, ,
	   $mysql_prefix_SPECIFIED/bin:$mysql_prefix/bin:/opt/csw/bin:$PATH:/bin:/usr/bin:/usr/local/bin:/opt/csw/mysql5/bin:/opt/csw/mysql4/bin )

	if ! [[ "x${mysql_config}" = "x" ]] ; then
		mysql_prefix=${mysql_config%%/bin/mysql_config}
		MYSQL_CONFIG=$mysql_config
	else
		if [[ "x${mysql_prefix_SPECIFIED}" = "x" ]] ; then
			mysql_prefix=${mysql_prefix_SPECIFIED}
		fi
	fi

   	AC_SUBST(mysql_prefix)

	if ! [[ "x$mysql_config" = "x" ]] ; then
   		mysql_cflags=`$mysql_config --cflags`
   		# mysql_ldadd=`$mysql_config --libs`
		mysql_ldadd=
   		mysql_ldflags=`$mysql_config --libs_r`
	else
		mysql_cflags="-I$mysql_prefix/include"
		mysql_ldflags="-L$mysql_prefix/lib"
		mysql_ldadd="-lmysqlclient_r"
	fi


	dnl Export our MYSQL build settings
	OLD_CFLAGS="$CFLAGS"
	OLD_LDFLAGS="$LDFLAGS"
	CFLAGS="$mysql_cflags"
	LDFLAGS="$mysql_ldflags $mysql_ldadd"
	ok=0

	AC_RUN_IFELSE( [
		#include <mysql.h>
		int main(void) {
		        MYSQL *x;
		        return(0);
		}], [ ok=1 ], [ ok=0 ])

	CFLAGS="$OLD_CFLAGS"
	LDFLAGS="$OLD_LDFLAGS"

	if [[ "x${ok}" = "x1" ]] ; then
   		AC_DEFINE(HAVE_MYSQL, 1, test "${enablemysql}" = "yes")

		# mysql_cflags="$mysql_cflags"
		# mysql_libs="$mysql_libs"

		enablemysql="yes"
		supported_urls="$supported_urls mysql"
   	AC_MSG_RESULT([Enable MySQL URLs      : yes ])
		AC_MSG_RESULT([MySQL LDFLAGS          : $mysql_ldflags])
		AC_MSG_RESULT([MySQL CFLags           : $mysql_cflags])
		AC_MSG_RESULT([MySQL LDAdd            : $mydql_ldadd])
	else
		enablemysql="no"
		mysql_cflags=
		mysql_ldadd=
		mysql_ldflags=

		MYSQL_CONFIG=
		MYSQL_CPPFLAGS=

   		AC_MSG_RESULT([**** WARNING::MySQL URLs are disabled! ****])
	fi
fi

   AC_SUBST(MYSQL_CONFIG)
   AC_SUBST(MYSQL_CPPFLAGS)
   AC_SUBST(mysql_cflags)
   AC_SUBST(mysql_ldflags)
   AC_SUBST(mysql_ldadd)

dnl ====================== PostgreSQL LIBRARIES ===================

	dnl Defaults
	PG_CONFIG=pg_config
	pg_cflags=
	pg_prefix=/usr
	pg_prefix_SPECIFIED=
	pg_ldflags="-L/usr/lib$mybits_install"
	pg_ldadd="-lpq "

	enablepg=yes
	pg_ldflags=
	pg_ldadd=
	pg_flags=
	pg_config=

	AC_ARG_ENABLE(pg,
		AC_HELP_STRING( [--enable-pg],
			[enable postgresql support ( default is yes)]),
				enablepg=$enableval, enablepg=yes )

	if [[ "x$iphone_build" = "xyes" ]] ; then
		enablepg=no
	fi

   if ! [[ "${enablepg}" = "no" ]] ; then
   	dnl pg with prefix
   	AC_ARG_WITH( pg-prefix,
   	[  --with-pg-prefix=DIR         pg lib prefix directory],
   	[ pg_prefix_SPECIFIED=$withval ] , [ pg_prefix_SPECIFIED= ] )

   	AC_PATH_PROG(pg_config, pg_config, ,
	   $pg_prefix_SPECIFIED/bin:/opt/csw/bin:/opt/csw/postgresql/bin:$PATH:/bin:/usr/bin:/usr/local/bin )

	if ! [[ "x${pg_prefix_SPECIFIED}" = "x" ]] ; then
			pg_prefix=${pg_prefix_SPECIFIED}
	else
		if ! [[ "x${pg_config}" = "x" ]] ; then
			pg_prefix=${pg_config%%/bin/pg_config}
			PG_CONFIG=$pg_config
		fi
	fi

	if ! [[ "x$pg_config" = "x" ]] ; then
   		pg_cflags=`$pg_config --includedir`
		pg_cflags="-I${pg_cflags}"
   		PG_LIBDIR=`$pg_config --libdir`
   		dnl pg_libs=`$pg_config --libs`
   		pg_ldflags="-L${PG_LIBDIR}"
   		pg_ldadd="-lpq"
	
	else
		pg_cflags="-I${pg_prefix}/include"
		pg_ldflags="-L${pg_prefix}/lib$mybits_install"
		pg_ldadd="-lpq"
	fi

	OLD_CFLAGS="$CFLAGS"
	OLD_LDFLAGS="$LDFLAGS"
	CFLAGS="$pg_cflags"
	LDFLAGS="$pg_ldflags $pg_ldadd"
	ok=0

	AC_RUN_IFELSE( [
		#include <libpq-fe.h>
		int main(void) {
			PGconn *sql;
		        return(0);
		}], [ ok=1 ], [ ok=0 ])

	CFLAGS="$OLD_CFLAGS"
	LDFLAGS="$OLD_LDFLAGS"

	if [[ "${ok}" = "1" ]] ; then
		AC_DEFINE(HAVE_PG, 1, test "${enablepg}" = "yes")

		pg_cflags="$pg_cflags"
		pg_ldflags="$pg_ldflags"
		pg_ldadd="$pg_ldadd"

		enablepg="yes"
		supported_urls="$supported_urls pg"
   		AC_MSG_RESULT([Enable PostgreSQL URLs    : yes ])
	else
		enablepg="no"
		pg_cflags=
		pg_ldflags=
		pg_ldadd=

		PG_CONFIG=
		PG_CPPFLAGS=
		pg_prefix=

   		AC_MSG_RESULT([**** WARNING::PostgreSQL disabled! ****])
	fi

   fi dnl /* END IF enablepg = "yes" */

   AC_SUBST(PG_CONFIG)
   AC_SUBST(pg_cflags)
   AC_SUBST(PG_CPPFLAGS)
   AC_SUBST(pg_prefix)
   AC_SUBST(pg_ldflags)
   AC_SUBST(pg_ldadd)


dnl ####################### Checks for libresolv #########################

AC_ARG_ENABLE(dns,
	AC_HELP_STRING( [--enable-dns],
		[enable dns support ( default is yes)]),
		dns=$enableval, dns=yes )

if [[ "$dns" = "yes" ]] ; then

	old_cflags="$CFLAGS"
	old_ldflags="$LDFLAGS"
	dns_ldadd="-lresolv"

	if [[ "x$myarch" = "xbsd" ]] ; then
		dns_ldadd="-lc"
	fi

	CFLAGS=""
	LDFLAGS="$dns_ldadd"

AC_TRY_COMPILE(
[#include <netinet/in.h>]
[#include <sys/types.h>]
[#include <arpa/inet.h>]
[#include <arpa/nameser.h>]
[#ifndef T_A]
[#include <arpa/nameser_compat.h>]
[#endif]
[#include <resolv.h>],
[ int type = T_A; ]
[ char *name = (char *) "www.openca.org"; ]
[ unsigned char response[NS_PACKETSZ]; ]
[ int len = res_search(name, C_IN, type, response, sizeof(response)); ],
[ have_libresolv=yes ] , 
[ have_libresolv=no ] )

if [[ "x$have_libresolv" = "xyes" ]] ; then
	dnl AC_MSG_RESULT([***** DEBUG: libresolv Found! *****])
	AC_DEFINE(HAVE_LIBRESOLV, 1, [DNS Library])

	resolv_ldadd="$dns_ldadd";
	supported_urls="$supported_urls dns"

	AC_SUBST(resolv_ldadd)
else
	AC_MSG_RESULT([***** WARNING: DNS URLs are disabled (libresolv not found!) ******])
fi

	LDFLAGS="$old_ldflags"
	CFLAGS="$old_cflags"

else

	AC_MSG_RESULT([***** WARNING: DNS URLs are disabled by config option ******])

  resolv_ldadd=""
  AC_SUBST(resolv_ldadd)
fi

dnl ######################### CRYPTO SUPPORT #############################

AC_ARG_ENABLE( kmf,
	AC_HELP_STRING( [--enable-kmf],
		[enable kmf crypto for token operations (default is no)]),
			enable_kmf=$enableval, enable_kmf=no )

AC_ARG_ENABLE( openssl,
	AC_HELP_STRING( [--enable-openssl],
		[enable openssl crypto for token operations (default is yes)]),
			enableopenssl=$enableval, enableopenssl=yes )

# if [[ "$myarch" = "solaris" ]] ; then
# 	if [[ "${enable_kmf}" = "" ]] ; then
# 		enable_kmf=no
# 	fi
# else
# 	# Not on solaris, we disable kmf
# 	enable_kmf=no
# fi

openssl_setup=no
kmf_setup=no

AC_MSG_RESULT([enable_kmf: ${enable_kmf}])
AC_MSG_RESULT([enable_openssl: ${enableopenssl}])

dnl Defaults
openssl_cflags=
openssl_ldflags=
openssl_ldadd=
openssl_include=
openssl_setup=no
openssl_engine=
openssl_static_libs=
openssl_min_ver=0.9.8
openssl_pkg_min_ver=0.9.8

dnl activate_ecdsa=

kmf_prefix=
kmf_cflags=
kmf_ldflags=
kmf_ldadd=
kmf_include=
kmf_setup=

if ! [[ $enable_kmf = "no" ]] ; then
AC_CHECK_LIB(kmf, KMF_Initialize,
		kmf_ldadd=-lkmf, [
			enable_kmf=no;
			enableopenssl=yes;
			AC_MSG_RESULT([***WARNING***: Can not setup kmf library correctly, Falling back to OpenSSL!])]
	    )
fi

AM_CONDITIONAL(ENABLE_KMF, test "${enable_kmf}" = "yes")

if [[ "${enable_kmf}" = "yes" ]] ; then
	AC_MSG_RESULT([crypto package for token operations... KMF])

	AC_DEFINE(ENABLE_KMF, 1, [SUN CMS])
	kmf_prefix=/usr
	kmf_include=/usr/include
	kmf_setup=yes
	AC_SUBST(kmf_prefix)
	AC_SUBST(kmf_cflags)
	AC_SUBST(kmf_libflags)
	AC_SUBST(kmf_ldadd)
fi

AM_CONDITIONAL(ENABLE_OPENSSL, test "${enableopenssl}" = "yes")
AM_CONDITIONAL(OPENSSL_PREFIX, test ! x$openssl_prefix = x )

dnl ECDSA support cecks
old_cflags=$CFLAGS
old_ldflags=$LDFLAGS

AC_ARG_WITH( openssl-prefix,
	AC_HELP_STRING( [--with-openssl-prefix=DIR], [openssl prefix]),
	openssl_prefix=$withval, openssl_prefix= )
AC_SUBST(openssl_prefix)

AC_MSG_RESULT([with openssl-prefix     : $openssl_prefix ])

if [[ "${enableopenssl}" = "yes" ]] ; then
   if ! [[ "x${openssl_prefix}" = "x" ]]; then
      if [[ -d "$openssl_prefix/lib/$mybits" ]] ; then
        openssl_path=$openssl_prefix/lib$mybits_install
      else
        openssl_path=$openssl_prefix/lib
      fi

	  openssl_ldadd="-lcrypto -lssl"
	  openssl_ldflags=
    AC_MSG_RESULT([openssl lib dir         : $openssl_path])
   else
    AC_MSG_RESULT([openssl lib dir         : $openssl_path (default)])

	  openssl_ldadd="-lcrypto -lssl"
	  openssl_ldflags=
	  openssl_setup=yes

	  AC_MSG_RESULT([crypto package for token operations... OPENSSL])

	  AC_DEFINE(ENABLE_OPENSSL, 1, [OPENSSL])

		dnl Now see if the user specified openssl_prefix
dnl		if ! [[ "x${openssl_prefix}" = "x" ]]; then
dnl		   	# openssl_setup=yes
dnl		   	AC_MSG_RESULT( [User specified --with-openssl-prefix])
dnl			dnl Check if the developer has the pkg-config macros
dnl		  	dnl for the autotools on their system
dnl		 	ifdef([PKG_CHECK_MODULES],
dnl		    	[
dnl		else  dnl else of prefix...
	            dnl If so, we can check if the target system has
		    dnl (1) pkg-config support installed as well, and
		    dnl (2) has openssl 0.9.8 or greater installed
		    if ! [[ x${HAS_PKGCONF} = x  ]]; then
		   	PKG_CHECK_MODULES( OPENSSL,openssl >= $openssl_pkg_min_ver, [
			   AC_MSG_RESULT([openssl $openssl_pkg_min_ver or greater found via pkgconfig])
			   openssl_cflags=$OPENSSL_CFLAGS
			   openssl_ldflags=$OPENSSL_LIBS
			   openssl_prefix=$prefix
			   openssl_ldadd="-lssl -lcrypto"
			   openssl_ldflags=`echo $openssl_ldflags | sed "s|-lssl||" | sed "s|-lcrypto||"`
			   openssl_setup=yes
			fi], [AC_MSG_RESULT( [good openssl not found via pkgconfig])])
dnl		  ],
dnl		  [
dnl		    ## Skipping pkg-config macros...
dnl		  ]
dnl		)dnl  End of check using pkg-config...


dnl		fi    dnl End of prefix block
	fi
	
dnl	if ! [[ "x$openssl_setup" = "xyes" ]] ; then
		dnl NEW Check function

		gen_dirs="/usr/lib$mybits /usr/local/lib$mybits_install /opt/lib$mybits_install /opt/local/lib$mybits_install"
		ssl_dirs="/usr/local/ssl/lib$mybits_install /usr/local/openssl/lib$mybits_install /opt/lib$mybits_install"
		solaris_dirs="/opt/csw/lib$mybits /opt/csw/lib /opt/csw /usr/sfw/lib$mylibs /usr/sfw/lib"
		darwin_dirs=""
		aix_dirs=""

		prefix_dirs="$prefix/lib$mybits_install $prefix/lib"

		dirs="$prefix_dirs $gen_dirs $ssl_dirs $solaris_dirs $darwin_dirs $aix_dirs"

		library_cflags=
		library_ldflags=
		library_ldadd=
		library_ldpath=
		library_prefix=
		library_libs=
		library_setup=
		library_shared=
		error_number=

		AC_CHECK_OPENSSL_PATH($openssl_min_ver, "$openssl_prefix", $dirs, $mybits_install)
		if [[ "x$library_setup" = "no" ]] ; then
			AC_MSG_ERROR([**** ERROR: Can not configure OPENSSL library ($error_number)!])
		fi

		AC_MSG_RESULT([OpenSSL Prefix: $openssl_prefix])

		if [[ -d "${library_prefix%/lib$mybits_install}" ]] ; then
			openssl_prefix="${library_prefix%/lib$mybits_install}"
		else
			openssl_prefix="${library_prefix%/lib}"
		fi
		openssl_cflags="$library_cflags"
		openssl_ldflags="$library_ldflags"
		openssl_ldadd="$library_ldadd"
		openssl_include="-I$library_prefix/include"
		dnl openssl_static_libs="${library_ldflags}"

		AC_MSG_RESULT([OpenSSL Prefix: $openssl_prefix])

		if ! [[ "x$openssl_prefix" = "x" ]] ; then
			if [[ -d "${openssl_prefix}/lib$mybits_install" ]] ; then
				openssl_path="${openssl_prefix}/lib$mybits_install";
			else
				openssl_path="${openssl_prefix}/lib"
			fi

			if test ! -z "$need_dash_r" ; then
	   	     	rpath="${rpath_opt} \"${openssl_path}\" ${rpath}"
			else
	   	     	rpath="${rpath_opt}\"${openssl_path}\" ${rpath}"
			fi
			ld_lib_path="$xml2_path:$ld_lib_path"
		fi

		# else 
		#	if [[ "$myarch" = "solaris" ]] ; then
		#		rpath="${rpath_opt}\"$openssl_prefix/lib$mybits_install\" ${rpath}"
		#	fi
		#fi

		if [[ "${enable_shared}" = "yes" ]] ; then
			if [[ "${library_shared}" = "no" ]] ; then
				AC_MSG_ERROR([***** ERROR: no shared openssl libs found!])
			fi
		else
			openssl_static_libs="$openssl_ldflags"
		fi
	dnl fi

	dnl openssl_static_libs="$openssl_ldflags"

	if [[ "x$openssl_ldadd" = "x" ]] ; then
		openssl_ldadd="-lcrypto -lssl"
	fi

	AC_MSG_RESULT([ OPENSSL ldflags: ................. ${openssl_ldflags}])
	AC_MSG_RESULT([ OPENSSL ldadd: ................... ${openssl_ldadd}])

	CFLAGS="${openssl_cflags}"
	LDFLAGS="${openssl_ldflags} ${openssl_ldadd} ${openssl_static_libs}"

	if [[ "$iphone_build" = "no" ]] ; then
	    AC_SEARCH_LIBS(BIO_new, "-lcrypto", [ ] ,
		AC_MSG_ERROR([**** ERROR::OpenSSL not Configured! (do you have the devel packages?) ****]), [-L$openssl_prefix/lib ] )
	fi

	activate_ecdsa=

   	dnl check for ECDSA support
   	AC_ARG_ENABLE( ecdsa,
   	[  --enable-ecdsa         enable Elliptic Curves DSA support],
   	[ activate_ecdsa="${enableval}" ],
        [ activate_ecdsa= ] )

	if [[ "x$activate_ecdsa" = "x" ]] ; then
		CHECK_EC(${openssl_prefix})
		if [[ "$activate_ecdsa" = "yes" ]] ; then
			AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
		fi
	else 
		if [[ "$activate_ecdsa" = "no" ]] ; then
			activate_ecdsa=no
		else
			if [[ "$activate_ecdsa" = "yes" ]] ; then
				_activate=$activate_ecdsa
				CHECK_EC(${openssl_prefix})
				if ! [[ "$_activate" = "$activate_ecdsa" ]] ; then
					AC_MSG_ERROR([*** ERROR::OpenSSL in ${openssl_prefix} does not support EC/ECDSA!])
				else
					activate_ecdsa=$_activate
					AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
				fi
			else
				AC_MSG_ERROR([*** ERROR :: Wrong value for enable-ecdsa option ($activate_ecdsa)!])
			fi
		fi
	fi

	if [[ "$activate_ecdsa" = "yes" ]] ; then
		openssl_cflags="${openssl_cflags} -DENABLE_ECDSA=1"
	fi

	CFLAGS="${old_cflags}"
	LDFLAGS="${old_ldflags}"

	AC_MSG_RESULT([ OPENSSL ldflags: ................. ${openssl_ldflags}])
	AC_MSG_RESULT([ OPENSSL ldadd: ................... ${openssl_ldadd}])

	AC_SUBST(openssl_cflags)
	AC_SUBST(openssl_ldflags)
	AC_SUBST(openssl_ldadd)
	AC_SUBST(openssl_static_libs)
	AC_SUBST(openssl_prefix)

	## End of OpenSSL build settings section ##

	dnl OpenSSL Engine Support
	AC_ARG_ENABLE( openssl-engine,
	[  --enable-openssl-engine      enable openssl engine support (yes)],
	[case "${enableval}" in
	  yes)  engine=yes ;;
	  no)   engine=no ;;
	  *) AC_MSG_ERROR([bad value ${engine} for --enable-openssl-engine]) ;;
	 esac], [engine=yes])

	AC_MSG_RESULT([enable engine support   : $engine])

	dnl AM_CONDITIONAL(HAVE_ENGINE, test x$engine = yes)

	if [[ "$engine" = "yes" ]] ; then
	        AC_DEFINE(HAVE_ENGINE, 1, [ENGINE])
	fi
	AM_CONDITIONAL(ENABLE_OPENSSL_ENGINE, test "${engine}" = "yes")
fi

dnl ================= OpenSSL Static LIBS (?) =========================

AM_CONDITIONAL(STATIC_COMPILE, test "x$openssl_static_libs" != "x")
AC_CONFIG_HEADER([src/libpki/config.h])

AC_ARG_ENABLE(strict,
	AC_HELP_STRING( [--enable-strict],
		[enable strict compilation error warnings (default is no)]),
		strict_compile=$enableval, strict_compile=no )

dnl ========================== GENERAL COMPILE OPTIONS ===============

sys_ldadd=
sys_cflags=

if test x$myarch = xlinux ; then
  AC_DEFINE(LIBPKI_TARGET_LINUX, 1, [Linux])
  sys_ldadd="-ldl -lrt"
  sys_cflags="-DLINUX"
elif test x$myarch = xbsd ; then
  AC_DEFINE(LIBPKI_TARGET_BSD, 1, [BSD])
  sys_ldadd="-lc "
  sys_cflags="-DBSD"
elif test x$myarch = xdarwin ; then
  if [[ "x$iphone_build" = "xyes" ]] ; then
    AC_DEFINE(LIBPKI_TARGET_IPHONE, 1, [IPHONE])
    sys_ldadd="-dead_strip -framework Foundation -framework UIKit"
    sys_cflags="-DIPHONE"
  else
    AC_DEFINE(LIBPKI_TARGET_OSX, 1, [OSX])
    sys_cflags="-DMACOS"
    dnl sys_cflags="-framework CoreFoundation"
    sys_ldadd="-ll -framework Foundation"
  fi
elif test x$myarch = xsolaris ; then
  AC_DEFINE(LIBPKI_TARGET_SOLARIS, 1, [Solaris])
  sys_ldadd="-ll -ldl -lnsl -lsocket -lposix4 -lresolv -lrt"
    sys_cflags="-DSOLARIS"
elif test x$myarch = xhpux ; then
  AC_DEFINE(LIBPKI_TARGET_HPUX, 1, [HP-UX])
  sys_ldadd="-ll -ldl -lrt"
  sys_cflags="-DHPUX"
fi

if ! [[ "$strict_compile" = "no" ]] ; then
	sys_cflags="${sys_cflags} -Wall -Werror"	
fi

AC_SUBST(sys_ldadd)
AC_SUBST(sys_cflags)

libpki_cflags="-I${package_prefix}/include ${openssl_cflags} ${ldap_cflags} ${kmf_cflags} ${xml2_cflags} ${mysql_cflags} ${pg_cflags}"

if [[ "${enable_shared}" = "yes" ]] ; then
  libpki_ldflags="-L${lib_prefix} ${openssl_ldflags} ${openssl_ldadd} ${xml2_ldflags} ${mysql_ldflags} ${pg_ldflags} ${kmf_ldflags}"
  libpki_ldadd="-lpthread"
else
  libpki_ldflags="-static -L${lib_prefix} ${openssl_ldflags} ${ldap_ldflags} ${xml2_ldflags} ${mysql_ldflags} ${pg_ldflags} ${kmf_ldflags}"
  libpki_ldadd="-lpthread ${openssl_ldadd} ${ldap_ldadd} ${xml2_ldadd} ${mysql_ldadd} ${pg_ldadd} ${resolv_ldadd} ${kmf_ldadd}"
fi

# Harmonize the linker directories
h_dirs="${lib_prefix} ${prefix}/lib"
for dir in $h_dirs ; do
  if ! [[ -d "${dir}${mybits_install}" ]] ; then
    libpki_ldflags=`echo $libpki_ldflags | sed -e "s|-L${dir}${mybits_install}||g"`
    AC_MSG_RESULT([Removed $dir from linking (non-existing dir)])
  else
    has_dir=`echo $libpki_ldflags | grep "L${dir}${mybits_install} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
    	AC_MSG_RESULT([Removing duplicate entries for -L${dir}${mybits_install} from libpki_ldflags])
      libpki_ldflags=`echo $libpki_ldflags | sed -e "s|-L${dir}${mybits_install} ||g"`
      libpki_ldflags="-L${dir}${mybits_install} $libpki_ldflags"
    	AC_MSG_RESULT([Removed duplicate entries for -L$dir${mybits_install} from libpki_ldflags])
    fi
  fi
done

# Harmonize the linker directories
c_dirs="${prefix}/include"
for dir in $c_dirs ; do
  if ! [[ -d "$dir" ]] ; then
    libpki_cflags=`echo $libpki_cflags | sed -e "s|-I${dir}||g"`
    AC_MSG_RESULT([Removed $dir from includes (non-existing dir)])
  else
    has_dir=`echo $libpki_cflags | grep "I${dir} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
      libpki_cflags=`echo "$libpki_cflags" | sed -e "s|-I${dir} ||g"`
      libpki_cflags="-I${dir} $libpki_cflags"
    	AC_MSG_RESULT([Removed duplicate entries for -I$dir from libpki_cflags])
    fi
  fi
done

# Adds all the rpaths
if ! [[ "x$enable_rpath" = "xyes" ]] ; then
	rpath=""
fi

libpki_ldflags="${libpki_ldflags}"
AC_SUBST(rpath)

dnl External Tools
AC_SUBST(libpki_cflags)
AC_SUBST(libpki_ldflags)
AC_SUBST(libpki_ldadd)

dnl Internal Makefile
if [[ "${enable_shared}" = "yes" ]] ; then
	my_ldadd="-lpthread ${sys_ldadd} ${ldap_ldadd} ${openssl_ldadd} ${xml2_ldadd} ${kmf_ldadd} ${mysql_ldadd} ${pg_ldadd} ${resolv_ldadd}"
	my_ldflags="-L${lib_prefix} ${openssl_ldflags} ${ldap_ldflags} ${xml2_ldflags} ${sys_ldflags} ${kmf_ldflags} ${mysql_ldflags} ${pg_ldflags}"
	test_libs="${sys_ldflags} ${sys_ldadd}"
else
	if [[ "$iphone_build" = "no" ]] ; then
		my_ldflags="-static -L${lib_prefix} ${openssl_ldflags} ${ldap_ldflags} ${xml2_ldflags} ${kmf_ldflags} ${mysql_ldflags} ${pg_ldflags}"
		my_ldadd="${sys_ldadd} ${openssl_ldadd} ${xml2_ldadd} ${kmf_ldadd} ${mysql_ldadd} ${pg_ldadd} ${ldap_ldadd} ${resolv_ldadd}"
		test_libs="-static ${sys_ldadd} src/.libs/libpki.a"
	else
		my_ldflags="${sys_ldflags} ${ldap_ldflags} ${openssl_ldflags} ${xml2_ldflags} ${kmf_ldflags} ${mysql_ldflags} ${pg_ldflags}"
		my_ldadd="${sys_ldadd} ${ldap_ldadd} ${openssl_ldadd} ${xml2_ldadd} ${kmf_ldadd} ${mysql_ldadd} ${pg_ldadd} ${resolv_ldadd}"
		test_libs="${sys_ldadd}"
	fi
fi

my_cflags="${EXTRA_CFLAGS} ${libpki_cflags}"
my_ldflags=`echo ${my_ldflags} | sed -e "s|-lssl||g" | sed -e "s|-lcrypto||g"`

# Harmonize the linker directories
h_dirs="${lib_prefix} ${prefix}/lib"
for dir in $h_dirs ; do
  if ! [[ -d "${dir}${mybits_install}" ]] ; then
    my_ldflags=`echo $my_ldflags | sed -e "s|-L${dir}${mybits_install}||g"`
    AC_MSG_RESULT([Removed $dir from linking (non-existing dir)])
  else
    has_dir=`echo $my_ldflags | grep "L${dir}${mybits_install} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
    	AC_MSG_RESULT([Removing duplicate entries for -L${dir}${mybits_install} from my_ldflags])
      my_ldflags=`echo $my_ldflags | sed -e "s|-L${dir}${mybits_install} ||g"`
      my_ldflags="-L${dir}${mybits_install} $my_ldflags"
    	AC_MSG_RESULT([Removed duplicate entries for -L${dir}${mybits_install} from my_ldflags])
    fi
    AC_MSG_RESULT([New my_ldflags: $my_ldflags])
  fi
done

# Harmonize the linker directories
c_dirs="${prefix}/include"
for dir in $c_dirs ; do
  if ! [[ -d "$dir" ]] ; then
    my_cflags=`echo $my_cflags | sed -e "s|-I${dir}||g"`
    AC_MSG_RESULT([Removed $dir from includes (non-existing dir)])
  else
    has_dir=`echo $my_cflags | grep "I${dir} "`
    if ! [[ "x$has_dir" = "x" ]] ; then
      my_cflags=`echo "$my_cflags" | sed -e "s|-I${dir} ||g"`
      my_cflags="-I${dir} $my_cflags"
    	AC_MSG_RESULT([Removed duplicate entries for -I${dir} from my_cflags])
    fi
  fi
done

AC_SUBST(my_cflags)
AC_SUBST(my_ldflags)
AC_SUBST(my_ldadd)
AC_SUBST(test_libs)
AC_SUBST(DESTDIR)

dnl =======================[ Default Config Opts ]====================

dnl Include Directory
include_dir=${prefix}/include
AC_SUBST(include_dir)

conf_dir=file://${prefix}/etc
etc_dir=${prefix}/etc

AC_SUBST(conf_dir)
AC_SUBST(etc_dir)

dnl ==================================================================

AC_CONFIG_FILES(
	Makefile
	src/global-vars
	src/Makefile
	src/drivers/Makefile
	src/drivers/openssl/Makefile
	src/drivers/engine/Makefile
	src/drivers/pkcs11/Makefile
	src/drivers/kmf/Makefile
	src/openssl/Makefile
	src/io/Makefile
	src/net/Makefile
	src/scep/Makefile
	src/cms/Makefile
	src/prqp/Makefile
	src/lirt/Makefile
	src/tools/Makefile
	src/scripts/libpki-config
	src/tests/Makefile
	src/libpki/pki_config.h
	contrib/libpki.pc
	contrib/libpki-inst.xml
	examples/prqp/Makefile
	examples/profiles/Makefile
	examples/token/Makefile
	examples/url/Makefile
	examples/crl/Makefile
	examples/pkcs11/Makefile
	examples/pkcs12/Makefile
	examples/fips-mode/Makefile
	docs/Makefile
	docs/pkginfo
	etc/Makefile
	etc/profile.d/test.xml
	etc/profile.d/user.xml
	etc/profile.d/server.xml
	etc/store.d/empty.xml
)

AC_OUTPUT

# if [[ "x$myarch" = "xsolaris" ]] ; then
# 	# We need to patch libtool
# 	patch -N <contrib/solaris-libtool.patch 2>/dev/null >/dev/null
# fi

echo "
XML2 library Configuration:
---------------------------

 XML2 prefix ..........: $xml2_prefix
 XML2 Compiler Flags ..: $xml2_cflags
 XML2 Linker ..........: $xml2_ldflags
 XML2 Libs ............: $xml2_ldadd
"

if [[ "$enablemysql" = "yes" ]] ; then
echo "
MYSQL library Configuration:
----------------------------

 MySQL prefix ..........: $mysql_prefix
 MySQL Compiler Flags ..: $mysql_cflags
 MySQL Linker ..........: $mysql_ldflags
 MySQL libs ............: $mysql_ldadd
"
fi

if [[ "$enablepg" = "yes" ]] ; then
echo "
PostgreSQL library Configuration:
---------------------------------

 PostgreSQL prefix ..........: $pg_prefix
 PostgreSQL Compiler Flags ..: $pg_cflags
 PostgreSQL Linker ..........: $pg_ldflags
 PostgreSQL libs ............: $pg_ldadd
"
fi

echo "
LDAP Configuration:
-------------------

 LDAP support .........: $ldap
 LDAP Vendor ..........: $ldap_vendor
 LDAP prefix ..........: $ldap_prefix
 LDAP Compiler Flags ..: $ldap_cflags
 LDAP libs prefix .....: $ldap_path
 LDAP Linker ..........: $ldap_ldflags
 LDAP libs ............: $ldap_ldadd
"

if [[ "$enableopenssl" = "yes" ]] ; then
echo "
OpenSSL Configuration:
----------------------

 Library ..............: OpenSSL
 Prefix ...............: $openssl_prefix
 Compiler Flags .......: $openssl_cflags"
if [[ "${enable_shared}" = "yes" ]] ; then
echo " Linker Flags .........: $openssl_ldflags"
echo " libs .................: $openssl_ldadd"
else
echo " Libs Flags (static)...: $openssl_static_libs (${enable_shared})"
fi
echo " Support for ECDSA ....: $activate_ecdsa
"
fi

if [[ "${enable_kmf}" = "yes" ]] ; then
echo "
KMF Configuration:
------------------

 Library ..............: KMF
 Prefix ...............: $kmf_prefix
 Compiler Flags .......: $kmf_cflags
 Libs Flags ...........: $kmf_ldflags
 Libs .................: $kmf_ldadd
 Support for ECDSA ....: $kmf_ecdsa
"
fi

echo "
Configuration for $PACKAGE $VERSION :
--------------------------------

 Architecture .........: $myarch ($mybits bits)
 Host System Type .....: $host
 Supported URLs .......: $supported_urls
 Library Version ......: v = $iface_current, r = $iface_revision, a = $iface_age
 Install lib path .....: $libdir
 Install path .........: $package_prefix
 Compiler Flags .......: $my_cflags
 Linker Flags .........: $my_ldflags $rpath
 Libs .................: $my_ldadd
"
echo "
 Package configured for: $DIST_NAME $DIST_VERSION ($arch_target)
"

echo "
 Now type 'make' to build $PACKAGE $VERSION,
 and then 'make install' for installation.
"

