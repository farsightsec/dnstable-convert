AC_PREREQ(2.60)
AC_INIT([dnstable-convert], [0])
AC_CONFIG_SRCDIR([dnstable_convert.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([libdnstable], [libdnstable])
PKG_CHECK_MODULES([libnmsg], [libnmsg])
PKG_CHECK_MODULES([libmtbl], [libmtbl])
PKG_CHECK_MODULES([libwdns], [libwdns])

AC_CHECK_HEADER([ldns/ldns.h])
AC_CHECK_LIB([ldns], [ldns_version])

CPPFLAGS_SAVED=$CPPFLAGS
CPPFLAGS="$pkg_cv_libnmsg_CFLAGS $CPPFLAGS"
AC_CHECK_HEADERS([nmsg/sie/dnsdedupe.pb-c.h],
                 [],
                 [AC_MSG_ERROR([required header file not found])])
CPPFLAGS=$CPPFLAGS_SAVED

AC_PATH_PROG([ASCIIDOC], [a2x])
AM_CONDITIONAL([BUILD_MAN], [test -n "$ASCIIDOC"])
if test -n "$ASCIIDOC"; then
    DOC_MAN_MSG="yes (asciidoc available)"
else
    DOC_MAN_MSG="no (asciidoc not available)"
fi

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
])
