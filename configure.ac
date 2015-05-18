AC_PREREQ([2.69])
AC_INIT([bootimgfs], [1.0.0], [digetx@gmail.com])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Link internal stuff statically to not depend on dev environment
LDFLAGS="-static-libgcc $LDFLAGS"

# Checks for libraries.
PKG_CHECK_MODULES([FUSE], [fuse >= 2.6.0],, [AC_MSG_ERROR([FUSE >= 2.6.0 was not found])])

AC_ARG_ENABLE([openssl], AS_HELP_STRING([--disable-openssl], [disable openssl]))

if test "x$enable_openssl" != "xno"; then
    PKG_CHECK_MODULES(OPENSSL, [libcrypto >= 0.9.8])
    AC_DEFINE([HAVE_SHA1], [1], [Define if have openssl-dev.])
    LIBS="$LIBS  $OPENSSL_LIBS"
fi

# Checks for header files.
AC_CHECK_HEADERS(fcntl.h stddef.h stdlib.h string.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
