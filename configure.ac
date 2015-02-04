AC_PREREQ(2.59)
AC_COPYRIGHT([Copyright (c) 2013 Weongyo Jeong <weongyo@gmail.com>])
AC_INIT([eel], [1.0.0], [weongyo@gmail.com])
AC_PREFIX_DEFAULT(/opt/eel/1.0.0)
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# --enable-debugging-symbols
AC_ARG_ENABLE(debugging-symbols,
	AS_HELP_STRING([--enable-debugging-symbols],[enable debugging symbols (default is NO)]), [
	CFLAGS="${CFLAGS} -O0 -g -fno-inline"
	CXXFLAGS="${CXXFLAGS} -O0 -g -fno-inline" ])

AC_CONFIG_FILES([
    Makefile
    etc/Makefile
    src/Makefile
])
AC_OUTPUT
