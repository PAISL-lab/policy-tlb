# SPDX-License-Identifier: Apache-2.0
AC_INIT([mcp-guard], [0.1.0], [https://github.com/PAISL-lab/mcp-ebpf-guard/issues])
AC_CONFIG_SRCDIR([loader/main.c])
AC_CONFIG_FILES([config.mk])
AC_LANG([C])

AC_PROG_CC
AC_ARG_VAR([CLANG], [C compiler used for eBPF objects])
AC_ARG_VAR([BPFTOOL], [bpftool executable used to generate libbpf skeletons])

AC_PATH_PROG([CLANG], [clang], [no])
AS_IF([test "x$CLANG" = "xno"], [
  AC_MSG_ERROR([clang is required to build eBPF objects])
])

AC_PATH_PROG([BPFTOOL], [bpftool], [no])
AS_IF([test "x$BPFTOOL" = "xno"], [
  AC_MSG_ERROR([bpftool is required to generate the libbpf skeleton])
])

AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
AS_IF([test "x$PKG_CONFIG" != "xno" && $PKG_CONFIG --exists libbpf], [
  LIBBPF_CFLAGS=`$PKG_CONFIG --cflags libbpf`
  USER_LDLIBS="`$PKG_CONFIG --libs libbpf` -lelf -lz"
], [
  LIBBPF_CFLAGS=""
  USER_LDLIBS="-lbpf -lelf -lz"
])

CPPFLAGS="$CPPFLAGS $LIBBPF_CFLAGS"
AC_CHECK_HEADERS([bpf/libbpf.h elf.h zlib.h], [], [
  AC_MSG_WARN([missing development header: $ac_header])
])

AC_SUBST([CLANG])
AC_SUBST([BPFTOOL])
AC_SUBST([LIBBPF_CFLAGS])
AC_SUBST([USER_LDLIBS])

AC_OUTPUT
