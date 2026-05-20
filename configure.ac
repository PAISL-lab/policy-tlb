# SPDX-License-Identifier: Apache-2.0
AC_INIT([mcp-guard], [0.1.0], [https://github.com/PAISL-lab/mcp-ebpf-guard/issues])
AC_CONFIG_SRCDIR([loader/main.c])
AC_CONFIG_FILES([config.mk])
AC_LANG([C])

AC_PROG_CC
AC_ARG_VAR([CLANG], [C compiler used for eBPF objects])
AC_ARG_VAR([BPFTOOL], [bpftool executable used to generate libbpf skeletons])

AS_IF([test -d "$srcdir/.devtools"], [
  mcp_guard_devtools="`cd "$srcdir/.devtools" && pwd`"
  PATH="$mcp_guard_devtools/conda/bin:$mcp_guard_devtools/apt/usr/lib/linux-tools-6.8.0-110:$mcp_guard_devtools/apt/usr/bin:$mcp_guard_devtools/apt/usr/sbin:$PATH"
  AS_IF([test -d "$mcp_guard_devtools/apt/usr/lib/x86_64-linux-gnu/pkgconfig"], [
    AS_IF([test -n "$LD_LIBRARY_PATH"], [
      LD_LIBRARY_PATH="$mcp_guard_devtools/apt/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
    ], [
      LD_LIBRARY_PATH="$mcp_guard_devtools/apt/usr/lib/x86_64-linux-gnu"
    ])
    AS_IF([test -n "$PKG_CONFIG_PATH"], [
      PKG_CONFIG_PATH="$mcp_guard_devtools/apt/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH"
    ], [
      PKG_CONFIG_PATH="$mcp_guard_devtools/apt/usr/lib/x86_64-linux-gnu/pkgconfig"
    ])
    AS_IF([test -n "$PKG_CONFIG_SYSROOT_DIR"], [], [
      PKG_CONFIG_SYSROOT_DIR="$mcp_guard_devtools/apt"
    ])
  ])
  export PATH LD_LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_SYSROOT_DIR
])

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
