AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_builddir)/includes -I$(top_srcdir)/includes
AM_CFLAGS = -O3 -Wall -g -ggdb

bin_PROGRAMS = main speed

main_LDADD = ${top_builddir}/bin/libpbgp.la @CHECK_LIBS@
speed_LDADD = ${top_builddir}/bin/libpbgp.la @CHECK_LIBS@

main_SOURCES = main.c
speed_SOURCES = speed.c

# Link your object files with -lgcov or -fprofile-arcs
# --coverage is a synonym for -fprofile-arcs -ftest-coverage

# -finstrument-functions
# -finstrument-functions-exclude-function-list=
# -finstrument-functions-exclude-file-list=
# -pg --coverage
main_CFLAGS = -Wall -g -ggdb -Wno-unused -O3
speed_CFLAGS = -Wall -g -ggdb -Wno-unused -O3

# main_LDFLAGS = --coverage

CLEANFILES = test_* __db* log.* core callgrind.out.* *.env *.gcno *.gcda *.gcov gmon.out cachegrind.*
