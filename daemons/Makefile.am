# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =

AM_CFLAGS = $(NULL)
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
		-Wcast-align -Werror-implicit-function-declaration \
		$(NULL)
endif
export AM_CFLAGS

SUBDIRS =			\
	dnssec			\
	ipa-kdb			\
	ipa-slapi-plugins	\
	ipa-sam			\
	ipa-otpd		\
	$(NULL)
