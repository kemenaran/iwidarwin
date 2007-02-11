#
# Makefile for the Linux Wireless network device drivers.
#
# Original makefile by Peter Johanson
#
# NOTE: This make file can serve as both an external Makefile (launched
#       directly by the user), or as the sub-dir Makefile used by the kernel
# 	build system.

# If CONFIG_IPW* isn't set, we'll assume the user has never configured
# their kernel to include this module and set up some defaults.
#
# NOTE: If you have previously added the IPW project to your kernel 
# 	and configured it for inclusion, these settings will be 
#	overridden by your kernel configuration.
ifndef CONFIG_IPW2100
EXTERNAL_BUILD=y
CONFIG_IPW2100=m
CONFIG_IPW2100_DEBUG=y

# If you are not interested in using monitor mode, simply comment out:
#
# NOTE:  If you have problems compiling due to IW_MODE_MONITOR not being
#        defined then you need to update the wireless extension version
#	 installed in your kernel, or comment this line out.
CONFIG_IPW2100_MONITOR=y

endif

# We have to add drivers/net/wireless until ieee802_11.h is in the default
# include path
EXTRA_CFLAGS += -I$(TOPDIR)/drivers/net/wireless 

ifeq ($(IEEE80211_INC),)
	IEEE80211_INC := /lib/modules/$(shell uname -r)/include
	IEEE80211_MODVERDIR=/lib/modules/$(KVER)/net/ieee80211/.tmp_versions
else
	IEEE80211_MODVERDIR=$(IEEE80211_INC)
endif
EXTRA_CFLAGS += -I$(IEEE80211_INC)

ifeq ($(CONFIG_IPW2100_DEBUG),y)
	EXTRA_CFLAGS += -g -Wa,-adhlms=$@.lst
endif

ifdef KBUILD_EXTMOD
	EXTRA_CFLAGS += -I$(KBUILD_EXTMOD)
endif

list-m :=
list-$(CONFIG_IPW2100) += ipw2100
obj-$(CONFIG_IPW2100) += ipw2100.o

#
# Begin dual Makefile mode here.  First we provide support for when we
# are being invoked by the kernel build system
#
ifneq ($(KERNELRELEASE),)

#
# If you receive a compile message about multiple definitions of
# CONFIG_IPW2100_DEBUG, then you have IPW* into the full kernel build, and 
# these definitions are now being set up by the kernel build system.  
#
#
# To correct this, remove any CONFIG_{IPW,IEEE80211}* lines from 
# $(KSRC)/.config and $(KSRC)/include/linux/autoconf.h
# 

EXTRA_CFLAGS += -DCONFIG_PM

ifeq ($(EXTERNAL_BUILD),y)
ifdef CONFIG_IPW2100_DEBUG
EXTRA_CFLAGS += -DCONFIG_IPW2100_DEBUG=$(CONFIG_IPW2100_DEBUG)
endif
ifdef CONFIG_IPW2100_MONITOR
EXTRA_CFLAGS += -DCONFIG_IPW2100_MONITOR=$(CONFIG_IPW2100_MONITOR)
endif
ifdef CONFIG_IPW_QOS
EXTRA_CFLAGS += -DCONFIG_IPW_QOS=$(CONFIG_IPW_QOS)
endif
endif

else 
# Here we begin the portion that is executed if the user invoked this Makefile
# directly.

# KSRC should be set to the path to your sources
# modules are installed into KMISC
KVER  := $(shell uname -r)
KSRC := /lib/modules/$(KVER)/build
KMISC := /lib/modules/$(KVER)/kernel/drivers/net/wireless/
KMISC_INC := /lib/modules/$(KVER)/include

# KSRC_OUTPUT should be overridden if you are using a 2.6 kernel that
# has it's output sent elsewhere via KBUILD_OUTPUT= or O=
KSRC_OUTPUT := $(KSRC)

PWD=$(shell pwd)

VERFILE := $(KSRC_OUTPUT)/include/linux/version.h
KERNELRELEASE := $(shell \
	if [ -r $(VERFILE) ]; then \
		(cat $(VERFILE); echo UTS_RELEASE) | \
		$(CC) -I$(KSRC_OUTPUT) $(CFLAGS) -E - | \
		tail -n 1 | \
		xargs echo; \
        else \
		uname -r; \
	fi)

MODPATH := $(DESTDIR)/lib/modules/$(KERNELRELEASE)

all: check_inc modules

check_inc:
	@([ ! -e $(IEEE80211_INC)/net/ieee80211.h ] && \
	echo -e \
"\n ERROR: ieee80211.h not found in '$(IEEE80211_INC)'.\n\n"\
"You need to install the ieee80211 subsystem from http://ieee80211.sf.net\n"\
"and point this build to the location where you installed those sources, eg.:\n\n"\
"% make IEEE80211_INC=/usr/src/ieee80211/\n\n"\
"will look for ieee80211.h in /usr/src/ieee80211/net/\n") || exit 0
	@[ -e $(IEEE80211_INC)/net/ieee80211.h ]

clean:
	rm -f *.mod.c *.mod *.o *.ko .*.cmd .*.flags .lst *.lst
	rm -rf $(PWD)/tmp
	for file in *.{c,h}; do \
		sed -i -e "s:\ *$$::g" -e "s:\t*$$::g" $$file; \
	done

distclean: clean
	rm -f tags TAGS

TMP=$(PWD)/tmp
MODVERDIR=$(TMP)/.tmp_versions

modules:
	mkdir -p $(MODVERDIR)
	-cp $(IEEE80211_MODVERDIR)/*.mod $(MODVERDIR)
ifdef ($(KSRC_OUTPUT)/.tmp_versions)
	-cp $(KSRC_OUTPUT)/.tmp_versions/*.mod $(MODVERDIR)
endif
ifeq ($(KSRC),$(KSRC_OUTPUT)) # We're not outputting elsewhere
ifdef ($(KSRC)/.tmp_versions)
	-cp $(KSRC)/.tmp_versions/*.mod $(MODVERDIR)
endif
	$(MAKE) -C $(KSRC) M=$(PWD) MODVERDIR=$(MODVERDIR) modules
else # We've got a kernel with seperate output, copy the config, and use O=
	mkdir -p $(TMP)
	cp $(KSRC_OUTPUT)/.config $(TMP)
	$(MAKE) -C $(KSRC) M=$(PWD) MODVERDIR=$(MODVERDIR)) O=$(PWD)/tmp modules
endif

install: modules
	install -d $(KMISC)
	install -m 644 -c $(addsuffix .ko,$(list-m)) $(KMISC)
	/sbin/depmod -a ${KVER}
	@echo "Don't forget to copy firmware to your hotplug's firmware directory and have the "
	@echo "hotplug tools in place."
	@echo "See INSTALL for more information."

uninstall:
	rm -rf $(addprefix $(KMISC),$(addsuffix .ko,$(list-m)))
	/sbin/depmod -a ${KVER}

endif # End of internal build


.PHONY: TAGS tags check_inc

RCS_FIND_IGNORE := \( -name SCCS -o -name BitKeeper -o -name .svn -o -name CVS \) -prune -o
define all-sources
	( find . $(RCS_FIND_IGNORE) -name '*.[chS]' -print )
endef

TAGS:
	$(all-sources) | etags -
tags:
	rm -f $@
	CTAGSF=`ctags --version | grep -i exuberant >/dev/null && echo "-I __initdata,__exitdata,EXPORT_SYMBOL,EXPORT_SYMBOL_NOVERS"`; \
	$(all-sources) | xargs ctags $$CTAGSF -a

