# Thanks to Mike O'Malley https://github.com/spuriousdata for apxs C++ compile
# https://gist.github.com/spuriousdata/4227525

# apxs is hardcoded to only compile *.c files so C++ files must be named foo.c or symlinked to foo.c -- What a pain in the ass.

OS=$(shell if grep -q Ubuntu /etc/*release; then echo Ubuntu; fi)
ifeq ($(OS), Ubuntu)
BUILD_BASE=/usr/share/apache2
TOPDIR=$(BUILD_BASE)
APXS=apxs2
else
BUILD_BASE=/usr/lib/httpd
TOPDIR=/etc/httpd
APXS=apxs
endif
 
builddir=.
top_srcdir=$(TOPDIR)
top_builddir=$(TOPDIR)
# include $(BUILD_BASE)/build/special.mk
 
MODULE = src/mod_less.la
SOURCES = src/mod_less.c

CC_FLAGS=$(shell apxs -q CFLAGS) $(shell apr-1-config --cppflags) -I./src -I/usr/include/httpd 
LD_FLAGS=-Wall$(shell pkg-config) $(shell apr-1-config --libs) -lstdc++
 
all: $(MODULE)
 
debug:
	$(APXS) -S CC=g++ -S CFLAGS="$(CC_FLAGS) -D_DEBUG -g -O0" $(LD_FLAGS) -c $(SOURCES)
 
$(MODULE): $(SOURCES)
	$(APXS) -S CC=g++ -S CFLAGS="$(CC_FLAGS)" $(LD_FLAGS) -c $(SOURCES)
 
install: all
	$(APXS) -i $(MODULE)
	apachectl restart
 
clean:
	@rm -f $(MODULE) src/*.o src/*.lo src/*.slo *.o src/gpb/*o
