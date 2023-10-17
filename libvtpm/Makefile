LIBCRT_DIR = $(CURDIR)/libcrt

LIBCRT = $(LIBCRT_DIR)/libcrt.a

LIBS = $(LIBCRT)

all: libvtpm.a

libvtpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

# libcrt
$(LIBCRT):
	$(MAKE) -C $(LIBCRT_DIR)

clean:
	make -C $(LIBCRT_DIR) clean
	rm -f libvtpm.a

distclean: clean

.PHONY: all clean distclean
