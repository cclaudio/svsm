LIBCRT_DIR = $(CURDIR)/libcrt
OPENSSL_DIR = $(CURDIR)/openssl
MSTPM_DIR = $(CURDIR)/ms-tpm-20-ref/TPMCmd

LIBCRT = $(LIBCRT_DIR)/libcrt.a

LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a

LIBTPM_A = tpm/src/libtpm.a
LIBTPM = $(MSTPM_DIR)/$(LIBTPM_A)

LIBPLATFORM_A = Platform/src/libplatform.a
LIBPLATFORM = $(MSTPM_DIR)/$(LIBPLATFORM_A)

OPENSSL_MAKEFILE = $(OPENSSL_DIR)/Makefile
MSTPM_MAKEFILE = $(MSTPM_DIR)/Makefile

LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBTPM) $(LIBPLATFORM)

all: libvtpm.a bindings.rs

libvtpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

# libcrt
$(LIBCRT):
	$(MAKE) -C $(LIBCRT_DIR)

# openssl
$(LIBCRYPTO): $(OPENSSL_MAKEFILE) $(LIBCRT)
	$(MAKE) -C $(OPENSSL_DIR) -j$$(nproc)

$(OPENSSL_MAKEFILE):
	(cd $(OPENSSL_DIR) && git checkout openssl-3.1.4  && \
		./Configure \
			--config=$(CURDIR)/openssl_svsm.conf \
			--api=1.1.1 \
			SVSM \
			no-afalgeng \
			no-aria \
			no-async \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cmac \
			no-cmp \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dsa \
			no-dso \
			no-dtls \
			no-dtls1-method \
			no-dtls1_2-method \
			no-dynamic-engine \
			no-ec2m \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-hw \
			no-idea \
			no-ktls \
			no-makedepend \
			no-module \
			no-md4 \
			no-mdc2 \
			no-multiblock \
			no-nextprotoneg \
			no-pic \
			no-psk \
			no-ocb \
			no-ocsp \
			no-padlockeng \
			no-poly1305 \
			no-posix-io \
			no-rc2 \
			no-rc4 \
			no-rc5 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-shared \
			no-siphash \
			no-siv \
			no-sm2 \
			no-sm4 \
			no-sock \
			no-srp \
			no-srtp \
			no-ssl \
			no-ssl3-method \
			no-ssl-trace \
			no-static-engine \
			no-stdio \
			no-threads \
			no-tls1_3 \
			no-ts \
			no-ui-console \
			no-whirlpool \
			disable-legacy \
			no-sse2 \
			no-asm \
			--with-rand-seed=none \
			-I$(LIBCRT_DIR)/include \
			-Wl,rpath=$(LIBCRT_DIR) -lcrt -g -O0)

# ms-tpm
$(LIBTPM): $(MSTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(MSTPM_DIR) $(LIBTPM_A)

$(LIBPLATFORM): $(MSTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(MSTPM_DIR) $(LIBPLATFORM_A)

MSTPM_CFLAGS := -static -nostdinc -fno-stack-protector -fPIE
MSTPM_CFLAGS += -DSIMULATION=NO -DEPHEMERAL_NV -DVTPM -DHASH_LIB=Ossl -DSYM_LIB=Ossl -DMATH_LIB=Ossl -DSELF_TEST=NO
MSTPM_CFLAGS += -I$(LIBCRT_DIR)/include
MSTPM_CFLAGS += -I$(OPENSSL_DIR)/include

$(MSTPM_MAKEFILE):
	(cd $(MSTPM_DIR) && \
		./bootstrap && \
		./configure \
			--with-crypto-engine=Ossl \
			CFLAGS="${MSTPM_CFLAGS}" \
			LIBCRYPTO_LIBS="${$(LIBCRT) $(LIBCRYPTO)}")

# bindings.rs
BINDGEN = ${HOME}/.cargo/bin/bindgen
BINDGEN_FLAGS = --use-core --impl-debug
CLANG_FLAGS = -Wno-incompatible-library-redeclaration -I$(MSTPM_DIR) -I$(MSTPM_DIR)/tpm/include/prototypes -I$(MSTPM_DIR)/Platform/include/prototypes -I$(LIBCRT_DIR)/include -I $(OPENSSL_DIR)/include -nostdinc

$(BINDGEN):
	cargo install bindgen-cli

bindings.rs: libvtpm.h $(BINDGEN) $(LIBTPM)
	echo "#![allow(non_upper_case_globals)]" > $@
	echo "#![allow(non_camel_case_types)]" >> $@
	echo "#![allow(non_snake_case)]" >> $@
	echo "#![allow(unused)]" >> $@
	echo "#![allow(improper_ctypes)]" >> $@
	$(BINDGEN) $(BINDGEN_FLAGS) libvtpm.h -- $(CLANG_FLAGS) >> $@

clean:
	make -C $(LIBCRT_DIR) clean
	make -C $(OPENSSL_DIR) clean
	make -C $(MSTPM_DIR) clean
	rm -f libvtpm.a

distclean: clean
	rm -f bindings.rs
	rm -f $(OPENSSL_MAKEFILE)
	rm -f $(MSTPM_MAKEFILE)

.PHONY: all clean distclean
