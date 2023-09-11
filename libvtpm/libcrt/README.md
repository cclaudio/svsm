# What is the libcrt?

Libcrt (C-Runtime library) is a subset of the [musl libc](https://musl.libc.org/)
that provides the libc functions required to build the SVSM libvtpm, which is an
archive with OpenSSL and Microsoft TPM static libraries.

# Libcrt overview

In general, the libcrt header files are just a proxy for the `libcrt.h`, which
centralizes all the definitions. That's similar to what OVMF does to build
OpenSSL without having to patch missing headers.

Some libc funtions are required at build time, but they are not called at
runtime. These functions are stubbed out in `stub.c`, a BUG error message is
printed in case they are reached.
