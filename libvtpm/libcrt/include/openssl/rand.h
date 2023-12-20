/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef OSSL_CRYPTO_RAND_H
#define OSSL_CRYPTO_RAND_H

#include <stdlib.h>

/* forward declaration */
typedef struct rand_pool_st RAND_POOL;

size_t rand_pool_entropy_available(RAND_POOL *pool);
/* |entropy_factor| expresses how many bits of data contain 1 bit of entropy */
size_t rand_pool_bytes_needed(RAND_POOL *pool, unsigned int entropy_factor);

int rand_pool_add(RAND_POOL *pool,
                  const unsigned char *buffer, size_t len, size_t entropy);
unsigned char *rand_pool_add_begin(RAND_POOL *pool, size_t len);
int rand_pool_add_end(RAND_POOL *pool, size_t len, size_t entropy);

#endif

