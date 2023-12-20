/** @file
  OpenSSL_1_1_1b doesn't implement rand_pool_* functions for UEFI.
  The file implement these functions.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "openssl/rand.h"
//#include <openssl/aes.h>

#include <libcrt.h>
//#include "CrtLibSupport.h"

//#include <Uefi.h>
//#include <Library/RngLib.h>

/**
  Calls RandomNumber64 to fill
  a buffer of arbitrary size with random bytes.
  This is a shim layer to RngLib.

  @param[in]   Length        Size of the buffer, in bytes,  to fill with.
  @param[out]  RandBuffer    Pointer to the buffer to store the random result.

  @retval TRUE        Random bytes generation succeeded.
  @retval FALSE       Failed to request random bytes.

**/
static bool RandGetBytes(size_t Length, uint8_t *RandBuffer)
{
  uint64_t TempRand;

  if (RandBuffer == NULL) {
//    DEBUG ((DEBUG_ERROR, "[OPENSSL_RAND_POOL] NULL RandBuffer. No random numbers are generated and your system is not secure\n"));
    assert(RandBuffer != NULL); // Since we can't generate random numbers, we should assert. Otherwise we will just blow up later.
    return false;
  }

  while (Length > 0) {
    // Use libcrt to get random number
    TempRand = rand();

    if (Length >= sizeof(TempRand)) {
      *((uint64_t *)RandBuffer) = TempRand;
      RandBuffer += sizeof(uint64_t);
      Length -= sizeof(TempRand);
    } else {
      memcpy(RandBuffer, &TempRand, Length);
      Length = 0;
    }   
  }

  return true;
}

/*
 * Add random bytes to the pool to acquire requested amount of entropy
 *
 * This function is platform specific and tries to acquire the requested
 * amount of entropy by polling platform specific entropy sources.
 *
 * This is OpenSSL required interface.
 */
size_t rand_pool_acquire_entropy(RAND_POOL  *pool)
{
  bool        Ret;
  size_t         Bytes_needed;
  unsigned char  *Buffer;

  Bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
  if (Bytes_needed > 0) {
    Buffer = rand_pool_add_begin(pool, Bytes_needed);

    if (Buffer != NULL) {
      Ret = RandGetBytes(Bytes_needed, Buffer);
      if (false == Ret) {
        rand_pool_add_end(pool, 0, 0);
      } else {
        rand_pool_add_end(pool, Bytes_needed, 8 * Bytes_needed);
      }
    }
  }

  return rand_pool_entropy_available(pool);
}

/*
 * Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_add_nonce_data(RAND_POOL  *pool)
{
  uint8_t  data[16];

  RandGetBytes (sizeof (data), data);

  return rand_pool_add (pool, (unsigned char *)&data, sizeof (data), 0);
}

/*
 * Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_add_additional_data(RAND_POOL  *pool)
{
  uint8_t  data[16];

  RandGetBytes (sizeof (data), data);

  return rand_pool_add (pool, (unsigned char *)&data, sizeof (data), 0);
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_init(void)
{
  return 1;
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
void rand_pool_cleanup(void)
{
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
void rand_pool_keep_random_devices_open(int  keep)
{
}

