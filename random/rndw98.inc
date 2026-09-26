/* Win98 CryptoAPI entropy adapter. SPDX-License-Identifier: LGPL-2.1-or-later */
#include <wincrypt.h>

int
_gcry_rndw32_gather_random (void (*add)(const void *, size_t,
                                     enum random_origins),
                          enum random_origins origin,
                          size_t length, int level)
{
  HCRYPTPROV provider;
  unsigned char buffer[256];

  if (!level || !length)
    return 0;

  if (!CryptAcquireContextA (&provider, NULL, MS_DEF_PROV_A,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    log_fatal ("Win98 CryptoAPI acquisition failed: %lu\n",
               (unsigned long)GetLastError ());

  while (length)
    {
      size_t count = length < sizeof buffer ? length : sizeof buffer;
      if (!CryptGenRandom (provider, (DWORD)count, buffer))
        {
          DWORD error = GetLastError ();
          wipememory (buffer, sizeof buffer);
          CryptReleaseContext (provider, 0);
          log_fatal ("Win98 CryptoAPI generation failed: %lu\n",
                     (unsigned long)error);
        }
      add (buffer, count, origin);
      wipememory (buffer, sizeof buffer);
      length -= count;
    }

  if (!CryptReleaseContext (provider, 0))
    log_fatal ("Win98 CryptoAPI release failed: %lu\n",
               (unsigned long)GetLastError ());
  return 0;
}

void
_gcry_rndw32_gather_random_fast (void (*add)(const void *, size_t,
                                          enum random_origins),
                               enum random_origins origin)
{
  _gcry_rndw32_gather_random (add, origin, 64, 1);
}
