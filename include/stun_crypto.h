/*
 *  See license file
 */

#include <stdlib.h>
#include <stdint.h>
#include <macro.h>

#ifdef __cplusplus
extern "C" {
#endif

FUNC_DECL unsigned char* stunlib_util_md5(const void* data, size_t len, unsigned char* md);

FUNC_DECL void stunlib_util_sha1_hmac(const void* key, size_t keyLength, const void* data, size_t dataLength, void* macOut, unsigned int* macLength);

FUNC_DECL void stunlib_util_random(void* buffer, size_t size); // not threadsafe

FUNC_DECL uint32_t stunlib_util_crc32(long crc, const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif
