#include "corecommon/crypto/gmssl/sm3_hash.h"
#include <gmsssl/sm3.h>
#include "common/byte.h"
#include "stbox/stx_status.h"
extern "C" {
#include "stbox/keccak/keccak.h"
}
namespace ypc {
namespace crypto {

uint32_t sm3_hash::get_msg_hash_size() { return 32; }

uint32_t sm3_hash::msg_hash(const uint8_t *raw_msg, uint32_t msg_size,
                           uint8_t *hash, uint32_t hash_size) {
	uint8_t dgst[32];
	memcpy(dgst, hash, 32);
	return sm3_digest(raw_msg, msg_size, dgst, 32);
}
} // namespace crypto
} // namespace ypc

