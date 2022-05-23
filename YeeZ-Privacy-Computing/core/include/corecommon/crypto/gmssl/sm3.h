#pragma once

namespace ypc {
namespace crypto {

class sm3 {
public:
  static uint32_t get_msg_hash_size();

  static uint32_t msg_hash(const uint8_t *raw_msg, uint32_t msg_size,
                           uint8_t *hash, uint32_t hash_size);
};

} // namespace crypto
} // namespace ypc
