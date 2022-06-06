#pragma once
#include <cstdint>

namespace ypc{
namespace crypto{

class sm4_aes{
public:
  static uint32_t get_encrypt_message_size_with_prefix(uint32_t data_size);

  static uint32_t encrypt_with_prefix(const uint8_t *key, uint32_t key_size,
                                        const uint8_t *data, uint32_t data_size,
                                        uint32_t prefix, uint8_t *cipher,
                                        uint32_t cipher_size, uint8_t *out_mac);
  static uint32_t get_decrypt_message_size_with_prefix(uint32_t cipher_size);
  static uint32_t decrypt_with_prefix(const uint8_t *key, uint32_t key_size,
                                    const uint8_t *cipher, uint32_t cipher_size,
                                    uint32_t prefix, uint8_t *data,
                                    uint32_t data_size, const uint8_t *in_mac);

};
}
}
