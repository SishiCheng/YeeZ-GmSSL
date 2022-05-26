#pragma once
#include <cstdint>

namespace ypc{
namespace crypto{

class sm2_ecc{
public:
    static uint32_t get_private_key_size();
    static uint32_t get_public_key_size();
     static uint32_t gen_private_key(uint32_t skey_size, uint8_t *skey);
    static uint32_t generate_pkey_from_skey(const uint8_t *skey,
                                          uint32_t skey_size, uint8_t *pkey,
                                          uint32_t pkey_size);
};

}
} // namespace ypc
