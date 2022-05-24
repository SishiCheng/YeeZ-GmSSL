#include "corecommon/crypto/gmssl/sm2_ecc.h"
#include <gmssl/sm2.h>
#include "common/byte.h"
#include "stbox/stx_status.h"
extern "C" {
#include "stbox/keccak/keccak.h"
}
namespace ypc {
namespace crypto {

uint32_t sm2_ecc::get_private_key_size() { return 32; }

uint32_t sm2_ecc::get_public_key_size() { return 256; }

uint32_t sm2_ecc::gen_private_key(uint32_t skey_size, uint8_t *skey) {
    struct SM2_KEY *p_key = nullptr;
    uint8_t tmp[skey_size];
    memcpy(tmp, skey, skey_size);
    sm2_key_set_private_key(p_key, tmp);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::generate_pkey_from_skey(const uint8_t *skey,
                                          uint32_t skey_size, uint8_t *pkey,
                                          uint32_t pkey_size) {
    struct SM2_KEY tmp;
    struct SM2_POINT tmp_pkey;
    tmp_pkey.x = 
    tmp.public_key = 
    return ecc_t::generate_pkey_from_skey(skey, skey_size, pkey, pkey_size);
}
} // namespace crypto
} // namespace ypc

