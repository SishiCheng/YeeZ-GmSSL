#include "corecommon/crypto/gmssl/sm2_ecc.h"
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include "common/byte.h"
#include "stbox/stx_status.h"
using namespace std;
extern "C" {
#include "stbox/keccak/keccak.h"
}
namespace ypc {
namespace crypto {

uint32_t sm2_ecc::get_private_key_size() { return 32; }

uint32_t sm2_ecc::get_public_key_size() { return 64; }

uint32_t sm2_ecc::gen_private_key(uint32_t skey_size, uint8_t *skey) {
    SM2_KEY *tmp = new SM2_KEY(); 
    sm2_key_generate(tmp);
    memcpy(skey, tmp->private_key, skey_size);
    return stbox::stx_status::success;
}

/* 
 * Goal:   generate public key form private key
 * Input:  skey - private key
 *         skey_size 
 *         pkey - public key
 *         pkey_size
 * Output: stx_status
*/
uint32_t sm2_ecc::generate_pkey_from_skey(const uint8_t *skey,
                                          uint32_t skey_size, uint8_t *pkey,
                                          uint32_t pkey_size) {
    SM2_KEY *tmp = new SM2_KEY(); 
    sm2_key_set_private_key(tmp, skey);
    memcpy(pkey, tmp->public_key.x, 32);
    memcpy(pkey + 32, tmp->public_key.y, 32);
    return stbox::stx_status::success;
}


} // namespace crypto
} // namespace ypc
