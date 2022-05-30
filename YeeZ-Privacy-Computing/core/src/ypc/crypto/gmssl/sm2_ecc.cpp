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

uint32_t sm2_ecc::get_public_key_size() { return 64; }

uint32_t sm2_ecc::gen_private_key(uint32_t skey_size, uint8_t *skey) {
    SM2_KEY tmp; 
    sm2_key_generate(&tmp);
    memcpy(skey, tmp.private_key, skey_size);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::generate_pkey_from_skey(const uint8_t *skey,
                                          uint32_t skey_size, uint8_t *pkey,
                                          uint32_t pkey_size) {
    SM2_KEY tmp; 
    sm2_key_set_private_key(&tmp, skey);
    memcpy(pkey, tmp.public_key.x, 32);
    memcpy(pkey + 32, tmp.public_key.y, 32);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::sign_message(const uint8_t *skey, uint32_t skey_size,
                             const uint8_t *data, uint32_t data_size,
                             uint8_t *sig, uint32_t sig_size){
    uint8_t pkey;
    sm2_ecc::generate_pkey_from_skey(skey, skey_size, &pkey, 64);
    SM2_KEY key;
    memcpy(key.public_key.x, skey, 32);
    memcpy(key.public_key.y, skey + 32, 32);
    memcpy(key.private_key, &pkey, 32);
    size_t siglen;
    sm2_sign(&key, data, sig, &siglen);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::verify_signature(const uint8_t *data, uint32_t data_size,
                          const uint8_t *sig, uint32_t sig_size,
                          const uint8_t *public_key,
                          uint32_t pkey_size){
    uint8_t private_key;
    sm2_ecc::generate_pkey_from_skey(public_key, pkey_size, &private_key, 64);
    SM2_KEY key;
    memcpy(key.public_key.x, public_key, 32);
    memcpy(key.public_key.y, public_key + 32, 32);
    memcpy(key.private_key, &private_key, 32);
    sm2_verify(&key, data, sig, (size_t)sig_size);
    return stbox::stx_status::success;
}

uint32_t ecdh_shared_key(const uint8_t *skey, uint32_t skey_size,
                         const uint8_t *public_key, uint32_t pkey_size,
                         uint8_t *shared_key,
                         uint32_t shared_key_size){
    uint8_t pkey;
    sm2_ecc::generate_pkey_from_skey(skey, skey_size, &pkey, 64);
    SM2_KEY key;
    memcpy(key.public_key.x, skey, 32);
    memcpy(key.public_key.y, skey + 32, 32);
    memcpy(key.private_key, &pkey, 32);
    SM2_POINT peer_public;
    SM2_POINT shared;
    memcpy(peer_public.x, public_key, 32);
    memcpy(peer_public.y, public_key + 32, 32);
    sm2_verify(key, &peer_public, &shared);
    memcpy(out, shared.x, 32);
    memcpy(out + 32, shared.y, 32);
    return stbox::stx_status::success;
}

} // namespace crypto
} // namespace ypc

