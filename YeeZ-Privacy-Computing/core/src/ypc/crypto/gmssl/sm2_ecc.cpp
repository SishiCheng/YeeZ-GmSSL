#include "corecommon/crypto/gmssl/sm2_ecc.h"
#include "corecommon/crypto/gmssl/sm3_hash.h"
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
    int res = sm2_key_generate(&tmp);
    if (res == -1)
    {
        return stbox::stx_status::sm2_empty_key;
    }
    
    memcpy(skey, tmp.private_key, skey_size);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::generate_pkey_from_skey(const uint8_t *skey,
                                          uint32_t skey_size, uint8_t *pkey,
                                          uint32_t pkey_size) {
    SM2_KEY tmp; 
    int res = sm2_key_set_private_key(&tmp, skey);
    if (res == -1)
    {
        return stbox::stx_status::sm2_point_generate_error;
    }

    memcpy(pkey, tmp.public_key.x, 32);
    memcpy(pkey + 32, tmp.public_key.y, 32);
    return stbox::stx_status::success;
}

uint32_t sm2_ecc::sign_message(const uint8_t *skey, uint32_t skey_size,
                             const uint8_t *data, uint32_t data_size,
                             uint8_t *sig, uint32_t sig_size){
    uint8_t hash[32];
    sm3_hash::msg_hash(data, data_size, hash, 32);
    SM2_KEY key;
    int res = sm2_key_set_private_key(&key, skey);
    if (res == -1)
    {
        return stbox::stx_status::sm2_point_generate_error;
    }

    size_t siglen;
    int sign_res = sm2_sign(&key, hash, sig, &siglen);
    if (sign_res == -1)
    {
        return stbox::stx_status::sm2_sign_error;
    }

    return stbox::stx_status::success;
}

uint32_t sm2_ecc::verify_signature(const uint8_t *data, uint32_t data_size,
                          const uint8_t *sig, uint32_t sig_size,
                          const uint8_t *public_key,
                          uint32_t pkey_size){
    uint8_t hash[32];
    sm3_hash::msg_hash(data, data_size, hash, 32);
    SM2_KEY key;
    SM2_POINT sm2_public_key;
    int convert_res = sm2_point_from_octets(&sm2_public_key, public_key, 64);
    if (convert_res == -1)
    {
        return stbox::stx_status::sm2_point_convert_error;
    }

    int res = sm2_key_set_public_key(&key, &sm2_public_key);
    if (res == -1)
    {
        return stbox::stx_status::sm2_empty_public_error;
    }

    int verify_res = sm2_verify(&key, hash, sig, (size_t)sig_size);
    if (verify_res == -1)
    {
        return stbox::stx_status::sm2_verify_error;
    }

    return stbox::stx_status::success;
}

uint32_t ecdh_shared_key(const uint8_t *skey, uint32_t skey_size,
                         const uint8_t *public_key, uint32_t pkey_size,
                         uint8_t *shared_key,
                         uint32_t shared_key_size){
    SM2_KEY key;
    int res = sm2_key_set_private_key(&key, skey);
    if (res == -1)
    {
        return stbox::stx_status::sm2_point_generate_error;
    }

    SM2_POINT peer_public, out;
    int convert_res = sm2_point_from_octets(&peer_public, public_key, 64);
    if (convert_res == -1)
    {
        return stbox::stx_status::sm2_point_convert_error;
    }

    int ecdh_res = sm2_ecdh(&key, &peer_public, &out);
    if (ecdh_res == -1)
    {
        return stbox::stx_status::sm2_shared_key_error;
    }

    memcpy(shared_key, out.x, 32);
    memcpy(shared_key + 32, out.y, 32);
    return stbox::stx_status::success;
}

} // namespace crypto
} // namespace ypc

