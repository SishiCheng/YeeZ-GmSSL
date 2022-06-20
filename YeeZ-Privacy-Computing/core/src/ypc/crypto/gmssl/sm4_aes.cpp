#include "corecommon/crypto/gmssl/sm4_aes.h"
#include "corecommon/crypto/gmssl/sm3_hash.h"
#include <glog/logging.h>
#include <gmssl/sm4.h>
#include <openssl/rand.h>
#include "common/byte.h"
#include "stbox/stx_status.h"
extern "C" {
#include "stbox/keccak/keccak.h"
}
#define AAD_MAC_TEXT_LEN 64
#define AAD_MAC_PREFIX_POS 24
#define INITIALIZATION_VECTOR_SIZE 12
static char aad_mac_text[AAD_MAC_TEXT_LEN] = "tech.yeez.key.manager";

namespace ypc{
namespace crypto{

  uint32_t sm4_aes::get_cipher_size(uint32_t data_size){ 
    return data_size + INITIALIZATION_VECTOR_SIZE; 
  }

  uint32_t sm4_aes::encrypt_with_prefix(const uint8_t *key, uint32_t key_size,
                                        const uint8_t *data, uint32_t data_size,
                                        uint32_t prefix, uint8_t *cipher,
                                        uint32_t cipher_size, uint8_t *out_mac){
    if (key_size != 16) {
      LOG(ERROR) << "invalid key size: " << key_size << ", expect 16!";
      return stbox::stx_status::ecc_invalid_aes_key_size;
    }

    if (cipher_size != data_size + INITIALIZATION_VECTOR_SIZE) {
      LOG(ERROR)
        << "cipher size should equal to data_size + 16";
      return stbox::stx_status::aes_invalid_cipher_size;
    } 

    uint8_t mac_text[AAD_MAC_TEXT_LEN];
    memset(mac_text, 0, AAD_MAC_TEXT_LEN);
    memcpy(mac_text, aad_mac_text, AAD_MAC_TEXT_LEN);
    uint32_t *p_prefix = (uint32_t *)(mac_text + AAD_MAC_PREFIX_POS);
    *p_prefix = prefix;
    uint8_t *p_iv_text = cipher + data_size;
    auto rc = RAND_bytes(p_iv_text, INITIALIZATION_VECTOR_SIZE);
    if (rc != 1) {
      LOG(ERROR) << "RAND_bytes key failed";
      return stbox::stx_status::aes_rand_fail;
    }

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key);
    sm4_gcm_encrypt(&sm4_key, p_iv_text, INITIALIZATION_VECTOR_SIZE, mac_text, AAD_MAC_TEXT_LEN, data, data_size, cipher, 16, out_mac);
    uint8_t hash[32];
    sm3_hash::msg_hash(out_mac, 16, hash, 32);
    memcpy(out_mac, hash, 16);
    return stbox::stx_status::success;
  }

  uint32_t sm4_aes::get_data_size(uint32_t cipher_size){ return cipher_size - INITIALIZATION_VECTOR_SIZE; }
  uint32_t sm4_aes::decrypt_with_prefix(const uint8_t *key, uint32_t key_size,
                                    const uint8_t *cipher, uint32_t cipher_size,
                                    uint32_t prefix, uint8_t *data,
                                    uint32_t data_size, const uint8_t *in_mac){
  if (key_size != 16) {
    LOG(ERROR) << "invalid key size: " << key_size << ", expect 16!";
    return stbox::stx_status::ecc_invalid_aes_key_size;
  }

  if (cipher_size != data_size + INITIALIZATION_VECTOR_SIZE) {
    LOG(ERROR)
        << "cipher size should equal to data_size + INITIALIZATION_VECTOR_SIZE";
    return stbox::stx_status::aes_invalid_data_size;
  }
  uint8_t mac_text[AAD_MAC_TEXT_LEN];
  memset(mac_text, 0, AAD_MAC_TEXT_LEN);
  memcpy(mac_text, aad_mac_text, AAD_MAC_TEXT_LEN);
  uint32_t *p_prefix = (uint32_t *)(mac_text + AAD_MAC_PREFIX_POS);
  *p_prefix = prefix;

  const uint8_t *p_iv_text = cipher + data_size;
  SM4_KEY sm4_key;
  sm4_set_decrypt_key(&sm4_key, key);
  auto se_ret = sm4_gcm_decrypt(&sm4_key, p_iv_text, INITIALIZATION_VECTOR_SIZE, mac_text, AAD_MAC_TEXT_LEN, cipher, cipher_size, in_mac, 16, data);
  return stbox::stx_status::success;
  }

} // namespace crypto
} // namespace ypc
