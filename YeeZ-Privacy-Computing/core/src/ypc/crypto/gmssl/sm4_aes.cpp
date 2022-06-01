#include "corecommon/crypto/gmssl/sm4_aes.h"
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

  uint32_t sm4_aes::get_encrypt_message_size_with_prefix(uint32_t data_size){ return data_size + 16; }

  uint32_t sm4_aes::encrypt_message_with_prefix(const uint8_t *public_key,
                                              uint32_t pkey_size,
                                              const uint8_t *data,
                                              uint32_t data_size,
                                              uint32_t prefix, uint8_t *cipher,
                                              uint32_t cipher_size){
    if (pkey_size != 16) {
      LOG(ERROR) << "invalid key size: " << pkey_size << ", expect 16!";
      return stbox::stx_status::ecc_invalid_aes_key_size;
    }

    if (cipher_size != data_size + 16) {
      LOG(ERROR)
        << "cipher size should equal to data_size + 16";
      return stbox::stx_status::aes_invalid_cipher_size;
    } 

    uint8_t *p_iv_text = cipher + data_size;
    auto rc = RAND_bytes(p_iv_text, 16);
    if (rc != 1) {
      LOG(ERROR) << "RAND_bytes key failed";
      return stbox::stx_status::aes_rand_fail;
    }

    SM4_KEY key;
    sm4_set_encrypt_key(&key, public_key);
    uint8_t mac_text[AAD_MAC_TEXT_LEN];
    memset(mac_text, 0, AAD_MAC_TEXT_LEN);
    memcpy(mac_text, aad_mac_text, AAD_MAC_TEXT_LEN);
    uint32_t *p_prefix = (uint32_t *)(mac_text + AAD_MAC_PREFIX_POS);
    *p_prefix = prefix;
    uint8_t tag;
    sm4_gcm_encrypt(&key, p_iv_text, SM4_GCM_IV_DEFAULT_SIZE, mac_text, AAD_MAC_TEXT_LEN, data, data_size, cipher, 16, &tag);
    return stbox::stx_status::success;       
  }

  uint32_t sm4_aes::get_decrypt_message_size_with_prefix(uint32_t cipher_size){ return cipher_size - 16; }
  uint32_t sm4_aes::decrypt_message_with_prefix(const uint8_t *private_key,
                                              uint32_t private_key_size,
                                              const uint8_t *cipher,
                                              uint32_t cipher_size,
                                              uint8_t *data, uint32_t data_size,
                                              uint32_t prefix){
  if (private_key_size != 16) {
    LOG(ERROR) << "invalid key size: " << private_key << ", expect 16!";
    return stbox::stx_status::ecc_invalid_aes_key_size;
  }

  if (cipher_size != data_size + 16) {
    LOG(ERROR)
        << "cipher size should equal to data_size + 16";
    return stbox::stx_status::aes_invalid_data_size;
  }

  SM4_KEY key;
  sm4_set_decrypt_key(&key, private_key);
  const uint8_t *p_iv_text = cipher + data_size;
  uint8_t mac_text[AAD_MAC_TEXT_LEN];
  memset(mac_text, 0, AAD_MAC_TEXT_LEN);
  memcpy(mac_text, aad_mac_text, AAD_MAC_TEXT_LEN);

  
  sm4_gcm_decrypt(&key, p_iv_text, 12, mac_text, AAD_MAC_TEXT_LEN, cipher, cipher_size, cipher + data_size, 16, data);
  return stbox::stx_status::success; 
  }

} // namespace crypto
} // namespace ypc
