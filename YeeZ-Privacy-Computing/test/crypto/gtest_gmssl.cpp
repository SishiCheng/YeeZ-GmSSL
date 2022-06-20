#include "corecommon/crypto/gmssl/sm2_ecc.h"
#include "corecommon/crypto/gmssl/sm3_hash.h"
#include "corecommon/crypto/gmssl/sm4_aes.h"
#include "ypc/byte.h"
#include <gmssl/sm2.h>
#include <gtest/gtest.h>

TEST(test_sm3_hash, sha3_256) {
  std::string msg = "hello";
  uint8_t hash[32];
  uint32_t ret = ypc::crypto::sm3_hash::sha3_256((const uint8_t *)&msg[0],
                                                 msg.size(), hash);
  EXPECT_EQ(ret, 0);
  ypc::bytes expect_hash =
      ypc::hex_bytes(
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
          .as<ypc::bytes>();
  EXPECT_TRUE(memcmp(hash, expect_hash.data(), 32) == 0);
}

TEST(test_sm3_hash, get_msg_hash_size) {
  EXPECT_EQ(ypc::crypto::sm3_hash::get_msg_hash_size(), 32);
}


TEST(test_sm3_hash, msg_hash) {
  std::string raw_msg = "hello";
  uint8_t hash[32];
  uint32_t ret = ypc::crypto::sm3_hash::msg_hash((const uint8_t *)&raw_msg[0],
                                                 raw_msg.size(), hash, 32);
  EXPECT_EQ(ret, 0);
  ypc::bytes expect_hash =
      ypc::hex_bytes(
          "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268")
          .as<ypc::bytes>();
  EXPECT_TRUE(memcmp(hash, expect_hash.data(), 32) == 0);
}

TEST(test_sm2_ecc, get_private_key_size) {
  EXPECT_EQ(ypc::crypto::sm2_ecc::get_private_key_size(), 32);
}

TEST(test_sm2_ecc, get_public_key_size) {
  EXPECT_EQ(ypc::crypto::sm2_ecc::get_public_key_size(), 64);
}

TEST(test_sm2_ecc, gen_private_key) {
  uint8_t skey[32];
  uint32_t ret = ypc::crypto::sm2_ecc::gen_private_key(32,
                                                 (uint8_t *)&skey[0]);
  EXPECT_EQ(ret, 0);
}

void get_expected_pkey(const ypc::bytes &skey, ypc::bytes &pkey) {
  SM2_KEY tmp;
  sm2_key_set_private_key(&tmp, skey.data());
  memcpy(pkey.data(), &tmp, 64);
  /*
  for (int i = 0; i < 64; i++) {
    printf("%02x", *(pkey.data() + i));
  }
  std::cout << std::endl;
  */
}

TEST(test_sm2_ecc, generate_pkey_from_skey) {
  ypc::hex_bytes skey_hex(
      "4f16ab84f1d146f036332f30cc00d76c6b598c01887d88d935e728d221f4506e");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  uint8_t pkey[64];
  uint32_t ret = ypc::crypto::sm2_ecc::generate_pkey_from_skey(
      skey.data(), skey.size(), pkey, 64);
  EXPECT_EQ(ret, 0);
  ypc::bytes expect_pkey(64);
  get_expected_pkey(skey, expect_pkey);
  EXPECT_TRUE(memcmp(pkey, expect_pkey.data(), 64) == 0);
}

TEST(test_sm2_ecc, get_signature_size) {
  EXPECT_EQ(ypc::crypto::sm2_ecc::get_signature_size(), 64);
}

TEST(test_sm2_ecc, sign) {
  ypc::hex_bytes skey_hex(
      "4f16ab84f1d146f036332f30cc00d76c6b598c01887d88d935e728d221f4506e");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  std::string data = "hello";
  uint32_t data_size = sizeof(data);
  uint8_t sig[64];
  std::cout << "start sign" << std::endl;
  uint32_t sign_ret = ypc::crypto::sm2_ecc::sign_message((const uint8_t *)&skey[0], 32,
                                                  (const uint8_t *)&data[0], data_size,
                                                 (uint8_t *)&sig[0], 64);
  std::cout << "end sign" << std::endl;
  ypc::bytes expect_pkey(64);
  get_expected_pkey(skey, expect_pkey);
  uint32_t ret = ypc::crypto::sm2_ecc::verify_signature((const uint8_t *)&data[0], data_size,
                                                (const uint8_t *)&sig[0], 64,
                                                (uint8_t *)&expect_pkey[0], 64);
  EXPECT_EQ(ret, 0);
}


TEST(test_sm2_ecc, ecdh_shared_key) {
  ypc::hex_bytes skey_hex(
      "4f16ab84f1d146f036332f30cc00d76c6b598c01887d88d935e728d221f4506e");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  ypc::bytes pkey =
    ypc::hex_bytes(
      "74ce7141e217c7c1d29fabc2459e408311aad0bc7417c5c159860c7ac64d9d36c"
      "900cfcb6ae534f60f9f621b29219b16d590d64888784229f7fbe5a4cad5477c")
        .as<ypc::bytes>();
  uint8_t shared_key[64];

  uint32_t ret = ypc::crypto::sm2_ecc::ecdh_shared_key((const uint8_t *)&skey[0], 32,
                                                (const uint8_t *)&pkey[0], 64,
                                                (uint8_t *)&shared_key[0], 64);
  EXPECT_EQ(ret, 0);
}

TEST(test_sm4_aes, get_cipher_size) {
  std::string data = "hello";
  uint32_t data_size = sizeof(data);
  EXPECT_EQ(ypc::crypto::sm4_aes::get_cipher_size(data_size), data_size + 12);
}

TEST(test_sm4_aes, encrypt_with_prefix) {
  ypc::bytes key("k3Men*p/2.3j4abB");
  std::string data = "this|is|a|test|message";
  uint32_t data_size = sizeof(data);
  uint32_t prefix = 0x1;
  uint32_t cipher_size = sizeof(data) + 12;
  uint8_t cipher[cipher_size];
  uint8_t out_mac[16];

  uint32_t ret = ypc::crypto::sm4_aes::encrypt_with_prefix((const uint8_t *)&key[0], 16,
                                                (const uint8_t *)&data[0], data_size, prefix,
                                                (uint8_t *)&cipher[0], cipher_size, &out_mac[0]);
  EXPECT_EQ(ret, 0);
}

TEST(test_sm4_aes, get_data_size) {
  uint32_t cipher_size = 0x25;
  EXPECT_EQ(ypc::crypto::sm4_aes::get_data_size(cipher_size), cipher_size - 12);
}

TEST(test_sm4_aes, decrypt_with_prefix) {
  ypc::bytes key("k3Men*p/2.3j4abB");
  std::string cipher = "this|is|a|test|messageihugyufhuidr";
  uint32_t cipher_size = sizeof(cipher);
  uint32_t prefix = 0x1;
  uint8_t data[cipher_size - 12];
  uint8_t in_mac[16];

  uint32_t ret = ypc::crypto::sm4_aes::decrypt_with_prefix((const uint8_t *)&key[0], 16,
                                                (const uint8_t *)&cipher[0], cipher_size, prefix,
                                                (uint8_t *)&data[0], cipher_size - 12, &in_mac[0]);
  EXPECT_EQ(ret, 0);
}
