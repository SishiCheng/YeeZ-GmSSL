#include "corecommon/crypto/gmssl/sm3_hash.h"
#include "corecommon/crypto/gmssl/sm2_ecc.h"
#include "corecommon/crypto/gmssl/sm4_aes.h"
#include "ypc/byte.h"
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
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
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

  ypc::bytes expect_hex =
    ypc::hex_bytes(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        .as<ypc::bytes>();
  EXPECT_TRUE(memcmp(skey, expect_hex.data(), 32) == 0);
}

TEST(test_sm2_ecc, generate_pkey_from_skey) {
  ypc::hex_bytes skey_hex(
      "3908a1b53ef489f2e8379298256112c4146475e86ace325c0a4be72b1d7a5043");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  uint8_t pkey[64];
  uint32_t ret = ypc::crypto::sm2_ecc::generate_pkey_from_skey((const uint8_t *)&skey[0], 32,
                                                 (uint8_t *)&pkey[0], 64);
  EXPECT_EQ(ret, 0);

  ypc::hex_bytes expect_hex(
      "5d7ee992f48ffcdb077c2cb57605b602bd4029faed3e91189c7fb9fccc72771e4"
      "5b7aa166766e2ad032d0a195372f5e2d20db792901d559ab0d2bfae10ecea97");
  EXPECT_TRUE(memcmp(pkey, expect_hex.data(), 64) == 0);
}

TEST(test_sm2_ecc, get_signature_size) {
  EXPECT_EQ(ypc::crypto::sm2_ecc::get_signature_size(), 64);
}

TEST(test_sm2_ecc, sign_message) {
  ypc::hex_bytes skey_hex(
      "3908a1b53ef489f2e8379298256112c4146475e86ace325c0a4be72b1d7a5043");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  std::string data = "hello";
  uint32_t data_size = sizeof(data);
  uint8_t sig[64];
  uint32_t ret = ypc::crypto::sm2_ecc::sign_message((const uint8_t *)&skey[0], 32,
                                                  (const uint8_t *)&data[0], data_size,
                                                 (uint8_t *)&sig[0], 64);
  EXPECT_EQ(ret, 0);
}

TEST(test_sm2_ecc, verify_signature) {
  ypc::hex_bytes skey_hex(
      "3908a1b53ef489f2e8379298256112c4146475e86ace325c0a4be72b1d7a5043");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  std::string data = "hello";
  uint32_t data_size = sizeof(data);
  uint8_t sig[64];
  uint32_t sign_ret = ypc::crypto::sm2_ecc::sign_message((const uint8_t *)&skey[0], 32,
                                                  (const uint8_t *)&data[0], data_size,
                                                 (uint8_t *)&sig[0], 64);
  
  ypc::bytes pkey =
    ypc::hex_bytes(
        "362a609ab5a6eecafdb2289890bd7261871c04fb5d7323d4fc750f6444b067a12a96"
        "e"
        "fbe24c62572156caa514657d4a535101d2147337f41f51fcdfcf8f43a53")
        .as<ypc::bytes>();
  uint32_t ret = ypc::crypto::sm2_ecc::verify_signature((const uint8_t *)&data[0], data_size,
                                                (const uint8_t *)&sig[0], 64,
                                                (uint8_t *)&pkey[0], 64);
  EXPECT_EQ(ret, 0);
}

TEST(test_sm2_ecc, ecdh_shared_key) {
  ypc::hex_bytes skey_hex(
      "3908a1b53ef489f2e8379298256112c4146475e86ace325c0a4be72b1d7a5043");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  ypc::bytes pkey =
    ypc::hex_bytes(
        "362a609ab5a6eecafdb2289890bd7261871c04fb5d7323d4fc750f6444b067a12a96"
        "e"
        "fbe24c62572156caa514657d4a535101d2147337f41f51fcdfcf8f43a53")
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
  ypc::bytes pkey("k3Men*p/2.3j4abB");
  ypc::bytes data("this|is|a|test|message");

  ypc::hex_bytes skey_hex(
      "3908a1b53ef489f2e8379298256112c4146475e86ace325c0a4be72b1d7a5043");
  ypc::bytes skey = skey_hex.as<ypc::bytes>();
  ypc::bytes pkey =
    ypc::hex_bytes(
        "362a609ab5a6eecafdb2289890bd7261871c04fb5d7323d4fc750f6444b067a12a96"
        "e"
        "fbe24c62572156caa514657d4a535101d2147337f41f51fcdfcf8f43a53")
        .as<ypc::bytes>();
  uint8_t shared_key[64];

  uint32_t ret = ypc::crypto::sm2_ecc::ecdh_shared_key((const uint8_t *)&skey[0], 32,
                                                (const uint8_t *)&pkey[0], 64,
                                                (uint8_t *)&shared_key[0], 64);
  EXPECT_EQ(ret, 0);
}
