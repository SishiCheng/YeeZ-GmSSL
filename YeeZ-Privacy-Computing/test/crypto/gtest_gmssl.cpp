#include "corecommon/crypto/gmssl/sm3_hash.h"
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
}

