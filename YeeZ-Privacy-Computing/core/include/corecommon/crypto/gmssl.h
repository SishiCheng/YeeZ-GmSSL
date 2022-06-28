#pragma once
#include "corecommon/crypto/stdeth/sm2_ecc.h"
#include "corecommon/crypto/stdeth/sm3_hash.h"
#include "corecommon/crypto/stdeth/sm4_aes.h"

#include "corecommon/crypto/crypto_pack.h"

namespace ypc {
namespace crypto {
typedef crypto_pack<sm2_ecc, sm3_hash, sm4_aes, sm2_ecc>
    eth_sgx_crypto;
}
} // namespace ypc
