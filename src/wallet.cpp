#include "wallet.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <array>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cctype>
#include <vector>
#include <cstdio>
#include <memory>

static std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool fromHex(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.length() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        int high = hexValue(hex[i * 2]);
        int low = hexValue(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

static std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

static std::string trim(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

static void keccakF1600(uint64_t state[25]) {
    static const uint64_t roundConstants[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static const int rotations[24] = {
        1, 3, 6, 10, 15, 21,
        28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43,
        62, 18, 39, 61, 20, 44
    };

    static const int pi[24] = {
        10, 7, 11, 17, 18, 3,
        5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2,
        20, 14, 22, 9, 6, 1
    };

    auto rotl64 = [](uint64_t value, int shift) -> uint64_t {
        return (value << shift) | (value >> (64 - shift));
    };

    for (int round = 0; round < 24; ++round) {
        uint64_t c[5] = {};
        for (int i = 0; i < 5; ++i) {
            c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        uint64_t d[5] = {};
        for (int i = 0; i < 5; ++i) {
            d[i] = c[(i + 4) % 5] ^ rotl64(c[(i + 1) % 5], 1);
        }

        for (int i = 0; i < 25; i += 5) {
            for (int j = 0; j < 5; ++j) {
                state[i + j] ^= d[j];
            }
        }

        uint64_t current = state[1];
        for (int i = 0; i < 24; ++i) {
            int j = pi[i];
            uint64_t temp = state[j];
            state[j] = rotl64(current, rotations[i]);
            current = temp;
        }

        for (int i = 0; i < 25; i += 5) {
            uint64_t row[5] = { state[i], state[i + 1], state[i + 2], state[i + 3], state[i + 4] };
            for (int j = 0; j < 5; ++j) {
                state[i + j] = row[j] ^ ((~row[(j + 1) % 5]) & row[(j + 2) % 5]);
            }
        }

        state[0] ^= roundConstants[round];
    }
}

static void keccak256(const unsigned char* data, size_t len, unsigned char out[32]) {
    constexpr size_t rateBytes = 136;
    uint64_t state[25] = {};

    while (len >= rateBytes) {
        for (size_t i = 0; i < rateBytes / 8; ++i) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; ++b) {
                lane |= static_cast<uint64_t>(data[i * 8 + b]) << (8 * b);
            }
            state[i] ^= lane;
        }
        keccakF1600(state);
        data += rateBytes;
        len -= rateBytes;
    }

    std::array<unsigned char, rateBytes> block{};
    if (len > 0) {
        std::memcpy(block.data(), data, len);
    }
    block[len] ^= 0x01;
    block[rateBytes - 1] ^= 0x80;

    for (size_t i = 0; i < rateBytes / 8; ++i) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; ++b) {
            lane |= static_cast<uint64_t>(block[i * 8 + b]) << (8 * b);
        }
        state[i] ^= lane;
    }
    keccakF1600(state);

    for (size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<unsigned char>((state[i / 8] >> (8 * (i % 8))) & 0xFFU);
    }
}

struct NetworkConfig {
    std::string canonicalName;
    std::string symbol;
    std::string rpcUrl;
    std::vector<std::string> aliases;
};

struct BNDeleter {
    void operator()(BIGNUM* value) const {
        BN_free(value);
    }
};

struct ECDSASigDeleter {
    void operator()(ECDSA_SIG* value) const {
        ECDSA_SIG_free(value);
    }
};

using UniqueBN = std::unique_ptr<BIGNUM, BNDeleter>;
using UniqueSig = std::unique_ptr<ECDSA_SIG, ECDSASigDeleter>;

static const std::vector<NetworkConfig>& supportedNetworks() {
    static const std::vector<NetworkConfig> networks = {
        { "eth-sepolia", "ETH", "https://ethereum-sepolia-rpc.publicnode.com", { "ethereum", "sepolia", "eth" } },
        { "bsc-testnet", "tBNB", "https://bsc-testnet-rpc.publicnode.com", { "binance", "bsc", "bnb" } },
        { "polygon-amoy", "POL", "https://polygon-amoy-bor-rpc.publicnode.com", { "polygon", "amoy", "matic" } }
    };
    return networks;
}

static bool resolveNetwork(const std::string& networkName, NetworkConfig& config) {
    std::string normalized = toLower(networkName);
    const auto& networks = supportedNetworks();
    for (const auto& network : networks) {
        if (normalized == network.canonicalName) {
            config = network;
            return true;
        }
        for (const auto& alias : network.aliases) {
            if (normalized == alias) {
                config = network;
                return true;
            }
        }
    }
    return false;
}

static bool deriveAddressFromPrivateHex(const std::string& privHex, std::string& addressOut) {
    unsigned char privKey[32];
    if (!fromHex(privHex, privKey, 32)) {
        return false;
    }

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        return false;
    }

    BIGNUM* privBn = BN_bin2bn(privKey, 32, nullptr);
    if (!privBn) {
        EC_KEY_free(ecKey);
        return false;
    }

    if (EC_KEY_set_private_key(ecKey, privBn) != 1) {
        BN_free(privBn);
        EC_KEY_free(ecKey);
        return false;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pubPoint = EC_POINT_new(group);
    if (!pubPoint) {
        BN_free(privBn);
        EC_KEY_free(ecKey);
        return false;
    }

    if (EC_POINT_mul(group, pubPoint, privBn, nullptr, nullptr, nullptr) != 1 ||
        EC_KEY_set_public_key(ecKey, pubPoint) != 1) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        return false;
    }

    size_t pubLen = EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (pubLen != 65) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        return false;
    }

    std::array<unsigned char, 65> pubKey{};
    if (EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, pubKey.data(), pubKey.size(), nullptr) != pubKey.size()) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        return false;
    }

    unsigned char hash[32];
    keccak256(pubKey.data() + 1, 64, hash);
    addressOut = "0x" + toHex(hash + 12, 20);

    EC_POINT_free(pubPoint);
    BN_free(privBn);
    EC_KEY_free(ecKey);
    return true;
}

static bool loadPrivateHex(std::string& privHex) {
    std::ifstream infile("data/wallet.dat");
    if (!infile) {
        return false;
    }
    infile >> privHex;
    return privHex.length() == 64;
}

static bool parseJsonRpcResultHex(const std::string& response, std::string& resultHex) {
    std::size_t keyPos = response.find("\"result\"");
    if (keyPos == std::string::npos) return false;
    std::size_t colonPos = response.find(':', keyPos);
    if (colonPos == std::string::npos) return false;
    std::size_t firstQuote = response.find('"', colonPos);
    if (firstQuote == std::string::npos) return false;
    std::size_t secondQuote = response.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos) return false;
    resultHex = response.substr(firstQuote + 1, secondQuote - firstQuote - 1);
    return !resultHex.empty();
}

static std::string parseJsonRpcError(const std::string& response) {
    std::size_t errorPos = response.find("\"error\"");
    if (errorPos == std::string::npos) {
        return "";
    }

    std::size_t msgPos = response.find("\"message\"", errorPos);
    if (msgPos == std::string::npos) {
        return "RPC returned an error";
    }

    std::size_t colonPos = response.find(':', msgPos);
    if (colonPos == std::string::npos) {
        return "RPC returned an error";
    }

    std::size_t firstQuote = response.find('"', colonPos + 1);
    if (firstQuote == std::string::npos) {
        return "RPC returned an error";
    }

    std::size_t secondQuote = response.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos) {
        return "RPC returned an error";
    }

    return response.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

static bool rpcCall(const NetworkConfig& network, const std::string& method, const std::string& paramsJson, std::string& responseBody, std::string& error) {
    std::string payload = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\",\"params\":" + paramsJson + ",\"id\":1}";
    std::string command = "curl -sS --max-time 20 -H 'Content-Type: application/json' -d '" + payload + "' '" + network.rpcUrl + "'";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        error = "Failed to launch curl command";
        return false;
    }

    responseBody.clear();
    std::array<char, 4096> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        responseBody += buffer.data();
    }

    int rc = pclose(pipe);
    if (rc != 0) {
        error = "RPC request failed";
        return false;
    }

    std::string rpcError = parseJsonRpcError(responseBody);
    if (!rpcError.empty()) {
        error = rpcError;
        return false;
    }

    return true;
}

static bool rpcCallResultHex(const NetworkConfig& network, const std::string& method, const std::string& paramsJson, std::string& resultHex, std::string& error) {
    std::string responseBody;
    if (!rpcCall(network, method, paramsJson, responseBody, error)) {
        return false;
    }

    if (!parseJsonRpcResultHex(responseBody, resultHex)) {
        error = "Failed to parse RPC response";
        return false;
    }

    return true;
}

static std::string stripHexPrefix(const std::string& value) {
    if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
        return value.substr(2);
    }
    return value;
}

static bool isValidHexString(const std::string& value) {
    for (char c : value) {
        if (hexValue(c) < 0) {
            return false;
        }
    }
    return true;
}

static bool isValidAddress(const std::string& address) {
    if (address.size() != 42) return false;
    if (!(address.rfind("0x", 0) == 0 || address.rfind("0X", 0) == 0)) return false;
    return isValidHexString(address.substr(2));
}

static std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.empty()) {
        return bytes;
    }

    std::string normalized = (hex.size() % 2 == 0) ? hex : ("0" + hex);
    bytes.resize(normalized.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        int high = hexValue(normalized[i * 2]);
        int low = hexValue(normalized[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return {};
        }
        bytes[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return bytes;
}

static std::vector<unsigned char> trimLeadingZeros(const std::vector<unsigned char>& bytes) {
    std::size_t firstNonZero = 0;
    while (firstNonZero < bytes.size() && bytes[firstNonZero] == 0) {
        ++firstNonZero;
    }
    return std::vector<unsigned char>(bytes.begin() + static_cast<long>(firstNonZero), bytes.end());
}

static std::vector<unsigned char> bnToMinimalBytes(const BIGNUM* value) {
    if (!value || BN_is_zero(value)) {
        return {};
    }

    int len = BN_num_bytes(value);
    std::vector<unsigned char> bytes(static_cast<std::size_t>(len));
    BN_bn2bin(value, bytes.data());
    return trimLeadingZeros(bytes);
}

static std::vector<unsigned char> encodeLength(std::size_t len) {
    std::vector<unsigned char> bytes;
    while (len > 0) {
        bytes.push_back(static_cast<unsigned char>(len & 0xFFU));
        len >>= 8;
    }
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

static std::vector<unsigned char> rlpEncodeBytes(const std::vector<unsigned char>& input) {
    if (input.size() == 1 && input[0] < 0x80) {
        return input;
    }

    std::vector<unsigned char> encoded;
    if (input.size() <= 55) {
        encoded.push_back(static_cast<unsigned char>(0x80 + input.size()));
    } else {
        auto lenBytes = encodeLength(input.size());
        encoded.push_back(static_cast<unsigned char>(0xB7 + lenBytes.size()));
        encoded.insert(encoded.end(), lenBytes.begin(), lenBytes.end());
    }
    encoded.insert(encoded.end(), input.begin(), input.end());
    return encoded;
}

static std::vector<unsigned char> rlpEncodeInteger(const BIGNUM* value) {
    return rlpEncodeBytes(bnToMinimalBytes(value));
}

static std::vector<unsigned char> rlpEncodeList(const std::vector<unsigned char>& payload) {
    std::vector<unsigned char> encoded;
    if (payload.size() <= 55) {
        encoded.push_back(static_cast<unsigned char>(0xC0 + payload.size()));
    } else {
        auto lenBytes = encodeLength(payload.size());
        encoded.push_back(static_cast<unsigned char>(0xF7 + lenBytes.size()));
        encoded.insert(encoded.end(), lenBytes.begin(), lenBytes.end());
    }
    encoded.insert(encoded.end(), payload.begin(), payload.end());
    return encoded;
}

static void appendBytes(std::vector<unsigned char>& dst, const std::vector<unsigned char>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

static bool parseNativeAmountWei(const std::string& amountNative, UniqueBN& amountWei) {
    std::string value = trim(amountNative);
    if (value.empty()) return false;

    std::size_t dotPos = value.find('.');
    if (dotPos != std::string::npos && value.find('.', dotPos + 1) != std::string::npos) {
        return false;
    }

    std::string whole = value;
    std::string fraction;
    if (dotPos != std::string::npos) {
        whole = value.substr(0, dotPos);
        fraction = value.substr(dotPos + 1);
    }

    if (whole.empty()) whole = "0";
    auto isDigitChar = [](unsigned char c) { return std::isdigit(c) != 0; };
    if (!std::all_of(whole.begin(), whole.end(), [&](char c) { return isDigitChar(static_cast<unsigned char>(c)); })) return false;
    if (!std::all_of(fraction.begin(), fraction.end(), [&](char c) { return isDigitChar(static_cast<unsigned char>(c)); })) return false;
    if (fraction.size() > 18) return false;

    while (fraction.size() < 18) {
        fraction.push_back('0');
    }

    std::string weiDec = whole + fraction;
    std::size_t firstNonZero = weiDec.find_first_not_of('0');
    if (firstNonZero == std::string::npos) {
        weiDec = "0";
    } else {
        weiDec = weiDec.substr(firstNonZero);
    }

    BIGNUM* parsed = nullptr;
    if (BN_dec2bn(&parsed, weiDec.c_str()) == 0 || parsed == nullptr) {
        return false;
    }

    amountWei.reset(parsed);
    return true;
}

static bool buildKeyFromPrivateHex(const std::string& privHex, EC_KEY*& ecKeyOut, BIGNUM*& privBnOut, EC_POINT*& pubPointOut) {
    ecKeyOut = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKeyOut) return false;

    unsigned char privBytes[32];
    if (!fromHex(privHex, privBytes, 32)) {
        EC_KEY_free(ecKeyOut);
        ecKeyOut = nullptr;
        return false;
    }

    privBnOut = BN_bin2bn(privBytes, 32, nullptr);
    if (!privBnOut) {
        EC_KEY_free(ecKeyOut);
        ecKeyOut = nullptr;
        return false;
    }

    if (EC_KEY_set_private_key(ecKeyOut, privBnOut) != 1) {
        BN_free(privBnOut);
        EC_KEY_free(ecKeyOut);
        privBnOut = nullptr;
        ecKeyOut = nullptr;
        return false;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKeyOut);
    pubPointOut = EC_POINT_new(group);
    if (!pubPointOut) {
        BN_free(privBnOut);
        EC_KEY_free(ecKeyOut);
        privBnOut = nullptr;
        ecKeyOut = nullptr;
        return false;
    }

    if (EC_POINT_mul(group, pubPointOut, privBnOut, nullptr, nullptr, nullptr) != 1 ||
        EC_KEY_set_public_key(ecKeyOut, pubPointOut) != 1) {
        EC_POINT_free(pubPointOut);
        BN_free(privBnOut);
        EC_KEY_free(ecKeyOut);
        pubPointOut = nullptr;
        privBnOut = nullptr;
        ecKeyOut = nullptr;
        return false;
    }

    return true;
}

static int findRecoveryId(const EC_GROUP* group, const BIGNUM* order, const BIGNUM* r, const BIGNUM* s,
                          const unsigned char hash32[32], const EC_POINT* expectedPubKey) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return -1;

    BIGNUM* fieldP = BN_new();
    BIGNUM* fieldA = BN_new();
    BIGNUM* fieldB = BN_new();
    BIGNUM* e = BN_bin2bn(hash32, 32, nullptr);
    BIGNUM* eMod = BN_new();
    BIGNUM* eNeg = BN_new();
    BIGNUM* rInv = BN_mod_inverse(nullptr, r, order, ctx);
    BIGNUM* x = BN_new();
    BIGNUM* jMulN = BN_new();
    BIGNUM* srInv = BN_new();
    BIGNUM* eInv = BN_new();
    EC_POINT* rPoint = EC_POINT_new(group);
    EC_POINT* qPoint = EC_POINT_new(group);

    if (!fieldP || !fieldA || !fieldB || !e || !eMod || !eNeg || !rInv || !x || !jMulN || !srInv || !eInv || !rPoint || !qPoint) {
        BN_free(fieldP); BN_free(fieldA); BN_free(fieldB); BN_free(e); BN_free(eMod); BN_free(eNeg);
        BN_free(rInv); BN_free(x); BN_free(jMulN); BN_free(srInv); BN_free(eInv);
        if (rPoint) EC_POINT_free(rPoint);
        if (qPoint) EC_POINT_free(qPoint);
        BN_CTX_free(ctx);
        return -1;
    }

    if (EC_GROUP_get_curve(group, fieldP, fieldA, fieldB, ctx) != 1 ||
        BN_nnmod(eMod, e, order, ctx) != 1 ||
        BN_set_word(eNeg, 0) != 1 ||
        BN_mod_sub(eNeg, eNeg, eMod, order, ctx) != 1) {
        BN_free(fieldP); BN_free(fieldA); BN_free(fieldB); BN_free(e); BN_free(eMod); BN_free(eNeg);
        BN_free(rInv); BN_free(x); BN_free(jMulN); BN_free(srInv); BN_free(eInv);
        EC_POINT_free(rPoint); EC_POINT_free(qPoint);
        BN_CTX_free(ctx);
        return -1;
    }

    for (int recId = 0; recId < 4; ++recId) {
        int j = recId / 2;
        int yBit = recId % 2;

        if (BN_set_word(jMulN, static_cast<unsigned long>(j)) != 1 ||
            BN_mul(jMulN, jMulN, order, ctx) != 1 ||
            BN_copy(x, r) == nullptr ||
            BN_add(x, x, jMulN) != 1) {
            continue;
        }

        if (BN_cmp(x, fieldP) >= 0) {
            continue;
        }

        if (EC_POINT_set_compressed_coordinates(group, rPoint, x, yBit, ctx) != 1) {
            continue;
        }

        if (EC_POINT_is_on_curve(group, rPoint, ctx) != 1) {
            continue;
        }

        if (EC_POINT_mul(group, qPoint, nullptr, rPoint, order, ctx) != 1 ||
            EC_POINT_is_at_infinity(group, qPoint) != 1) {
            continue;
        }

        if (BN_mod_mul(srInv, s, rInv, order, ctx) != 1 ||
            BN_mod_mul(eInv, eNeg, rInv, order, ctx) != 1 ||
            EC_POINT_mul(group, qPoint, eInv, rPoint, srInv, ctx) != 1) {
            continue;
        }

        if (EC_POINT_cmp(group, qPoint, expectedPubKey, ctx) == 0) {
            BN_free(fieldP); BN_free(fieldA); BN_free(fieldB); BN_free(e); BN_free(eMod); BN_free(eNeg);
            BN_free(rInv); BN_free(x); BN_free(jMulN); BN_free(srInv); BN_free(eInv);
            EC_POINT_free(rPoint); EC_POINT_free(qPoint);
            BN_CTX_free(ctx);
            return recId;
        }
    }

    BN_free(fieldP); BN_free(fieldA); BN_free(fieldB); BN_free(e); BN_free(eMod); BN_free(eNeg);
    BN_free(rInv); BN_free(x); BN_free(jMulN); BN_free(srInv); BN_free(eInv);
    EC_POINT_free(rPoint); EC_POINT_free(qPoint);
    BN_CTX_free(ctx);
    return -1;
}

static bool signLegacyTransaction(const std::string& privHex,
                                  const std::string& toAddress,
                                  const BIGNUM* amountWei,
                                  const BIGNUM* nonce,
                                  const BIGNUM* gasPrice,
                                  const BIGNUM* gasLimit,
                                  unsigned long long chainId,
                                  std::string& rawTxHex,
                                  std::string& error) {
    EC_KEY* ecKey = nullptr;
    BIGNUM* privBn = nullptr;
    EC_POINT* pubPoint = nullptr;
    if (!buildKeyFromPrivateHex(privHex, ecKey, privBn, pubPoint)) {
        error = "Failed to load private key";
        return false;
    }

    UniqueBN chainIdBn(BN_new());
    UniqueBN zeroBn(BN_new());
    if (!chainIdBn || !zeroBn || BN_set_word(chainIdBn.get(), chainId) != 1 || BN_set_word(zeroBn.get(), 0) != 1) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to initialize transaction values";
        return false;
    }

    std::string toHexAddress = stripHexPrefix(toAddress);
    auto toBytes = hexToBytes(toHexAddress);
    if (toBytes.size() != 20) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Invalid recipient address";
        return false;
    }

    std::vector<unsigned char> unsignedPayload;
    appendBytes(unsignedPayload, rlpEncodeInteger(nonce));
    appendBytes(unsignedPayload, rlpEncodeInteger(gasPrice));
    appendBytes(unsignedPayload, rlpEncodeInteger(gasLimit));
    appendBytes(unsignedPayload, rlpEncodeBytes(toBytes));
    appendBytes(unsignedPayload, rlpEncodeInteger(amountWei));
    appendBytes(unsignedPayload, rlpEncodeBytes({}));
    appendBytes(unsignedPayload, rlpEncodeInteger(chainIdBn.get()));
    appendBytes(unsignedPayload, rlpEncodeInteger(zeroBn.get()));
    appendBytes(unsignedPayload, rlpEncodeInteger(zeroBn.get()));

    std::vector<unsigned char> unsignedTx = rlpEncodeList(unsignedPayload);
    unsigned char txHash[32];
    keccak256(unsignedTx.data(), unsignedTx.size(), txHash);

    UniqueSig signature(ECDSA_do_sign(txHash, 32, ecKey));
    if (!signature) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to sign transaction";
        return false;
    }

    const BIGNUM* sigR = nullptr;
    const BIGNUM* sigS = nullptr;
    ECDSA_SIG_get0(signature.get(), &sigR, &sigS);
    UniqueBN r(BN_dup(sigR));
    UniqueBN s(BN_dup(sigS));
    if (!r || !s) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to read signature";
        return false;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    UniqueBN order(BN_new());
    UniqueBN halfOrder(BN_new());
    BN_CTX* bnCtx = BN_CTX_new();
    if (!order || !halfOrder || !bnCtx ||
        EC_GROUP_get_order(group, order.get(), bnCtx) != 1 ||
        BN_rshift1(halfOrder.get(), order.get()) != 1) {
        if (bnCtx) BN_CTX_free(bnCtx);
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to read curve order";
        return false;
    }

    if (BN_cmp(s.get(), halfOrder.get()) > 0) {
        if (BN_sub(s.get(), order.get(), s.get()) != 1) {
            BN_CTX_free(bnCtx);
            EC_POINT_free(pubPoint);
            BN_free(privBn);
            EC_KEY_free(ecKey);
            error = "Failed to normalize signature";
            return false;
        }
    }

    int recId = findRecoveryId(group, order.get(), r.get(), s.get(), txHash, pubPoint);
    BN_CTX_free(bnCtx);
    if (recId < 0) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to recover signature id";
        return false;
    }

    unsigned long long vValue = chainId * 2ULL + 35ULL + static_cast<unsigned long long>(recId);
    UniqueBN v(BN_new());
    if (!v || BN_set_word(v.get(), vValue) != 1) {
        EC_POINT_free(pubPoint);
        BN_free(privBn);
        EC_KEY_free(ecKey);
        error = "Failed to finalize signature";
        return false;
    }

    std::vector<unsigned char> signedPayload;
    appendBytes(signedPayload, rlpEncodeInteger(nonce));
    appendBytes(signedPayload, rlpEncodeInteger(gasPrice));
    appendBytes(signedPayload, rlpEncodeInteger(gasLimit));
    appendBytes(signedPayload, rlpEncodeBytes(toBytes));
    appendBytes(signedPayload, rlpEncodeInteger(amountWei));
    appendBytes(signedPayload, rlpEncodeBytes({}));
    appendBytes(signedPayload, rlpEncodeInteger(v.get()));
    appendBytes(signedPayload, rlpEncodeInteger(r.get()));
    appendBytes(signedPayload, rlpEncodeInteger(s.get()));

    std::vector<unsigned char> signedTx = rlpEncodeList(signedPayload);
    rawTxHex = "0x" + toHex(signedTx.data(), signedTx.size());

    EC_POINT_free(pubPoint);
    BN_free(privBn);
    EC_KEY_free(ecKey);
    return true;
}

static bool fetchBalanceHex(const NetworkConfig& network, const std::string& address, std::string& balanceHex, std::string& error) {
    return rpcCallResultHex(network, "eth_getBalance", "[\"" + address + "\",\"latest\"]", balanceHex, error);
}

static std::string formatWeiAsNative(const std::string& weiHex) {
    std::string normalized = weiHex;
    if (normalized.rfind("0x", 0) == 0 || normalized.rfind("0X", 0) == 0) {
        normalized = normalized.substr(2);
    }
    if (normalized.empty()) {
        return "0";
    }

    BIGNUM* amountWei = nullptr;
    if (BN_hex2bn(&amountWei, normalized.c_str()) == 0 || amountWei == nullptr) {
        return "0";
    }

    char* decimalRaw = BN_bn2dec(amountWei);
    std::string decimal = decimalRaw ? decimalRaw : "0";
    if (decimalRaw) {
        OPENSSL_free(decimalRaw);
    }
    BN_free(amountWei);

    constexpr size_t decimals = 18;
    if (decimal.size() <= decimals) {
        decimal.insert(0, decimals - decimal.size() + 1, '0');
    }

    std::string whole = decimal.substr(0, decimal.size() - decimals);
    std::string fraction = decimal.substr(decimal.size() - decimals);

    while (!fraction.empty() && fraction.back() == '0') {
        fraction.pop_back();
    }

    if (fraction.empty()) {
        return whole;
    }

    return whole + "." + fraction;
}

void createWallet() {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        std::cerr << "Failed to create EC_KEY\n";
        return;
    }

    if (EC_KEY_generate_key(ecKey) != 1) {
        std::cerr << "Failed to generate key pair\n";
        EC_KEY_free(ecKey);
        return;
    }

    const BIGNUM* privBn = EC_KEY_get0_private_key(ecKey);
    if (!privBn) {
        std::cerr << "Failed to get private key\n";
        EC_KEY_free(ecKey);
        return;
    }

    unsigned char privKey[32];
    std::memset(privKey, 0, 32);
    if (BN_bn2binpad(privBn, privKey, 32) != 32) {
        std::cerr << "Failed to convert private key\n";
        EC_KEY_free(ecKey);
        return;
    }

    std::string privHex = toHex(privKey, 32);

    std::ofstream outfile("data/wallet.dat");
    if (!outfile) {
        std::cerr << "Failed to open wallet.dat for writing\n";
        EC_KEY_free(ecKey);
        return;
    }
    outfile << privHex;
    outfile.close();

    std::string address;
    if (!deriveAddressFromPrivateHex(privHex, address)) {
        std::cerr << "Failed to derive address\n";
        EC_KEY_free(ecKey);
        return;
    }

    EC_KEY_free(ecKey);

    std::cout << "Wallet created successfully!\n";
    std::cout << "Address: " << address << "\n";
    std::cout << "Private key saved to data/wallet.dat\n";
}

void showAddress() {
    std::string privHex;
    if (!loadPrivateHex(privHex)) {
        std::cerr << "No wallet found. Create one first.\n";
        return;
    }

    std::string address;
    if (!deriveAddressFromPrivateHex(privHex, address)) {
        std::cerr << "Invalid wallet file\n";
        return;
    }

    std::cout << "Address: " << address << "\n";
}

void listSupportedNetworks() {
    std::cout << "Supported networks:\n";
    for (const auto& network : supportedNetworks()) {
        std::cout << "  - " << network.canonicalName << " (aliases: ";
        for (size_t i = 0; i < network.aliases.size(); ++i) {
            std::cout << network.aliases[i];
            if (i + 1 < network.aliases.size()) {
                std::cout << ", ";
            }
        }
        std::cout << ")\n";
    }
}

void showBalance(const std::string& networkName) {
    NetworkConfig network;
    if (!resolveNetwork(networkName, network)) {
        std::cerr << "Unsupported network: " << networkName << "\n";
        listSupportedNetworks();
        return;
    }

    std::string privHex;
    if (!loadPrivateHex(privHex)) {
        std::cerr << "No wallet found. Create one first.\n";
        return;
    }

    std::string address;
    if (!deriveAddressFromPrivateHex(privHex, address)) {
        std::cerr << "Invalid wallet file\n";
        return;
    }

    std::string balanceHex;
    std::string error;
    if (!fetchBalanceHex(network, address, balanceHex, error)) {
        std::cerr << error << "\n";
        return;
    }

    std::string formattedBalance = formatWeiAsNative(balanceHex);
    std::cout << "Network: " << network.canonicalName << "\n";
    std::cout << "Address: " << address << "\n";
    std::cout << "Balance: " << formattedBalance << " " << network.symbol << "\n";
}

void sendNative(const std::string& networkName, const std::string& toAddress, const std::string& amountNative) {
    NetworkConfig network;
    if (!resolveNetwork(networkName, network)) {
        std::cerr << "Unsupported network: " << networkName << "\n";
        listSupportedNetworks();
        return;
    }

    if (!isValidAddress(toAddress)) {
        std::cerr << "Invalid recipient address\n";
        return;
    }

    UniqueBN amountWei;
    if (!parseNativeAmountWei(amountNative, amountWei)) {
        std::cerr << "Invalid amount. Use decimal format with up to 18 decimals.\n";
        return;
    }

    std::string privHex;
    if (!loadPrivateHex(privHex)) {
        std::cerr << "No wallet found. Create one first.\n";
        return;
    }

    std::string fromAddress;
    if (!deriveAddressFromPrivateHex(privHex, fromAddress)) {
        std::cerr << "Invalid wallet file\n";
        return;
    }

    std::string nonceHex;
    std::string gasPriceHex;
    std::string chainIdHex;
    std::string error;

    if (!rpcCallResultHex(network, "eth_getTransactionCount", "[\"" + fromAddress + "\",\"pending\"]", nonceHex, error)) {
        std::cerr << "Failed to get nonce: " << error << "\n";
        return;
    }

    if (!rpcCallResultHex(network, "eth_gasPrice", "[]", gasPriceHex, error)) {
        std::cerr << "Failed to get gas price: " << error << "\n";
        return;
    }

    if (!rpcCallResultHex(network, "eth_chainId", "[]", chainIdHex, error)) {
        std::cerr << "Failed to get chain id: " << error << "\n";
        return;
    }

    UniqueBN nonce(BN_new());
    UniqueBN gasPrice(BN_new());
    UniqueBN gasLimit(BN_new());
    if (!nonce || !gasPrice || !gasLimit) {
        std::cerr << "Failed to allocate transaction values\n";
        return;
    }

    std::string nonceNorm = stripHexPrefix(nonceHex);
    std::string gasNorm = stripHexPrefix(gasPriceHex);
    std::string chainNorm = stripHexPrefix(chainIdHex);

    if (nonceNorm.empty()) nonceNorm = "0";
    if (gasNorm.empty()) gasNorm = "0";
    if (chainNorm.empty()) chainNorm = "0";

    if (!isValidHexString(nonceNorm) || !isValidHexString(gasNorm) || !isValidHexString(chainNorm)) {
        std::cerr << "RPC returned non-hex transaction values\n";
        return;
    }

    BIGNUM* nonceRaw = nullptr;
    BIGNUM* gasPriceRaw = nullptr;
    if (BN_hex2bn(&nonceRaw, nonceNorm.c_str()) == 0 || BN_hex2bn(&gasPriceRaw, gasNorm.c_str()) == 0) {
        BN_free(nonceRaw);
        BN_free(gasPriceRaw);
        std::cerr << "Failed to parse RPC transaction values\n";
        return;
    }
    nonce.reset(nonceRaw);
    gasPrice.reset(gasPriceRaw);

    if (BN_set_word(gasLimit.get(), 21000) != 1) {
        std::cerr << "Failed to parse RPC transaction values\n";
        return;
    }

    unsigned long long chainId = 0;
    try {
        chainId = std::stoull(chainNorm, nullptr, 16);
    } catch (...) {
        std::cerr << "Invalid chain id from RPC\n";
        return;
    }

    std::string rawTxHex;
    if (!signLegacyTransaction(privHex, toAddress, amountWei.get(), nonce.get(), gasPrice.get(), gasLimit.get(), chainId, rawTxHex, error)) {
        std::cerr << "Failed to sign transaction: " << error << "\n";
        return;
    }

    std::string txHash;
    if (!rpcCallResultHex(network, "eth_sendRawTransaction", "[\"" + rawTxHex + "\"]", txHash, error)) {
        std::cerr << "Failed to send transaction: " << error << "\n";
        return;
    }

    std::cout << "Network: " << network.canonicalName << "\n";
    std::cout << "From: " << fromAddress << "\n";
    std::cout << "To: " << toAddress << "\n";
    std::cout << "Amount: " << amountNative << " " << network.symbol << "\n";
    std::cout << "Tx Hash: " << txHash << "\n";
}
