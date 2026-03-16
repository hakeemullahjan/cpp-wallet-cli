#include "wallet.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

static std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

static bool fromHex(const std::string& hex, unsigned char* out, size_t out_len) {
    if (hex.length() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte;
        std::istringstream(hex.substr(i * 2, 2)) >> std::hex >> byte;
        out[i] = static_cast<unsigned char>(byte);
    }
    return true;
}

void createWallet() {
    EC_KEY* ec_key = nullptr;
    const BIGNUM* priv_bn = nullptr;
    const EC_POINT* pub_point = nullptr;
    unsigned char* pub_key = nullptr;
    size_t pub_len = 0;

    // Create EC_KEY with secp256k1 curve
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        std::cerr << "Failed to create EC_KEY\n";
        return;
    }

    // Generate key pair
    if (EC_KEY_generate_key(ec_key) != 1) {
        std::cerr << "Failed to generate key pair\n";
        EC_KEY_free(ec_key);
        return;
    }

    // Get private key as BIGNUM
    priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) {
        std::cerr << "Failed to get private key\n";
        EC_KEY_free(ec_key);
        return;
    }

    // Convert private key to 32-byte array
    unsigned char priv_key[32];
    memset(priv_key, 0, 32);
    if (BN_bn2binpad(priv_bn, priv_key, 32) != 32) {
        std::cerr << "Failed to convert private key\n";
        EC_KEY_free(ec_key);
        return;
    }

    std::string priv_hex = toHex(priv_key, 32);

    // Save private key to file
    std::ofstream outfile("data/wallet.dat");
    if (!outfile) {
        std::cerr << "Failed to open wallet.dat for writing\n";
        EC_KEY_free(ec_key);
        return;
    }
    outfile << priv_hex;
    outfile.close();

    // Get public key point
    pub_point = EC_KEY_get0_public_key(ec_key);
    if (!pub_point) {
        std::cerr << "Failed to get public key\n";
        EC_KEY_free(ec_key);
        return;
    }

    // Convert public key to uncompressed format
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (pub_len == 0) {
        std::cerr << "Failed to get public key length\n";
        EC_KEY_free(ec_key);
        return;
    }

    pub_key = new unsigned char[pub_len];
    if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_key, pub_len, nullptr) != pub_len) {
        std::cerr << "Failed to convert public key\n";
        delete[] pub_key;
        EC_KEY_free(ec_key);
        return;
    }

    // Hash public key (skip 0x04 prefix, use 64 bytes)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(pub_key + 1, 64, hash);

    // Cleanup
    delete[] pub_key;
    EC_KEY_free(ec_key);

    // Ethereum address: last 20 bytes of hash
    std::string address = "0x" + toHex(hash + 12, 20);

    std::cout << "Wallet created successfully!\n";
    std::cout << "Address: " << address << "\n";
    std::cout << "Private key saved to data/wallet.dat\n";
}

void showAddress() {
    std::ifstream infile("data/wallet.dat");
    if (!infile) {
        std::cerr << "No wallet found. Create one first.\n";
        return;
    }

    std::string priv_hex;
    infile >> priv_hex;
    infile.close();

    if (priv_hex.length() != 64) {
        std::cerr << "Invalid wallet file\n";
        return;
    }

    unsigned char priv_key[32];
    if (!fromHex(priv_hex, priv_key, 32)) {
        std::cerr << "Failed to parse private key\n";
        return;
    }

    EC_KEY* ec_key = nullptr;
    BIGNUM* priv_bn = nullptr;
    EC_POINT* pub_point = nullptr;
    unsigned char* pub_key = nullptr;
    size_t pub_len = 0;

    // Create EC_KEY with secp256k1 curve
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        std::cerr << "Failed to create EC_KEY\n";
        return;
    }

    // Convert private key bytes to BIGNUM
    priv_bn = BN_bin2bn(priv_key, 32, nullptr);
    if (!priv_bn) {
        std::cerr << "Failed to create BIGNUM\n";
        EC_KEY_free(ec_key);
        return;
    }

    // Set private key
    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        std::cerr << "Failed to set private key\n";
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    // Derive public key from private key
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        std::cerr << "Failed to create EC_POINT\n";
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    if (EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr) != 1) {
        std::cerr << "Failed to derive public key\n";
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        std::cerr << "Failed to set public key\n";
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    // Convert public key to uncompressed format
    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (pub_len == 0) {
        std::cerr << "Failed to get public key length\n";
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    pub_key = new unsigned char[pub_len];
    if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_key, pub_len, nullptr) != pub_len) {
        std::cerr << "Failed to convert public key\n";
        delete[] pub_key;
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return;
    }

    // Hash public key (skip 0x04 prefix, use 64 bytes)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(pub_key + 1, 64, hash);

    // Cleanup
    delete[] pub_key;
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(ec_key);

    std::string address = "0x" + toHex(hash + 12, 20);
    std::cout << "Address: " << address << "\n";
}
