#pragma once

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

constexpr std::size_t AES256_KEY_LEN = 32;
constexpr std::size_t AES_GCM_NONCE_LEN = 12;
constexpr std::size_t AES_GCM_TAG_LEN = 16;
constexpr std::size_t HKDF_SHA256_MAX_OUTPUT_LEN = 255 * 32;

// 擦除 vector 当前已分配区域中的敏感数据；不会释放容量。
void secure_wipe(std::vector<std::uint8_t>& buffer) noexcept;

// 返回的 EVP_PKEY* 由调用方使用 EVP_PKEY_free() 释放。
EVP_PKEY* load_x25519_private_key(const std::string& pem_path);
EVP_PKEY* load_x25519_public_key(const std::string& pem_path);

std::vector<std::uint8_t> ecdh_derive_shared_secret(
    EVP_PKEY* local_private_key,
    EVP_PKEY* peer_public_key);

std::vector<std::uint8_t> hkdf_derive_key(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& salt,
    const std::string& info,
    std::size_t output_length);

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length);

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length,
    const std::uint8_t* aad,
    std::size_t aad_length);

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input);

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input,
    const std::uint8_t* aad,
    std::size_t aad_length);

std::vector<std::uint8_t> build_inner_packet(
    std::uint8_t packet_type,
    const std::vector<std::uint8_t>& payload);

bool parse_inner_packet(
    const std::vector<std::uint8_t>& inner_plaintext,
    std::uint8_t& output_type,
    std::vector<std::uint8_t>& output_payload);
