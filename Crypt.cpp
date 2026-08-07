#include "Crypt.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <climits>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

    struct FileCloser {
        void operator()(FILE* file) const noexcept
        {
            if (file != nullptr)
                std::fclose(file);
        }
    };

    using FilePtr = std::unique_ptr<FILE, FileCloser>;
    using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using PKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using CipherCtxPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    using KdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
    using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

    std::string collect_openssl_errors()
    {
        std::string result;
        unsigned long error_code = 0;

        while ((error_code = ERR_get_error()) != 0) {
            char buffer[256]{};
            ERR_error_string_n(error_code, buffer, sizeof(buffer));

            if (!result.empty())
                result += " | ";

            result += buffer;
        }

        return result.empty() ? "unknown OpenSSL error" : result;
    }

    [[noreturn]] void throw_openssl_error(const std::string& message)
    {
        throw std::runtime_error(message + ": " + collect_openssl_errors());
    }

    int checked_size_to_int(std::size_t value, const char* field_name)
    {
        if (value > static_cast<std::size_t>(INT_MAX)) {
            throw std::length_error(
                std::string(field_name) + " length exceeds INT_MAX");
        }

        return static_cast<int>(value);
    }

    void validate_optional_buffer(
        const std::uint8_t* data,
        std::size_t length,
        const char* field_name)
    {
        if (length != 0 && data == nullptr) {
            throw std::invalid_argument(
                std::string(field_name) +
                " is null while its length is non-zero");
        }
    }

    void validate_aes256_key(const std::vector<std::uint8_t>& key)
    {
        if (key.size() != AES256_KEY_LEN) {
            throw std::invalid_argument(
                "AES-256 key must be exactly 32 bytes");
        }
    }

} // namespace

void secure_wipe(std::vector<std::uint8_t>& buffer) noexcept
{
    if (!buffer.empty())
        OPENSSL_cleanse(buffer.data(), buffer.size());

    // 防止调用者继续读取旧长度的数据。
    buffer.clear();
}

EVP_PKEY* load_x25519_private_key(const std::string& pem_path)
{
    FILE* raw_file = std::fopen(pem_path.c_str(), "rb");
    if (raw_file == nullptr) {
        throw std::runtime_error(
            "Cannot open X25519 private-key file: " + pem_path);
    }

    FilePtr file(raw_file);
    PKeyPtr key(
        PEM_read_PrivateKey(file.get(), nullptr, nullptr, nullptr),
        &EVP_PKEY_free);

    if (!key)
        throw_openssl_error("PEM_read_PrivateKey failed");

    if (EVP_PKEY_is_a(key.get(), "X25519") != 1) {
        throw std::runtime_error(
            "File does not contain an X25519 private key");
    }

    return key.release();
}

EVP_PKEY* load_x25519_public_key(const std::string& pem_path)
{
    FILE* raw_file = std::fopen(pem_path.c_str(), "rb");
    if (raw_file == nullptr) {
        throw std::runtime_error(
            "Cannot open X25519 public-key file: " + pem_path);
    }

    FilePtr file(raw_file);
    PKeyPtr key(
        PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr),
        &EVP_PKEY_free);

    if (!key)
        throw_openssl_error("PEM_read_PUBKEY failed");

    if (EVP_PKEY_is_a(key.get(), "X25519") != 1) {
        throw std::runtime_error(
            "File does not contain an X25519 public key");
    }

    return key.release();
}

std::vector<std::uint8_t> ecdh_derive_shared_secret(
    EVP_PKEY* local_private_key,
    EVP_PKEY* peer_public_key)
{
    if (local_private_key == nullptr || peer_public_key == nullptr) {
        throw std::invalid_argument(
            "X25519 key pointer cannot be null");
    }

    if (EVP_PKEY_is_a(local_private_key, "X25519") != 1 ||
        EVP_PKEY_is_a(peer_public_key, "X25519") != 1) {
        throw std::invalid_argument(
            "Both keys must be X25519 keys");
    }

    PKeyCtxPtr context(
        EVP_PKEY_CTX_new_from_pkey(
            nullptr,
            local_private_key,
            nullptr),
        &EVP_PKEY_CTX_free);

    if (!context)
        throw_openssl_error("EVP_PKEY_CTX_new_from_pkey failed");

    if (EVP_PKEY_derive_init(context.get()) <= 0)
        throw_openssl_error("EVP_PKEY_derive_init failed");

    if (EVP_PKEY_derive_set_peer(
        context.get(),
        peer_public_key) <= 0) {
        throw_openssl_error(
            "EVP_PKEY_derive_set_peer failed");
    }

    std::size_t secret_length = 0;
    if (EVP_PKEY_derive(
        context.get(),
        nullptr,
        &secret_length) <= 0) {
        throw_openssl_error(
            "Cannot query X25519 shared-secret length");
    }

    if (secret_length == 0)
        throw std::runtime_error("X25519 produced an empty secret");

    std::vector<std::uint8_t> secret(secret_length);

    if (EVP_PKEY_derive(
        context.get(),
        secret.data(),
        &secret_length) <= 0) {
        secure_wipe(secret);
        throw_openssl_error(
            "X25519 shared-secret derivation failed");
    }

    secret.resize(secret_length);
    return secret;
}

std::vector<std::uint8_t> hkdf_derive_key(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& salt,
    const std::string& info,
    std::size_t output_length)
{
    if (shared_secret.empty()) {
        throw std::invalid_argument(
            "HKDF input key material cannot be empty");
    }

    if (output_length == 0)
        throw std::invalid_argument("HKDF output length cannot be zero");

    if (output_length > HKDF_SHA256_MAX_OUTPUT_LEN) {
        throw std::length_error(
            "HKDF-SHA256 output exceeds 8160 bytes");
    }

    KdfPtr kdf(
        EVP_KDF_fetch(nullptr, "HKDF", nullptr),
        &EVP_KDF_free);

    if (!kdf)
        throw_openssl_error("EVP_KDF_fetch(HKDF) failed");

    KdfCtxPtr context(
        EVP_KDF_CTX_new(kdf.get()),
        &EVP_KDF_CTX_free);

    if (!context)
        throw_openssl_error("EVP_KDF_CTX_new failed");

    char digest_name[] = "SHA256";
    char mode_name[] = "EXTRACT_AND_EXPAND";

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            digest_name,
            0),
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE,
            mode_name,
            0),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<std::uint8_t*>(shared_secret.data()),
            shared_secret.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.empty()
                ? nullptr
                : const_cast<std::uint8_t*>(salt.data()),
            salt.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info.empty()
                ? nullptr
                : const_cast<char*>(info.data()),
            info.size()),
        OSSL_PARAM_construct_end()
    };

    std::vector<std::uint8_t> output(output_length);

    if (EVP_KDF_derive(
        context.get(),
        output.data(),
        output.size(),
        parameters) <= 0) {
        secure_wipe(output);
        throw_openssl_error("HKDF-SHA256 derivation failed");
    }

    return output;
}

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length)
{
    return aes256_gcm_encrypt(
        key,
        plaintext,
        plaintext_length,
        nullptr,
        0);
}

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length,
    const std::uint8_t* aad,
    std::size_t aad_length)
{
    validate_aes256_key(key);
    validate_optional_buffer(
        plaintext,
        plaintext_length,
        "plaintext");
    validate_optional_buffer(aad, aad_length, "AAD");

    const int plaintext_length_int =
        checked_size_to_int(plaintext_length, "plaintext");
    const int aad_length_int =
        checked_size_to_int(aad_length, "AAD");

    std::vector<std::uint8_t> nonce(AES_GCM_NONCE_LEN);

    if (RAND_bytes(
        nonce.data(),
        checked_size_to_int(nonce.size(), "nonce")) != 1) {
        throw_openssl_error("RAND_bytes failed");
    }

    CipherCtxPtr context(
        EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);

    if (!context)
        throw_openssl_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex2(
        context.get(),
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr) != 1) {
        throw_openssl_error("EVP_EncryptInit_ex2 failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
        context.get(),
        EVP_CTRL_AEAD_SET_IVLEN,
        checked_size_to_int(nonce.size(), "nonce"),
        nullptr) != 1) {
        throw_openssl_error(
            "Cannot set AES-GCM nonce length");
    }

    if (EVP_EncryptInit_ex2(
        context.get(),
        nullptr,
        key.data(),
        nonce.data(),
        nullptr) != 1) {
        throw_openssl_error(
            "Cannot initialize AES-GCM key and nonce");
    }

    int produced = 0;

    if (aad_length != 0 &&
        EVP_EncryptUpdate(
            context.get(),
            nullptr,
            &produced,
            aad,
            aad_length_int) != 1) {
        throw_openssl_error("AES-GCM AAD update failed");
    }

    std::vector<std::uint8_t> ciphertext(
        plaintext_length + EVP_MAX_BLOCK_LENGTH);

    int total = 0;

    if (plaintext_length != 0) {
        if (EVP_EncryptUpdate(
            context.get(),
            ciphertext.data(),
            &produced,
            plaintext,
            plaintext_length_int) != 1) {
            throw_openssl_error(
                "AES-GCM plaintext encryption failed");
        }

        total = produced;
    }

    if (EVP_EncryptFinal_ex(
        context.get(),
        ciphertext.data() + total,
        &produced) != 1) {
        throw_openssl_error(
            "AES-GCM encryption finalization failed");
    }

    total += produced;
    ciphertext.resize(static_cast<std::size_t>(total));

    std::vector<std::uint8_t> tag(AES_GCM_TAG_LEN);

    if (EVP_CIPHER_CTX_ctrl(
        context.get(),
        EVP_CTRL_AEAD_GET_TAG,
        checked_size_to_int(tag.size(), "tag"),
        tag.data()) != 1) {
        throw_openssl_error(
            "Cannot obtain AES-GCM authentication tag");
    }

    std::vector<std::uint8_t> result;
    result.reserve(
        nonce.size() +
        ciphertext.size() +
        tag.size());

    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(
        result.end(),
        ciphertext.begin(),
        ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input)
{
    return aes256_gcm_decrypt(key, input, nullptr, 0);
}

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input,
    const std::uint8_t* aad,
    std::size_t aad_length)
{
    validate_aes256_key(key);
    validate_optional_buffer(aad, aad_length, "AAD");

    constexpr std::size_t overhead =
        AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;

    if (input.size() < overhead)
        return std::nullopt;

    const std::size_t ciphertext_length =
        input.size() - overhead;

    const int ciphertext_length_int =
        checked_size_to_int(ciphertext_length, "ciphertext");
    const int aad_length_int =
        checked_size_to_int(aad_length, "AAD");

    const std::uint8_t* nonce = input.data();
    const std::uint8_t* ciphertext =
        input.data() + AES_GCM_NONCE_LEN;
    const std::uint8_t* tag =
        ciphertext + ciphertext_length;

    CipherCtxPtr context(
        EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);

    if (!context)
        throw_openssl_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex2(
        context.get(),
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr) != 1) {
        throw_openssl_error("EVP_DecryptInit_ex2 failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
        context.get(),
        EVP_CTRL_AEAD_SET_IVLEN,
        static_cast<int>(AES_GCM_NONCE_LEN),
        nullptr) != 1) {
        throw_openssl_error(
            "Cannot set AES-GCM nonce length");
    }

    if (EVP_DecryptInit_ex2(
        context.get(),
        nullptr,
        key.data(),
        nonce,
        nullptr) != 1) {
        throw_openssl_error(
            "Cannot initialize AES-GCM key and nonce");
    }

    int produced = 0;

    if (aad_length != 0 &&
        EVP_DecryptUpdate(
            context.get(),
            nullptr,
            &produced,
            aad,
            aad_length_int) != 1) {
        throw_openssl_error("AES-GCM AAD update failed");
    }

    std::vector<std::uint8_t> plaintext(
        ciphertext_length + EVP_MAX_BLOCK_LENGTH);

    int total = 0;

    if (ciphertext_length != 0) {
        if (EVP_DecryptUpdate(
            context.get(),
            plaintext.data(),
            &produced,
            ciphertext,
            ciphertext_length_int) != 1) {
            secure_wipe(plaintext);
            throw_openssl_error(
                "AES-GCM ciphertext processing failed");
        }

        total = produced;
    }

    if (EVP_CIPHER_CTX_ctrl(
        context.get(),
        EVP_CTRL_AEAD_SET_TAG,
        static_cast<int>(AES_GCM_TAG_LEN),
        const_cast<std::uint8_t*>(tag)) != 1) {
        secure_wipe(plaintext);
        throw_openssl_error(
            "Cannot set AES-GCM authentication tag");
    }

    const int final_result =
        EVP_DecryptFinal_ex(
            context.get(),
            plaintext.data() + total,
            &produced);

    if (final_result <= 0) {
        secure_wipe(plaintext);
        return std::nullopt;
    }

    total += produced;
    plaintext.resize(static_cast<std::size_t>(total));
    return plaintext;
}

std::vector<std::uint8_t> build_inner_packet(
    std::uint8_t packet_type,
    const std::vector<std::uint8_t>& payload)
{
    std::vector<std::uint8_t> packet;
    packet.reserve(1 + payload.size());
    packet.push_back(packet_type);
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

bool parse_inner_packet(
    const std::vector<std::uint8_t>& inner_plaintext,
    std::uint8_t& output_type,
    std::vector<std::uint8_t>& output_payload)
{
    if (inner_plaintext.empty())
        return false;

    output_type = inner_plaintext.front();
    output_payload.assign(
        inner_plaintext.begin() + 1,
        inner_plaintext.end());

    return true;
}
