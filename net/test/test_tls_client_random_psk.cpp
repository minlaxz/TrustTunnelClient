#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "common/defs.h"
#include "net/utils.h"

#include <openssl/aes.h>
#include <openssl/hkdf.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#ifdef SSL_set_custom_client_random

namespace {

// Recompute the second 16 bytes of the client_random from its salt (its first
// 16 bytes), the PSK key and the SNI using the same HKDF-SHA256 + AES-128
// algorithm as derive_client_random_from_psk, and return whether they match.
bool matches_derived_ciphertext(const ag::U8View &psk_key, const uint8_t *client_random, const char *sni) {
    constexpr size_t half = SSL3_RANDOM_SIZE / 2;
    static constexpr std::string_view INFO = "tls13 encryption context";

    uint8_t derived_key[half];
    if (1
            != HKDF(derived_key, half, EVP_sha256(), psk_key.data(), psk_key.size(), client_random, half,
                    reinterpret_cast<const uint8_t *>(INFO.data()), INFO.size())) {
        return false;
    }

    uint8_t sni_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t *>(sni), std::strlen(sni), sni_hash);

    AES_KEY aes_key;
    if (0 != AES_set_encrypt_key(derived_key, half * CHAR_BIT, &aes_key)) {
        return false;
    }

    uint8_t ciphertext[half];
    AES_encrypt(sni_hash, ciphertext, &aes_key);

    return 0 == std::memcmp(ciphertext, client_random + half, half);
}

constexpr std::array<uint8_t, 16> TEST_PSK_BYTES = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

constexpr std::array<uint8_t, 16> OTHER_PSK_BYTES = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

} // namespace

TEST(TlsClientRandomPsk, DerivesFullClientRandom) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{TEST_PSK_BYTES.data(), TEST_PSK_BYTES.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());
    ASSERT_EQ(SSL3_RANDOM_SIZE, derived->size());

    // The second half must be AES(HKDF(psk, salt), SHA256(SNI)[..16]) of the salt.
    EXPECT_TRUE(matches_derived_ciphertext(psk, derived->data(), SNI));
}

TEST(TlsClientRandomPsk, RandomSaltDiffersBetweenCalls) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{TEST_PSK_BYTES.data(), TEST_PSK_BYTES.size()};

    auto first = ag::derive_client_random_from_psk(psk, SNI);
    auto second = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    // The random salt (first half) should differ between calls.
    EXPECT_NE(0, std::memcmp(first->data(), second->data(), SSL3_RANDOM_SIZE / 2));
}

TEST(TlsClientRandomPsk, WrongSniDoesNotValidate) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{TEST_PSK_BYTES.data(), TEST_PSK_BYTES.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());

    EXPECT_FALSE(matches_derived_ciphertext(psk, derived->data(), "other.example.com"));
}

TEST(TlsClientRandomPsk, WrongPskDoesNotValidate) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{TEST_PSK_BYTES.data(), TEST_PSK_BYTES.size()};
    ag::U8View other_psk{OTHER_PSK_BYTES.data(), OTHER_PSK_BYTES.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());

    EXPECT_FALSE(matches_derived_ciphertext(other_psk, derived->data(), SNI));
}

TEST(TlsClientRandomPsk, EmptySniFails) {
    ag::U8View psk{TEST_PSK_BYTES.data(), TEST_PSK_BYTES.size()};

    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, nullptr).has_value());
    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, "").has_value());
}

#endif
