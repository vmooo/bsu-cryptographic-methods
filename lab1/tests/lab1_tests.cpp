#include <gtest/gtest.h>
#include <algorithm>

#include "../include/lab1.h"

// ============================================================================
// Common fixtures
// ============================================================================

namespace {

    using U32 = std::u32string;

    const U32 EN_ALPHABET = U"abcdefghijklmnopqrstuvwxyz";
    const U32 RU_ALPHABET = U"абвгдеёжзийклмнопрстуфхцчшщъыьэюя";

} // namespace

// ============================================================================
// shiftCipher
// ============================================================================

TEST(ShiftCipher, EncryptsBasicText) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"hello", EN_ALPHABET, 3, false), U"khoor");
}

TEST(ShiftCipher, DecryptsBasicText) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"khoor", EN_ALPHABET, 3, true), U"hello");
}

TEST(ShiftCipher, RoundTripReturnsOriginal) {
    const U32 original = U"thequickbrownfox";
    const auto encrypted = ClassicCrypto::shiftCipher(original, EN_ALPHABET, 7, false);
    const auto decrypted = ClassicCrypto::shiftCipher(encrypted, EN_ALPHABET, 7, true);
    EXPECT_EQ(decrypted, original);
}

TEST(ShiftCipher, HandlesKeyLargerThanAlphabet) {
    // key = 29 == 3 (mod 26)
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"abc", EN_ALPHABET, 29, false),
              ClassicCrypto::shiftCipher(U"abc", EN_ALPHABET, 3, false));
}

TEST(ShiftCipher, HandlesNegativeKey) {
    // shift by -3 == shift by 23
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"abc", EN_ALPHABET, -3, false),
              ClassicCrypto::shiftCipher(U"abc", EN_ALPHABET, 23, false));
}

TEST(ShiftCipher, LeavesUnknownCharactersUntouched) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"hi, there!", EN_ALPHABET, 1, false),
              U"ij, uifsf!");
}

TEST(ShiftCipher, HandlesEmptyInput) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"", EN_ALPHABET, 5, false), U"");
}

TEST(ShiftCipher, HandlesEmptyAlphabet) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"hello", U"", 5, false), U"hello");
}

TEST(ShiftCipher, WorksWithRussianAlphabet) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"абв", RU_ALPHABET, 1, false), U"бвг");
}

TEST(ShiftCipher, ZeroKeyReturnsOriginal) {
    EXPECT_EQ(ClassicCrypto::shiftCipher(U"hello", EN_ALPHABET, 0, false), U"hello");
}