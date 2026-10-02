#include <gtest/gtest.h>

#include "../include/lab1.h"
#include <string>

TEST(ClassicCryptoTests, shiftCipherTest1) {
    std::string input = "abc";
    ASSERT_TRUE(ClassicCrypto::shiftCipher(input, 1, false) == "bcd");
}

TEST(ClassicCryptoTests, shiftCipherTest2) {
    std::string input = "bcd";
    ASSERT_TRUE(ClassicCrypto::shiftCipher(input, 1, true) == "abc");
}