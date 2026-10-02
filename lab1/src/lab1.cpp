#include "../include/lab1.h"

std::string ClassicCrypto::shiftCipher(std::string input, int16_t key, bool mode) {

    if (mode) {
        for (char& c : input) {
            c = (static_cast<int16_t>(c) - key) % alphabetSize;
        }
    }
    else {
        for (char& c : input) {
            c = (static_cast<int16_t>(c) + key) % alphabetSize;
        }
    }

    return input;
}