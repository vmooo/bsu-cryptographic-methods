#ifndef BSU_CRYPTOGRAPHIC_METHODS_LAB1_H
#define BSU_CRYPTOGRAPHIC_METHODS_LAB1_H

#include <string>
#include <cstdint>

class ClassicCrypto {

    static constexpr int16_t alphabetSize = 128;

public:

    static std::string shiftCipher(std::string input, int16_t key, bool mode = false);
    static std::string affineCipher(std::string input);
    static std::string simpleSubstitutionCipher(std::string input);
    static std::string hillCipher(std::string input);
    static std::string transpositionCipher(std::string input);
    static std::string vigenereCipher(std::string input);

};

#endif //BSU_CRYPTOGRAPHIC_METHODS_LAB1_H