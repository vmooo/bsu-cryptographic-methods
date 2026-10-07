#include "../include/lab1.h"

/**
 * @brief UTF-32 string type used as the working representation for text.
 *
 * Each element of a @c std::u32string corresponds to exactly one Unicode
 * code point, so character indexing, iteration and length are unambiguous
 * for any alphabet (Latin, Cyrillic, Greek, etc.). This avoids the
 * multi-byte pitfalls of UTF-8 @c std::string.
 */
using U32 = std::u32string;

/**
 * @brief Returns the index of @p symbol in @p alphabet.
 *
 * Performs a linear search of @p symbol in @p alphabet. Used as the
 * "letter -> number" mapping for cipher algorithms that operate over a
 * finite alphabet.
 *
 * @param[in] alphabet Sequence of valid characters (code points) in their
 *                     canonical order. Must not contain duplicates for the
 *                     mapping to be well-defined.
 * @param[in] symbol   Code point to look up.
 *
 * @return Zero-based index of @p symbol in @p alphabet, or @c -1 if the
 *         symbol is not present.
 *
 * @note Runs in O(alphabet.size()). Alphabets used in classic ciphers are
 *       small, so a linear scan is preferable to building a hash map.
 * @see getSymbolByNumber
 */
int32_t getNumberInAlphabet(const U32& alphabet, char32_t symbol) {
    auto pos = alphabet.find(symbol);
    return pos == std::string::npos ? -1 : static_cast<int32_t>(pos);
}

/**
 * @brief Returns the character located at position @p number in @p alphabet.
 *
 * Inverse of getNumberInAlphabet(): converts a numeric index back into the
 * corresponding code point.
 *
 * @param[in] alphabet Sequence of valid characters (code points).
 * @param[in] number   Zero-based index; must satisfy
 *                     @c 0 <= number < alphabet.size().
 *
 * @return Code point @c alphabet[number].
 *
 * @warning The caller is responsible for passing an index within range.
 *          Passing an out-of-range index results in undefined behavior.
 * @see getNumberInAlphabet
 */
char32_t getSymbolByNumber(const U32& alphabet, const int32_t number) {
    return alphabet[number];
}

/**
 * @brief Computes the mathematical modulo of @p x by @p n.
 *
 * Unlike the built-in @c % operator, whose result takes the sign of the
 * dividend, this function always returns a value in the range
 * @c [0, n). This is essential for cipher arithmetic, where a negative
 * shift (e.g. during decryption or with a negative key) must wrap around
 * to a valid alphabet index instead of producing a negative one.
 *
 * @param[in] x Dividend (may be negative).
 * @param[in] n Divisor; must be strictly positive.
 *
 * @return Value @c r such that @c 0 <= r < n and @c r == x (mod n).
 *
 * @note Implemented as @c ((x % n) + n) % n.
 */
static inline int32_t mod(int32_t x, int32_t n) {
    return ((x % n) + n) % n;
}

/**
 * @brief Caesar cipher (shift cipher) over an arbitrary alphabet.
 *
 * Encrypts or decrypts @p input by shifting each character along
 * @p alphabet by @p key positions. Characters that are not part of
 * @p alphabet (spaces, punctuation, digits, symbols from another script)
 * are copied unchanged and do not affect the shift.
 *
 * The shift is reduced modulo @c alphabet.size(), so any integer key —
 * including negative and larger-than-alphabet values — is valid.
 * Decryption is performed by applying the inverse shift.
 *
 * @param[in] input    Text to transform, represented as a UTF-32 string.
 *                     Passed by value; the caller's string is not modified.
 * @param[in] alphabet Ordered set of characters forming the cipher
 *                     alphabet (e.g. @c U"abc...z" or a Cyrillic
 *                     alphabet). Must not be empty and must not contain
 *                     duplicates.
 * @param[in] key      Shift amount in alphabet positions. Any @c int32_t
 *                     value is accepted; it is normalized into
 *                     @c [0, alphabet.size()) internally.
 * @param[in] mode     Operation mode:
 *                     @c false — encryption,
 *                     @c true  — decryption.
 *
 * @return Transformed string with the same length as @p input. Characters
 *         outside the alphabet are preserved verbatim.
 *
 * @note If @p alphabet is empty, @p input is returned unchanged.
 * @note This is a monoalphabetic substitution; it is trivially breakable
 *       by frequency analysis and is intended for educational purposes.
 *
 * @see getNumberInAlphabet, getSymbolByNumber, mod
 */
U32 ClassicCrypto::shiftCipher(U32 input,
                               const U32& alphabet,
                               const int32_t key,
                               const bool mode) {

    const auto alphabetSize = static_cast<int32_t>(alphabet.size());

    if (mode) {
        // Decryption: shift each character backwards by `key`.
        for (char32_t& c : input) {
            const int32_t symbolNumber = getNumberInAlphabet(alphabet, c);
            if (symbolNumber == -1) continue;

            c = getSymbolByNumber(alphabet, mod((symbolNumber - key), alphabetSize));
        }
    }
    else {
        // Encryption: shift each character forwards by `key`.
        for (char32_t& c : input) {
            if (int32_t symbolNumber = getNumberInAlphabet(alphabet, c); symbolNumber == -1) continue;

            c = getSymbolByNumber(alphabet, mod((getNumberInAlphabet(alphabet, c) + key), alphabetSize));
        }
    }

    return input;
}