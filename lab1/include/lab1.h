#ifndef BSU_CRYPTOGRAPHIC_METHODS_LAB1_H
#define BSU_CRYPTOGRAPHIC_METHODS_LAB1_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief Class implementing classic cryptographic algorithms.
 *
 * All methods take a plaintext (or ciphertext) string and return the
 * transformed result without modifying the original string. The algorithms
 * operate on characters from a given alphabet; characters not belonging to
 * the alphabet are left unchanged.
 */
class ClassicCrypto {

    /**
    * @brief UTF-32 string type used as the working representation for text.
    *
    * Each element of a @c std::u32string corresponds to exactly one Unicode
    * code point, so character indexing, iteration and length are unambiguous
    * for any alphabet (Latin, Cyrillic, Greek, etc.). This avoids the
    * multi-byte pitfalls of UTF-8 @c std::string.
    */
    using U32 = std::u32string;

public:

    /**
     * @brief Caesar cipher (shift cipher).
     *
     * Each character of the input string is replaced by the character
     * located @p key positions further along @p alphabet. For decryption,
     * the shift is performed in the opposite direction.
     *
     * @param[in] input    Input string (plaintext or ciphertext).
     * @param[in] alphabet Alphabet within which the shift is performed.
     *                     Case and character order are defined by the caller.
     * @param[in] key      Shift amount in alphabet characters. May be any
     *                     integer; it is reduced modulo the alphabet length
     *                     before use.
     * @param[in] mode     Operation mode:
     *                     @c false — encryption (default),
     *                     @c true  — decryption.
     *
     * @return Transformed string of the same length as @p input.
     *
     * @note If @p alphabet is empty, @p input is returned unchanged.
     * @see affineCipher, vigenereCipher
     */
    static U32 shiftCipher(U32 input,
                                   const U32& alphabet,
                                   int32_t key,
                                   bool mode = false);

    /**
     * @brief Affine cipher (linear transformation over an alphabet).
     *
     * Each character with index @c x in the alphabet is replaced by the
     * character with index @c (a*x + b) mod n, where @c n is the alphabet
     * length. For decryption, the modular inverse @c a^{-1} mod n is used.
     *
     * @param[in] input    Input string.
     * @param[in] alphabet Alphabet used for indexing characters.
     * @param[in] key      Pair of coefficients @c (a, b):
     *                     @c a — multiplier (must be coprime with the
     *                            alphabet length; otherwise the cipher is
     *                            not invertible),
     *                     @c b — additive term (shift).
     * @param[in] mode     Operation mode:
     *                     @c false — encryption (default),
     *                     @c true  — decryption.
     *
     * @return Transformed string.
     *
     * @warning If @c gcd(a, n) != 1, decryption is impossible — the
     *          behavior of the method in this case is undefined.
     * @see shiftCipher
     */
    static U32 affineCipher(U32 input,
                                    const U32& alphabet,
                                    std::pair<int16_t, int16_t> key,
                                    bool mode = false);

    /**
     * @brief Simple substitution cipher (monoalphabetic).
     *
     * Each alphabet character is replaced by a fixed character according
     * to a substitution table. The table @p substitution must be a
     * permutation of @p alphabet with the same length, so that the
     * character @c alphabet[i] is replaced by @c substitution[i].
     *
     * @param[in] input        Input string.
     * @param[in] alphabet     Source alphabet.
     * @param[in] substitution Substitution alphabet — a permutation of
     *                         @p alphabet of the same length.
     * @param[in] mode         Operation mode:
     *                         @c false — encryption (default),
     *                         @c true  — decryption (uses the inverse
     *                         permutation).
     *
     * @return Transformed string.
     *
     * @warning If @p substitution is not a permutation of @p alphabet or
     *          the lengths differ, the behavior is undefined.
     */
    static U32 simpleSubstitutionCipher(U32 input,
                                                const U32& alphabet,
                                                const U32& substitution,
                                                bool mode = false);

    /**
     * @brief Hill cipher (matrix encryption over an alphabet).
     *
     * A block of @c k characters is multiplied by a square @c k x k matrix
     * modulo the alphabet length. For decryption, the inverse matrix modulo
     * the alphabet length is used.
     *
     * @param[in] input    Input string.
     * @param[in] alphabet Alphabet used for indexing characters.
     * @param[in] key      Square key matrix of size @c k x @c k, where
     *                     @c k is the block size. Values are reduced modulo
     *                     the alphabet length.
     * @param[in] mode     Operation mode:
     *                     @c false — encryption (default),
     *                     @c true  — decryption.
     *
     * @return Transformed string. The length is padded if necessary to a
     *         multiple of the block size @c k.
     *
     * @warning The matrix must be invertible modulo the alphabet length
     *          (i.e. @c det(key) must be coprime with the alphabet length);
     *          otherwise decryption is impossible.
     */
    static U32 hillCipher(U32 input,
                                  const U32& alphabet,
                                  const std::vector<std::vector<int>>& key,
                                  bool mode = false);

    /**
     * @brief Transposition cipher (columnar permutation).
     *
     * Characters of the string are rearranged according to the permutation
     * @p key without changing the set of characters themselves. The input
     * is conceptually split into blocks of size @c key.size(); within each
     * block the character at position @c i is moved to position
     * @c key[i]. For decryption, the inverse permutation is applied.
     *
     * @param[in] input Input string.
     * @param[in] key   Permutation of indices @c [0, key.size()); must
     *                  contain each value from that range exactly once.
     * @param[in] mode  Operation mode:
     *                  @c false — encryption (default),
     *                  @c true  — decryption.
     *
     * @return String with rearranged characters. Its length equals the
     *         length of @p input; the last block may be shorter than
     *         @c key.size() and is left partially permuted.
     *
     * @warning If @p key is not a valid permutation, the behavior is
     *          undefined.
     */
    static U32 transpositionCipher(U32 input,
                                           const std::vector<size_t>& key,
                                           bool mode = false);

    /**
     * @brief Vigenère cipher (polyalphabetic shift using a keyword).
     *
     * Each character is shifted by an amount determined by the next
     * character of @p keyword; the shift is cyclically repeated over the
     * keyword length. It is a generalization of the Caesar cipher.
     *
     * @param[in] input    Input string.
     * @param[in] alphabet Alphabet used for indexing characters.
     * @param[in] keyword  Key word; its characters must belong to
     *                     @p alphabet. An empty keyword makes the method a
     *                     no-op.
     * @param[in] mode     Operation mode:
     *                     @c false — encryption (default),
     *                     @c true  — decryption.
     *
     * @return Transformed string of the same length as @p input.
     *
     * @see shiftCipher
     */
    static U32 vigenereCipher(U32 input,
                                      const U32& alphabet,
                                      const U32& keyword,
                                      bool mode = false);

};

#endif //BSU_CRYPTOGRAPHIC_METHODS_LAB1_H