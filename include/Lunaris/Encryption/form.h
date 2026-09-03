#pragma once

#include <cstdint>
#include <vector>

namespace Lunaris {
namespace Encryption {

    /**
     * @brief Basic layer on top of a simple random seed-generated combined sum.
     *
     * By itself it's not secure, but maybe it's another step on top of something else.
     * This is the 32-bit version.
     */
    class Form32 {
        uint32_t m_seed;
    public:
        /**
         * @brief Create with a seed directly.
         * @param seed Seed to setup for every encode/decode.
         */
        Form32(const uint32_t& seed);

        /**
         * @brief Set internal seed for encode/decode operations.
         * @param seed Seed to setup for every encode/decode.
         */
        void reseed(const uint32_t& seed);

        /**
         * @brief Encode data using sequential random sum based on seed.
         * @param data Data source.
         * @param len Data length, in bytes.
         * @return The final data encrypted with randomness.
         */
        std::vector<uint8_t> encode(const uint8_t* data, const size_t len) const;

        /**
         * @brief Decode data using sequential random sub based on seed.
         * @param data Data source.
         * @param len Data length, in bytes.
         * @return The final data decrypted with randomness.
         */
        std::vector<uint8_t> decode(const uint8_t* data, const size_t len) const;

        /**
         * @brief Encode data using sequential random sum based on seed and save into itself.
         * @param data Data source/target.
         * @param len Data length, in bytes.
         */
        void encode_in(uint8_t* data, const size_t len) const;

        /**
         * @brief Decode data using sequential random sub based on seed and save into itself.
         * @param data Data source/target.
         * @param len Data length, in bytes.
         */
        void decode_in(uint8_t* data, const size_t len) const;

        /**
         * @brief Encode data using sequential random sum based on seed and save into itself.
         * @param vec Data source/target.
         */
        void encode_in(std::vector<uint8_t>& vec) const;

        /**
         * @brief Decode data using sequential random sub based on seed and save into itself.
         * @param vec Data source/target.
         */
        void decode_in(std::vector<uint8_t>& vec) const;
    };

    /**
     * @brief Basic layer on top of a simple random seed-generated combined sum.
     *
     * By itself it's not secure, but maybe it's another step on top of something else.
     * This is the 64-bit version.
     */
    class Form64 {
        uint64_t m_seed;
    public:
        /**
         * @brief Create with a seed directly.
         * @param seed Seed to setup for every encode/decode.
         */
        Form64(const uint64_t& seed);

        /**
         * @brief Set internal seed for encode/decode operations.
         * @param seed Seed to setup for every encode/decode.
         */
        void reseed(const uint64_t& seed);

        /**
         * @brief Encode data using sequential random sum based on seed.
         * @param data Data source.
         * @param len Data length, in bytes.
         * @return The final data encrypted with randomness.
         */
        std::vector<uint8_t> encode(const uint8_t* data, const size_t len) const;

        /**
         * @brief Decode data using sequential random sub based on seed.
         * @param data Data source.
         * @param len Data length, in bytes.
         * @return The final data decrypted with randomness.
         */
        std::vector<uint8_t> decode(const uint8_t* data, const size_t len) const;

        /**
         * @brief Encode data using sequential random sum based on seed and save into itself.
         * @param data Data source/target.
         * @param len Data length, in bytes.
         */
        void encode_in(uint8_t* data, const size_t len) const;

        /**
         * @brief Decode data using sequential random sub based on seed and save into itself.
         * @param data Data source/target.
         * @param len Data length, in bytes.
         */
        void decode_in(uint8_t* data, const size_t len) const;

        /**
         * @brief Encode data using sequential random sum based on seed and save into itself.
         * @param vec Data source/target.
         */
        void encode_in(std::vector<uint8_t>& vec) const;

        /**
         * @brief Decode data using sequential random sub based on seed and save into itself.
         * @param vec Data source/target.
         */
        void decode_in(std::vector<uint8_t>& vec) const;
    };

} // Encryption
} // Lunaris