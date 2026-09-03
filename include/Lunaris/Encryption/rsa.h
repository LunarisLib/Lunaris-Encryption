#pragma once

#include <type_traits>
#include <functional>
#include <random>

namespace Lunaris {
namespace Encryption {

    /**
     * @brief Easier concept to facilitate template of unsigned type
     */
    template <typename T>
    concept UnsignedLong = requires {
        requires (sizeof(T) >= 4) && std::unsigned_integral<T>;
    };

    /**
     * @ brief This is used like the public and mod keys. It is a shortcut.
     */
	template<typename UnsignedLong>
	struct RSA_keys {
		UnsignedLong key, mod; // do not change order
	};

    // must be sqrt(T) for half the bytes so ops won't get bigger than T
	template<typename UnsignedLong>
	inline constexpr UnsignedLong rsa_mask = std::numeric_limits<UnsignedLong>::max() >> (sizeof(UnsignedLong) * 4); // if 8 bits, sizeof(T) == 1, move 4 bits -> sqrt(max(T))

    /**
     * @brief An RSA encrypt/decrypt object (depends on source). Uses internal keys to work.
     *
     * It is expected to create one of these from an RSACustom.
     */
    template<typename UnsignedLong>
    class RSADeviceCustom {
        const UnsignedLong n, key;
        const bool m_16to32; // encrypt? false == decrypt

        UnsignedLong enc(const UnsignedLong&) const; // UnsignedLong max expected = mask
    public:
        /**
         * @brief Copy constructor.
         * @param other An RSADeviceCustom to copy from.
         */
        RSADeviceCustom(const RSADeviceCustom<UnsignedLong>& other);

        /**
         * @brief Main constructor used by RSA.
         * @param key Key.
         * @param mod Mod.
         * @param enc Work as encrypt? (Encoder does 16 bit to 32 bit, decryptor is the opposite).
         */
        RSADeviceCustom(const UnsignedLong& key, const UnsignedLong& mod, const bool enc = false); // UnsignedLong max expected = mask

        /**
         * @brief Assuming that you're doing decode and got directly this thing containing public key and mod.
         * @param as_dec The public keys.
         */
        RSADeviceCustom(const RSA_keys<UnsignedLong>& as_dec);

        /**
         * @brief Get a data source and transform.
         *
         * The transform is encrypt or decrypt depending on what was set in the constructor.
         *
         * @param data Data source.
         * @param len Data length, in bytes.
         * @return Transformed data.
         */
        std::vector<uint8_t> transform(const uint8_t* data, const size_t len) const;

        /**
         * @brief Get a data source and transform.
         *
         * The transform is encrypt or decrypt depending on what was set in the constructor.
         *
         * @param vec Data source.
         * @return Transformed data.
         */
        std::vector<uint8_t> transform(const std::vector<uint8_t>& vec) const;

        /**
         * @brief Get a data source and transform to itself.
         *
         * The transform is encrypt or decrypt depending on what was set in the constructor.
         *
         * @param vec Data source/target.
         */
        void transform_in(std::vector<uint8_t>& vec) const;

        /**
         * @brief Get the public key used for the creation of this RSADeviceCustom.
         * @return Public key.
         */
        UnsignedLong get_key() const;

        /**
         * @brief Get the mod key used for the creation of this RSADeviceCustom.
         * @return Mod key.
         */
        UnsignedLong get_mod() const;

        /**
         * @brief Get both public and mod keys on one thing.
         * @return Combo of keys.
         */
        RSA_keys<UnsignedLong> get_combo() const;
    };

    /**
     * @brief Simple RSA class capable of handling any input.
     *
     * Encrypts in 1/4 of the bits of UnsignedLong and saves as 1/2 of the bits of UnsignedLong.
     */
    template<typename UnsignedLong>
    class RSACustom {
    protected:
        bool is_prime(const UnsignedLong&) const;
        UnsignedLong prime_b(UnsignedLong, const bool = false) const;

        UnsignedLong find_prime_different_max(const std::function<UnsignedLong(void)> randomf, const UnsignedLong& lim, const UnsignedLong* arr, const size_t len);
        UnsignedLong p{}, e{}, n{}; // ops max 64 bit
    public:
        /**
         * @brief Generate keys using a seed.
         *
         * Same seed should generate same keys internally, so DO NOT USE A FIXED VALUE for a final product.
         *
         * @param seed A number for the internal random generator of primes.
         */
        void generate(const uint64_t& seed);

        /**
         * @brief Randomly generate primes for this RSA.
         * @return The random number generated internally.
         */
        uint64_t generate();

        /**
         * @brief Get the public key used for RSADevices.
         * @return Public key.
         */
        UnsignedLong get_key() const;

        /**
         * @brief Get the mod key used for RSADevices.
         * @return Mod key.
         */
        UnsignedLong get_mod() const;

        /**
         * @brief Get both public and mod keys on one thing.
         * @return Combo of keys.
         */
        RSA_keys<UnsignedLong> get_combo() const;

        /**
         * @brief Get encryptor for YOUR encryption! This uses the private key, and should be used only on YOUR side.
         * @return An RSADeviceCustom capable of encrypting data.
         */
        RSADeviceCustom<UnsignedLong> get_encrypt() const;

        /**
         * @brief Get the decryptor for this RSA.
         * @return An RSADeviceCustom capable of decrypting data.
         */
        RSADeviceCustom<UnsignedLong> get_decrypt() const;
    };

	using RSADevice = RSADeviceCustom<uint64_t>;
	using RSA = RSACustom<uint64_t>;

} // Encryption
} // Lunaris

#include <Lunaris/Encryption/impl/rsa.ipp>