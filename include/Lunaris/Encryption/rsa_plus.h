#pragma once

#include <memory>

#include <Lunaris/Encryption/form.h>
#include <Lunaris/Encryption/rsa.h>

namespace Lunaris {
namespace Encryption {

    /**
     * @brief Simple combined RSA (32-bit) + Form64 class.
     *
     * Adds both fast worlds into a messy fast one. Hopefully this is secure
     * enough for most non-long applications.
     */
    class RSAPlus : protected Form64 {
    protected:
        std::unique_ptr<RSADevice> crypt;
        uint64_t m_pub_cpy_p{}, m_pub_cpy_m{};
        bool m_is_enc{};
    public:
        RSAPlus();

        /**
         * @brief Are you the receptor? You call as_decoder then.
         * @param pubkey The public key from the other side doing cryptographic stuff.
         * @param modkey The mod key from the other side doing cryptographic stuff.
         */
        void as_decoder(const uint64_t& pubkey, const uint64_t& modkey);

        /**
         * @brief Are you the receptor? You call as_decoder then.
         *
         * This gets both keys at once.
         *
         * @param keys The keys from the other side doing cryptographic stuff.
         */
        void as_decoder(const RSA_keys<uint64_t>& keys);

        /**
         * @brief Do you want to encrypt stuff and send to someone? That's how you do that.
         * @param seed A seed for internal number generation. Expected to be random for security.
         */
        void as_encoder(const uint64_t& seed);

        /**
         * @brief Do you want to encrypt stuff and send to someone? That's how you do that.
         *
         * This will create random numbers inside for all.
         */
        void as_encoder();

        /**
         * @brief Get the public key used on the other side.
         * @return Public key.
         */
        uint64_t get_key() const;

        /**
         * @brief Get the mod key used on the other side.
         * @return Mod key.
         */
        uint64_t get_mod() const;

        /**
         * @brief Get both public and mod keys in one object.
         * @return Combo of keys.
         */
        RSA_keys<uint64_t> get_combo() const;

        /**
         * @brief Are you the owner of the private key or receiving encrypted data?
         * @return True if you've got the private key!
         */
        bool is_encoder() const;

        /**
         * @brief Transform data as the cryptographer or decryptographer.
         * @param data Data source.
         * @param len Data size, in bytes.
         * @param push Output container where transformed data will be placed.
         * @param exceptions If failure happens, throw? (otherwise return false).
         * @return True on success; false on failure when exceptions are disabled.
         */
        bool transform(const uint8_t* data, const size_t len, std::vector<uint8_t>& push, const bool exceptions = true) const;

        /**
         * @brief Transform data in-place as the cryptographer or decryptographer.
         * @param vec Data source and target.
         * @param exceptions If failure happens, throw? (otherwise return false).
         * @return True on success; false on failure when exceptions are disabled.
         */
        bool transform(std::vector<uint8_t>& vec, const bool exceptions = true) const;

        operator RSA_keys<uint64_t>() const;
    };

    RSAPlus make_encrypt_auto();
    RSAPlus make_decrypt_auto(const RSA_keys<uint64_t>& public_key);

} // Encryption
} // Lunaris