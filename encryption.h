#pragma once

#include <stdint.h>
#include <random>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <memory>

namespace Lunaris {

#ifdef LUNARIS_ENABLE_TABLEMATCH_ENCRYPTION
	/// <summary>
	/// <para>table_match is a stupid simple algorithm that randomly creates a table from your seed (or totally random) to replace a number to another.</para>
	/// <para>It has two maps internally pointing to each other (once set).</para>
	/// <para>WARN: Bigger the T, bigger the maps! This gets big FAST. It is FAST, but it EATS memory!</para>
	/// </summary>
	/// <typeparam name="T">Base type. Try uint8_t or uint16_t first. uint32_t is too big for most systems.</typeparam>
	template<typename T>
	class table_match {
#ifndef LUNARIS_UNSAFE
		static_assert(std::is_unsigned_v<T>, "Must be unsigned!");
#endif

		std::unordered_map<T, const T*> mm_enc, mm_dec;
		uint64_t m_gen = 0;

		const T& encode(const T&) const;
		const T& decode(const T&) const;
	public:
		/// <summary>
		/// <para>Make internal map based on seed.</para>
		/// </summary>
		/// <param name="seed">The seed used to generate the table.</param>
		void generate(const uint64_t seed);

		/// <summary>
		/// <para>Create a random seed and generate the internal map.</para>
		/// </summary>
		/// <returns>{uint64_t} The seed used.</returns>
		uint64_t generate();

		/// <summary>
		/// <para>Encrypt a message using the internal table.</para>
		/// </summary>
		/// <param name="data">Data start.</param>
		/// <param name="len">Data size, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data encrypted.</returns>
		std::vector<uint8_t> encrypt(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Decrypt a message using the internal table.</para>
		/// </summary>
		/// <param name="data">Data start.</param>
		/// <param name="len">Data size, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data decrypted.</returns>
		std::vector<uint8_t> decrypt(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Encrypt the data into itself (overwrite).</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data size, of T's.</param>
		void encrypt_in(T* data, const size_t len) const;

		/// <summary>
		/// <para>Decrypt the data into itself (overwrite).</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data size, of T's.</param>
		void decrypt_in(T* data, const size_t len) const;

		/// <summary>
		/// <para>Encrypt the data into itself (overwrite).</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void encrypt_in(std::vector<T>& vec) const;

		/// <summary>
		/// <para>Decrypt the data into itself (overwrite).</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void decrypt_in(std::vector<T>& vec) const;
	};
#endif

	/// <summary>
	/// <para>This is a basic layer on top of a simple random seed-generated combined sum.</para>
	/// <para>By itself it's not secure, but maybe it's another step on top of something else.</para>
	/// <para>This is the 64 bit version.</para>
	/// </summary>
	class form_64 {
		uint64_t m_seed;
	public:
		/// <summary>
		/// <para>Create with a seed directly.</para>
		/// </summary>
		/// <param name="seed">Seed to setup for every encode/decode.</param>
		form_64(const uint64_t& seed);

		/// <summary>
		/// <para>Set internal seed for encode/decode operations.</para>
		/// </summary>
		/// <param name="seed">Seed to setup for every encode/decode.</param>
		void reseed(const uint64_t&);

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data length, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data encrypted with randomness.</returns>
		std::vector<uint8_t> encode(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data length, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data decrypted with randomness.</returns>
		std::vector<uint8_t> decode(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed and save into itself.</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data length, in bytes.</param>
		void encode_in(uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed and save into itself.</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data length, in bytes.</param>
		void decode_in(uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed and save into itself.</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void encode_in(std::vector<uint8_t>& vec) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed and save into itself.</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void decode_in(std::vector<uint8_t>& vec) const;
	};

	/// <summary>
	/// <para>This is a basic layer on top of a simple random seed-generated combined sum.</para>
	/// <para>By itself it's not secure, but maybe it's another step on top of something else.</para>
	/// <para>This is the 32 bit version.</para>
	/// </summary>
	class form_32 {
		uint32_t m_seed;
	public:
		/// <summary>
		/// <para>Create with a seed directly.</para>
		/// </summary>
		/// <param name="seed">Seed to setup for every encode/decode.</param>
		form_32(const uint32_t& seed);

		/// <summary>
		/// <para>Set internal seed for encode/decode operations.</para>
		/// </summary>
		/// <param name="seed">Seed to setup for every encode/decode.</param>
		void reseed(const uint32_t&);

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data length, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data encrypted with randomness.</returns>
		std::vector<uint8_t> encode(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data length, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} The final data decrypted with randomness.</returns>
		std::vector<uint8_t> decode(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed and save into itself.</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data length, in bytes.</param>
		void encode_in(uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed and save into itself.</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="len">Data length, in bytes.</param>
		void decode_in(uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Encode data using sequential random sum based on seed and save into itself.</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void encode_in(std::vector<uint8_t>& vec) const;

		/// <summary>
		/// <para>Decode data using sequential random sub based on seed and save into itself.</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void decode_in(std::vector<uint8_t>& vec) const;
	};

	/// <summary>
	/// <para>This is used like the public and mod keys. It is a shortcut.</para>
	/// </summary>
	template<typename T>
	struct RSA_keys {
		T key, mod; // do not change order
	};

	/// <summary>
	/// <para>A RSA encrypt/decrypt object (it depends on source). It uses internal keys to work.</para>
	/// <para>It is expected to create one of this from a RSA_custom.</para>
	/// </summary>
	template<typename T>
	class RSA_device_custom {
#ifndef LUNARIS_UNSAFE
		static_assert(sizeof(T) >= 4, "Too small for operations!");
		static_assert(std::is_unsigned_v<T>, "Must be unsigned!");
#endif

		static const T mask; // must be sqrt(T) for half the bytes so ops won't get bigger than T
		const T n, key;
		const bool m_16to32; // encryptor? aka encrypt? false == decrypt

		T enc(const T&) const; // T max expected = mask
	public:
		/// <summary>
		/// <para>Copy constructor.</para>
		/// </summary>
		/// <param name="const RSA_device_custom&amp;">A RSA_device_custom to copy from.</param>
		RSA_device_custom(const RSA_device_custom<T>&);

		/// <summary>
		/// <para>Main constructor used by RSA.</para>
		/// </summary>
		/// <param name="key">Key.</param>
		/// <param name="mod">Mod.</param>
		/// <param name="enc">Work as encrypt? (Encoder do 16 bit to 32 bit, decryptor is the opposite).</param>
		RSA_device_custom(const T& key, const T& mod, const bool enc = false); // T max expected = mask

		/// <summary>
		/// <para>Assuming that you're doing decode and got directly this thing containing public key and mod.</para>
		/// </summary>
		/// <param name="as_dec">The public keys</param>
		RSA_device_custom(const RSA_keys<T>& as_dec);

		/// <summary>
		/// <para>Get a data source and transform.</para>
		/// <para>The transform is encrypt or decrypt depending on what was set in the constructor.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data length, in bytes.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} Transformed data.</returns>
		std::vector<uint8_t> transform(const uint8_t* data, const size_t len) const;

		/// <summary>
		/// <para>Get a data source and transform.</para>
		/// <para>The transform is encrypt or decrypt depending on what was set in the constructor.</para>
		/// </summary>
		/// <param name="vec">Data source.</param>
		/// <returns>{std::vector&lt;uint8_t&gt;} Transformed data.</returns>
		std::vector<uint8_t> transform(const std::vector<uint8_t>& vec) const;

		/// <summary>
		/// <para>Get a data source and transform to itself.</para>
		/// <para>The transform is encrypt or decrypt depending on what was set in the constructor.</para>
		/// </summary>
		/// <param name="vec">Data source/target.</param>
		void transform_in(std::vector<uint8_t>& vec) const;

		/// <summary>
		/// <para>Get the public key used for the creation of this RSA_device_custom.</para>
		/// </summary>
		/// <returns>{T} Public key.</returns>
		T get_key() const;

		/// <summary>
		/// <para>Get the mod key used for the creation of this RSA_device_custom.</para>
		/// </summary>
		/// <returns>{T} Mod key.</returns>
		T get_mod() const;

		/// <summary>
		/// <para>Get both public and mod keys on one thing.</para>
		/// </summary>
		/// <returns>{RSA_keys&lt;T&gt;} Combo of keys.</returns>
		RSA_keys<T> get_combo() const;
	};

	/// <summary>
	/// <para>This is a simple RSA class capable of handling any input.</para>
	/// <para>It will encrypt in 1/4 of the bits of T and save as 1/2 of the bits of T.</para>
	/// </summary>
	template<typename T>
	class RSA_custom {
#ifndef LUNARIS_UNSAFE
		static_assert(sizeof(T) >= 4, "Too small for operations!");
		static_assert(std::is_unsigned_v<T>, "Must be unsigned!");
#endif

		bool is_prime(const T&) const;
		T prime_b(T, const bool = false) const;

		T find_prime_different_max(const std::function<T(void)> randomf, const T& lim, const T* arr, const size_t len);
	protected:
		T p{}, e{}, n{}; // ops max 64 bit
	public:
		/// <summary>
		/// <para>Generate keys using a seed.</para>
		/// <para>Same seed should generate same keys internally, so DO NOT USE A FIXED VALUE for a final product or something.</para>
		/// </summary>
		/// <param name="seed">A number for the internal random generator of primes.</param>
		void generate(const uint64_t& seed);

		/// <summary>
		/// <para>Randomly generate primes for this RSA.</para>
		/// </summary>
		/// <returns>{uint64_t} The random number generated internally.</returns>
		uint64_t generate();

		/// <summary>
		/// <para>Get the public key used for RSA_devices.</para>
		/// </summary>
		/// <returns>{T} Public key.</returns>
		T get_key() const;

		/// <summary>
		/// <para>Get the mod key used for RSA_devices.</para>
		/// </summary>
		/// <returns>{T} Mod key.</returns>
		T get_mod() const;

		/// <summary>
		/// <para>Get both public and mod keys on one thing.</para>
		/// </summary>
		/// <returns>{RSA_keys&lt;T&gt;} Combo of keys.</returns>
		RSA_keys<T> get_combo() const;

		/// <summary>
		/// <para>Get encryptor for YOUR encryption! This uses the private key, and should be used only on YOUR side.</para>
		/// </summary>
		/// <returns>{RSA_device_custom} A RSA_device_custom capable of encrypting data.</returns>
		RSA_device_custom<T> get_encrypt() const;

		/// <summary>
		/// <para>Get the decryptor for this RSA.</para>
		/// </summary>
		/// <returns>{RSA_device_custom} A RSA_device_custom capable of decrypting data.</returns>
		RSA_device_custom<T> get_decrypt() const;
	};

	using RSA_device = RSA_device_custom<uint64_t>;
	using RSA = RSA_custom<uint64_t>;

	/// <summary>
	/// <para>This is a simple combined RSA (32 bit) + form_64 class. This adds both fast worlds into a messy fast one.</para>
	/// <para>Hopefully this is secure enough for most not-long applications.</para>
	/// </summary>
	class RSA_plus : protected form_64 {
		std::unique_ptr<RSA_device> crypt;
		uint64_t m_pub_cpy_p{}, m_pub_cpy_m{};
		bool m_is_enc{};
	public:
		RSA_plus();

		/// <summary>
		/// <para>Are you the receptor? You call the as_decoder then.</para>
		/// </summary>
		/// <param name="pubkey">The public key from the other side doing cryptographic stuff.</param>
		/// <param name="modkey">The mod key from the other side doing cryptographic stuff.</param>
		void as_decoder(const uint64_t& pubkey, const uint64_t& modkey);

		/// <summary>
		/// <para>Are you the receptor? You call the as_decoder then.</para>
		/// <para>This gets both keys at once.</para>
		/// </summary>
		/// <param name="keys">The keys from the other side doing cryptographic stuff.</param>
		void as_decoder(const RSA_keys<uint64_t>& keys);

		/// <summary>
		/// <para>Do you want to cryptograph stuff and send to someone? That's how you do that.</para>
		/// </summary>
		/// <param name="seed">A seed for internal number generation. It is expected to be random for security reasons.</param>
		void as_encoder(const uint64_t& seed);

		/// <summary>
		/// <para>Do you want to cryptograph stuff and send to someone? That's how you do that.</para>
		/// <para>This will create random numbers inside for all.</para>
		/// </summary>
		void as_encoder();

		/// <summary>
		/// <para>Get the public key used on the other side. This is used there with as_decoder, as you'd probably guessed already..</para>
		/// </summary>
		/// <returns>{T} Public key.</returns>
		uint64_t get_key() const;

		/// <summary>
		/// <para>Get the mod key used on the other side. This is used there with as_decoder, as you'd probably guessed already..</para>
		/// </summary>
		/// <returns>{T} Mod key.</returns>
		uint64_t get_mod() const;

		/// <summary>
		/// <para>Get both public and mod keys on one thing.</para>
		/// </summary>
		/// <returns>{RSA_keys&lt;T&gt;} Combo of keys.</returns>
		RSA_keys<uint64_t> get_combo() const;

		/// <summary>
		/// <para>Are you the ownder of the private key or are you the one receiving the cryptographed stuff?</para>
		/// </summary>
		/// <returns>{bool} True if you've got the private key!</returns>
		bool is_encoder() const;

		/// <summary>
		/// <para>Transform data as the cryphographer or de decryptographer.</para>
		/// </summary>
		/// <param name="data">Data source.</param>
		/// <param name="len">Data size, in bytes.</param>
		/// <param name="push">The place where stuff will be placed.</param>
		/// <param name="exceptions">If fails happen somehow, throw? (or return false)</param>
		/// <returns>{bool} If no exceptions, return false on failure, else in any case returns true.</returns>
		bool transform(const uint8_t* data, const size_t len, std::vector<uint8_t>& push, const bool exceptions = true) const;

		/// <summary>
		/// <para>Transform data as the cryphographer or de decryptographer.</para>
		/// </summary>
		/// <param name="data">Data source/target.</param>
		/// <param name="exceptions">If fails happen somehow, throw? (or return false)</param>
		/// <returns>{bool} If no exceptions, return false on failure, else in any case returns true.</returns>
		bool transform(std::vector<uint8_t>& vec, const bool exceptions = true) const;

		operator RSA_keys<uint64_t>() const;
	};

	RSA_plus make_encrypt_auto();
	RSA_plus make_decrypt_auto(const RSA_keys<uint64_t>& public_key);

}

#include "encryption.ipp"
