#pragma once

namespace Lunaris {
namespace Encryption {
    
	template<typename UnsignedLong>
	inline UnsignedLong RSADeviceCustom<UnsignedLong>::enc(const UnsignedLong& num) const
	{
		UnsignedLong fin = 1;
		UnsignedLong count = 0;
		UnsignedLong pw = key & rsa_mask<UnsignedLong>; // safety first
		const UnsignedLong rm = n & rsa_mask<UnsignedLong>; // safety first

		while (pw) {
			UnsignedLong currpw = (pw & (static_cast<UnsignedLong>(0b1) << count++));
			if (!currpw) continue;
			pw &= ~currpw;

			UnsignedLong numc = num & rsa_mask<UnsignedLong>; // safety first
			while (currpw >>= 1) {
				numc *= numc; // numc ^ 2
				numc %= rm; // result = (numc ^ 2) % rm;
			}
			fin *= numc;
			fin %= rm;
		}

		return fin;
	}

	template<typename UnsignedLong>
	inline RSADeviceCustom<UnsignedLong>::RSADeviceCustom(const RSADeviceCustom<UnsignedLong>& device)
		: n(device.n), key(device.key), m_16to32(device.m_16to32)
	{
	}

	template<typename UnsignedLong>
	inline RSADeviceCustom<UnsignedLong>::RSADeviceCustom(const UnsignedLong& key, const UnsignedLong& mod, const bool enc)
		: key(key), n(mod), m_16to32(enc)
	{
	}

	template<typename UnsignedLong>
	inline RSADeviceCustom<UnsignedLong>::RSADeviceCustom(const RSA_keys<UnsignedLong>& as_dec)
		: key(as_dec.key), n(as_dec.mod), m_16to32(false)
	{
	}

	template<typename UnsignedLong>
	inline std::vector<uint8_t> RSADeviceCustom<UnsignedLong>::transform(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> end;
		constexpr size_t s64 = sizeof(UnsignedLong); // assume this is max
		constexpr size_t s32 = sizeof(UnsignedLong) / 2; // so this is max rem (on other example, this was 
		constexpr size_t s16 = sizeof(UnsignedLong) / 4; // and this is max real number working on

		const auto pushT32 = [&](const UnsignedLong& num) { // num has s32 in size.
			for (size_t k = 0; k < s32; ++k) end.push_back(static_cast<uint8_t>(num >> (8 * k))); // in 64, 32 bit, so that's it
		};
		const auto pushT16 = [&](const UnsignedLong& num) { // num has s16 in size.
			for (size_t k = 0; k < s16; ++k) end.push_back(static_cast<uint8_t>(num >> (8 * k)));
		};
		const auto getT32 = [&](const size_t& at_in_T, const size_t off = 0) {
			UnsignedLong _n{};
			for (size_t k = 0; k < s32 && ((at_in_T * s32 + k + off) < len); ++k) _n |= (static_cast<UnsignedLong>(data[at_in_T * s32 + k + off]) << (8 * k));
			return _n;
		};
		const auto getT16 = [&](const size_t& at_in_T, const size_t off = 0) {
			UnsignedLong _n{};
			for (size_t k = 0; k < s16 && ((at_in_T * s16 + k + off) < len); ++k) _n |= (static_cast<UnsignedLong>(data[at_in_T * s16 + k + off]) << (8 * k));
			return _n;
		};

		if (m_16to32) {
			UnsignedLong rm = static_cast<UnsignedLong>(len % s16); // must hold as s16
			pushT16(rm); // first is key

			for (size_t p = 0; p < ((len / s16) + (rm > 0 ? 1 : 0)); ++p) {
				UnsignedLong _n = getT16(p);
				pushT32(enc(_n));
			}
		}
		else {
			const UnsignedLong rm = (getT16(0));

			for (size_t p = 0; p < (len / s32); ++p) {
				const UnsignedLong _n = getT32(p, s16); // combine s32 (8 * s32 = s64's bit)
				pushT16(enc(_n));// expect 1/2 of bytes of s64 by default
			}

			UnsignedLong rmtrash = ((s16 - rm) % s16);
			while (rmtrash--) end.pop_back();
		}

		return end;
	}

	template<typename UnsignedLong>
	inline std::vector<uint8_t> RSADeviceCustom<UnsignedLong>::transform(const std::vector<uint8_t>& vec) const
	{
		return transform(vec.data(), vec.size());
	}

	template<typename UnsignedLong>
	inline void RSADeviceCustom<UnsignedLong>::transform_in(std::vector<uint8_t>& vec) const
	{
		vec = transform(vec);
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSADeviceCustom<UnsignedLong>::get_key() const
	{
		return key;
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSADeviceCustom<UnsignedLong>::get_mod() const
	{
		return n;
	}

	template<typename UnsignedLong>
	inline RSA_keys<UnsignedLong> RSADeviceCustom<UnsignedLong>::get_combo() const
	{
		return RSA_keys<UnsignedLong>{ key, n};
	}

	template<typename UnsignedLong>
	inline bool RSACustom<UnsignedLong>::is_prime(const UnsignedLong& test) const
	{
		if (test == 2 || test == 3)
			return true;
		if (test <= 1 || test % 2 == 0 || test % 3 == 0)
			return false;
		for (UnsignedLong i = 5; i * i <= test; i += 6) {
			if (test % i == 0 || test % (i + 2) == 0)
				return false;
		}
		return true;
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSACustom<UnsignedLong>::prime_b(UnsignedLong p, const bool noexc) const
	{
		while (!is_prime(--p) && p > 2);
		if (p <= 2) {
			if (noexc) return 0;
			throw std::runtime_error("Somehow primeb got invalid prime lesser than expected prime limit");
		}
		return p;
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSACustom<UnsignedLong>::find_prime_different_max(const std::function<UnsignedLong(void)> randomf, const UnsignedLong& lim, const UnsignedLong* arr, const size_t len)
	{
		const auto validate = [&](const UnsignedLong& n) {
			if (n < 2) return false;
			if (!arr) return true;
			for (const UnsignedLong* it = arr; it != (arr + len); ++it) if (*it == n) return false;
			return true;
		};

		UnsignedLong _t;

		while (1) {
			_t = prime_b(randomf() % lim);
			if (validate(_t)) return _t;
		}
		return 0;
	}

	template<typename UnsignedLong>
	inline void RSACustom<UnsignedLong>::generate(const uint64_t& seed)
	{
		std::mt19937_64 gen(seed);
		std::uniform_int_distribution<UnsignedLong> dis;

		constexpr UnsignedLong maxx = std::numeric_limits<UnsignedLong>::max() >> (sizeof(UnsignedLong) * 4); // limit for operations. 32 bit number * 32 bit number = 64 bit number, fits uint64_t.
		constexpr UnsignedLong less = std::numeric_limits<UnsignedLong>::max() >> (sizeof(UnsignedLong) * 7); // minimum value trying for primes. Lowest prime possible should be bigger than this.
		constexpr UnsignedLong expc = std::numeric_limits<UnsignedLong>::max() >> (sizeof(UnsignedLong) * 6); // primes must fit into 16 unfortunately, so n fits in 32 and operations fit in 64.


		UnsignedLong primes[3]{ 0 };
		while ((primes[0] * primes[1]) < expc) { // force 16 bit minimum for N!
			for (auto& i : primes) { i = find_prime_different_max([&] {return less + (dis(gen) % (expc - less - 1)); }, expc, primes, std::size(primes)); }
		}

		// has primes from here. Random primes, probably.

		n = (primes[0] * primes[1]); // there's no DOUBT this is > than 16 bit and < than 32. This is A MUST because numbers later are % this, so this > 16 bit for functional purposes.
		if (n < expc) throw std::runtime_error("N must be more than 1/4 of the bits of UnsignedLong, but it isn't somehow. Please call for help!"); // I did this anyway (read line above kekw)
		e = (primes[2]) & maxx;

		const UnsignedLong phi = ((primes[0] - 1) * (primes[1] - 1));

		{
			UnsignedLong k = 1;
			UnsignedLong tmpp = 0;
			while (1) {
				if (((k * phi + 1) % e) == 0) {
					if (((tmpp = (k * phi + 1) / e) % phi) == 0) continue;

					if (tmpp > maxx) throw std::runtime_error("P value must not be bigger than 32 bits. Math failed internally :("); // the numbers * numbers % this should be <= 32 bit so next (this * this) won't overflow 64 bit
					p = tmpp;
					break;
				}
				if (++k == 0) throw std::runtime_error("Fatal error generating internal RSA");
			}
		}
	}

	template<typename UnsignedLong>
	inline uint64_t RSACustom<UnsignedLong>::generate()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());
		const uint64_t gn = gen();
		generate(gn);
		return gn;
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSACustom<UnsignedLong>::get_key() const
	{
		return p;
	}

	template<typename UnsignedLong>
	inline UnsignedLong RSACustom<UnsignedLong>::get_mod() const
	{
		return n;
	}

	template<typename UnsignedLong>
	inline RSA_keys<UnsignedLong> RSACustom<UnsignedLong>::get_combo() const
	{
		return RSA_keys<UnsignedLong>{ p, n };
	}

	template<typename UnsignedLong>
	inline RSADeviceCustom<UnsignedLong> RSACustom<UnsignedLong>::get_encrypt() const
	{
		return RSADeviceCustom<UnsignedLong>(e, n, true);
	}

	template<typename UnsignedLong>
	inline RSADeviceCustom<UnsignedLong> RSACustom<UnsignedLong>::get_decrypt() const
	{
		return RSADeviceCustom<UnsignedLong>(p, n, false);
	}

} // Encryption
} // Lunaris