#pragma once

#include "encryption.h"

// sometimes this is needed.
#undef max
#undef min

namespace Lunaris {

#ifdef LUNARIS_ENABLE_TABLEMATCH_ENCRYPTION

	template<typename T>
	inline const T& table_match<T>::encode(const T& key) const
	{
		auto it = mm_enc.find(key);
		if (it != mm_enc.end()) return *(it->second);
		throw std::runtime_error("table_match map not generated properly!");
		return {};
	}

	template<typename T>
	inline const T& table_match<T>::decode(const T& key) const
	{
		auto it = mm_dec.find(key);
		if (it != mm_dec.end()) return *(it->second);
		throw std::runtime_error("table_match map not generated properly!");
		return {};
	}

	template<typename T>
	inline void table_match<T>::generate(const uint64_t seed)
	{
		T p = 0;

		mm_enc.clear();
		mm_dec.clear();
		m_gen = seed;

		std::mt19937_64 gen(seed);
	
		std::vector<T> fun;
		fun.resize(std::numeric_limits<T>::max() + 1);

		do {
			fun[p] = p;
		} while (++p != 0);

		std::shuffle(fun.begin(), fun.end(), gen);

		do {
			const T& res = fun[p];
		
			auto ec = mm_enc.emplace(std::pair<T, T*>{ static_cast<T>(p), (T*)nullptr });
			auto dc = mm_dec.emplace(std::pair<T, T*>{ res, (T*)nullptr });
			ec.first->second = &dc.first->first;
			dc.first->second = &ec.first->first;
		} while (++p != 0);
	}

	template<typename T>
	inline uint64_t table_match<T>::generate()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());
		const T gn = gen();
		generate(gn);
		return gn;
	}

	template<typename T>
	inline std::vector<uint8_t> table_match<T>::encrypt(const uint8_t* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");

		std::vector<uint8_t> vec(data, data + len);
		uint8_t _c = 0;
		while ((vec.size() + 1) % sizeof(T)) { // fix size
			++_c;
			vec.push_back({});
		}
		vec.push_back(_c); // save
		encrypt_in((T*)vec.data(), vec.size() / sizeof(T));
		return vec;
	}

	template<typename T>
	inline std::vector<uint8_t> table_match<T>::decrypt(const uint8_t* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");
		if (len % sizeof(T)) throw std::invalid_argument("len CANNOT BE SOMETHING ELSE THAN multiple of sizeof(T)");

		std::vector<uint8_t> vec(data, data + len);
		decrypt_in((T*)vec.data(), vec.size() / sizeof(T));
		uint8_t _c = vec.back();
		vec.pop_back(); // _c
		while (_c--) vec.pop_back();
		return vec;
	}

	template<typename T>
	inline void table_match<T>::encrypt_in(T* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");
		for (size_t p = 0; p < len; ++p) data[p] = encode(data[p]);
	}

	template<typename T>
	inline void table_match<T>::decrypt_in(T* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");
		for (size_t p = 0; p < len; ++p) data[p] = decode(data[p]);
	}

	template<typename T>
	inline void table_match<T>::encrypt_in(std::vector<T>& vec) const
	{
		encrypt_in(vec.data(), vec.size());
	}

	template<typename T>
	inline void table_match<T>::decrypt_in(std::vector<T>& vec) const
	{
		decrypt_in(vec.data(), vec.size());
	}

#endif

	inline Lunaris::form_64::form_64(const uint64_t& seed)
		: m_seed(seed)
	{
	}
	
	inline void form_64::reseed(const uint64_t& seed)
	{
		m_seed = seed;
	}

	inline std::vector<uint8_t> form_64::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	inline std::vector<uint8_t> form_64::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	inline void form_64::encode_in(uint8_t* data, const size_t len) const
	{
		std::mt19937_64 gen(m_seed);

		uint64_t* cast = (uint64_t*)data;
		for (size_t p = 0; p < (len / sizeof(uint64_t)); ++p) {
			cast[p] += gen();
		}
		size_t rm = len % sizeof(uint64_t);

		if (rm >= sizeof(uint32_t)) {
			uint32_t* cast = (uint32_t*)data;
			const size_t lim = len / sizeof(uint32_t);
			cast[lim - 1] += static_cast<uint32_t>(gen());
			rm -= 4;
		}
		if (rm >= sizeof(uint16_t)) {
			uint16_t* cast = (uint16_t*)data;
			const size_t lim = len / sizeof(uint16_t);
			cast[lim - 1] += + static_cast<uint16_t>(gen());
			rm -= 4;
		}
		if (rm) {
			data[len - 1] += static_cast<uint8_t>(gen());
		}
	}

	inline void form_64::decode_in(uint8_t* data, const size_t len) const
	{
		std::mt19937_64 gen(m_seed);

		uint64_t* cast = (uint64_t*)data;
		for (size_t p = 0; p < (len / sizeof(uint64_t)); ++p) {
			cast[p] -= gen();
		}
		size_t rm = len % sizeof(uint64_t);

		if (rm >= sizeof(uint32_t)) {
			uint32_t* cast = (uint32_t*)data;
			const size_t lim = len / sizeof(uint32_t);
			cast[lim - 1] -= static_cast<uint32_t>(gen());
			rm -= 4;
		}
		if (rm >= sizeof(uint16_t)) {
			uint16_t* cast = (uint16_t*)data;
			const size_t lim = len / sizeof(uint16_t);
			cast[lim - 1] -= +static_cast<uint16_t>(gen());
			rm -= 4;
		}
		if (rm) {
			data[len - 1] -= static_cast<uint8_t>(gen());
		}
	}

	inline void form_64::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	inline void form_64::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}


	inline Lunaris::form_32::form_32(const uint32_t& seed)
		: m_seed(seed)
	{
	}

	inline void form_32::reseed(const uint32_t& seed)
	{
		m_seed = seed;
	}

	inline std::vector<uint8_t> form_32::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	inline std::vector<uint8_t> form_32::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	inline void form_32::encode_in(uint8_t* data, const size_t len) const
	{
		std::mt19937 gen(m_seed);

		uint32_t* cast = (uint32_t*)data;
		for (size_t p = 0; p < (len / sizeof(uint32_t)); ++p) {
			cast[p] += gen();
		}
		size_t rm = len % sizeof(uint32_t);

		if (rm >= sizeof(uint16_t)) {
			uint16_t* cast = (uint16_t*)data;
			const size_t lim = len / sizeof(uint16_t);
			cast[lim - 1] += +static_cast<uint16_t>(gen());
			rm -= 4;
		}
		if (rm) {
			data[len - 1] += static_cast<uint8_t>(gen());
		}
	}

	inline void form_32::decode_in(uint8_t* data, const size_t len) const
	{
		std::mt19937 gen(m_seed);

		uint32_t* cast = (uint32_t*)data;
		for (size_t p = 0; p < (len / sizeof(uint32_t)); ++p) {
			cast[p] -= gen();
		}
		size_t rm = len % sizeof(uint32_t);

		if (rm >= sizeof(uint16_t)) {
			uint16_t* cast = (uint16_t*)data;
			const size_t lim = len / sizeof(uint16_t);
			cast[lim - 1] -= +static_cast<uint16_t>(gen());
			rm -= 4;
		}
		if (rm) {
			data[len - 1] -= static_cast<uint8_t>(gen());
		}
	}

	inline void form_32::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	inline void form_32::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}



	template<typename T>
	const T RSA_device_custom<T>::mask = std::numeric_limits<T>::max() >> (sizeof(T) * 4); // if 8 bits, sizeof(T) == 1, move 4 bits -> sqrt(max(T))

	template<typename T>
	inline T RSA_device_custom<T>::enc(const T& num) const
	{
		T fin = 1;
		T count = 0;
		T pw = key & mask; // safety first
		const T rm = n & mask; // safety first

		while (pw) {
			T currpw = (pw & (static_cast<T>(0b1) << count++));
			if (!currpw) continue;
			pw &= ~currpw;

			T numc = num & mask; // safety first
			while (currpw >>= 1) {
				numc *= numc; // numc ^ 2
				numc %= rm; // result = (numc ^ 2) % rm;
			}
			fin *= numc;
			fin %= rm;
		}

		return fin;
	}

	template<typename T>
	inline RSA_device_custom<T>::RSA_device_custom(const RSA_device_custom<T>& device)
		: n(device.n), key(device.key), m_16to32(device.m_16to32)
	{
	}

	template<typename T>
	inline RSA_device_custom<T>::RSA_device_custom(const T& key, const T& mod, const bool enc)
		: key(key), n(mod), m_16to32(enc)
	{
	}

	template<typename T>
	inline RSA_device_custom<T>::RSA_device_custom(const RSA_keys<T>& as_dec)
		: key(as_dec.key), n(as_dec.mod), m_16to32(false)
	{
	}

	template<typename T>
	inline std::vector<uint8_t> RSA_device_custom<T>::transform(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> end;
		constexpr size_t s64 = sizeof(T); // assume this is max
		constexpr size_t s32 = sizeof(T) / 2; // so this is max rem (on other example, this was 
		constexpr size_t s16 = sizeof(T) / 4; // and this is max real number working on

		const auto pushT32 = [&](const T& num) { // num has s32 in size.
			for (size_t k = 0; k < s32; ++k) end.push_back(static_cast<uint8_t>(num >> (8 * k))); // in 64, 32 bit, so that's it
		};
		const auto pushT16 = [&](const T& num) { // num has s16 in size.
			for (size_t k = 0; k < s16; ++k) end.push_back(static_cast<uint8_t>(num >> (8 * k)));
		};
		const auto getT32 = [&](const size_t& at_in_T, const size_t off = 0) {
			T _n{};
			for (size_t k = 0; k < s32 && ((at_in_T * s32 + k + off) < len); ++k) _n |= (static_cast<T>(data[at_in_T * s32 + k + off]) << (8 * k));
			return _n;
		};
		const auto getT16 = [&](const size_t& at_in_T, const size_t off = 0) {
			T _n{};
			for (size_t k = 0; k < s16 && ((at_in_T * s16 + k + off) < len); ++k) _n |= (static_cast<T>(data[at_in_T * s16 + k + off]) << (8 * k));
			return _n;
		};

		if (m_16to32) {
			T rm = static_cast<T>(len % s16); // must hold as s16
			pushT16(rm); // first is key

			for (size_t p = 0; p < ((len / s16) + (rm > 0 ? 1 : 0)); ++p) {
				T _n = getT16(p);
				pushT32(enc(_n));
			}
		}
		else {
			const T rm = (getT16(0));

			for (size_t p = 0; p < (len / s32); ++p) {
				const T _n = getT32(p, s16); // combine s32 (8 * s32 = s64's bit)
				pushT16(enc(_n));// expect 1/2 of bytes of s64 by default
			}

			T rmtrash = ((s16 - rm) % s16);
			while (rmtrash--) end.pop_back();
		}

		return end;
	}

	template<typename T>
	inline std::vector<uint8_t> RSA_device_custom<T>::transform(const std::vector<uint8_t>& vec) const
	{
		return transform(vec.data(), vec.size());
	}

	template<typename T>
	inline void RSA_device_custom<T>::transform_in(std::vector<uint8_t>& vec) const
	{
		vec = transform(vec);
	}

	template<typename T>
	inline T RSA_device_custom<T>::get_key() const
	{
		return key;
	}

	template<typename T>
	inline T RSA_device_custom<T>::get_mod() const
	{
		return n;
	}

	template<typename T>
	inline RSA_keys<T> RSA_device_custom<T>::get_combo() const
	{
		return RSA_keys<T>{ key, n};
	}

	template<typename T>
	inline bool RSA_custom<T>::is_prime(const T& test) const
	{
		if (test == 2 || test == 3)
			return true;
		if (test <= 1 || test % 2 == 0 || test % 3 == 0)
			return false;
		for (T i = 5; i * i <= test; i += 6) {
			if (test % i == 0 || test % (i + 2) == 0)
				return false;
		}
		return true;
	}

	template<typename T>
	inline T RSA_custom<T>::prime_b(T p, const bool noexc) const
	{
		while (!is_prime(--p) && p > 2);
		if (p <= 2) {
			if (noexc) return 0;
			throw std::runtime_error("Somehow primeb got invalid prime lesser than expected prime limit");
		}
		return p;
	}

	template<typename T>
	inline T RSA_custom<T>::find_prime_different_max(const std::function<T(void)> randomf, const T& lim, const T* arr, const size_t len)
	{
		const auto validate = [&](const T& n) {
			if (n < 2) return false;
			if (!arr) return true;
			for (const T* it = arr; it != (arr + len); ++it) if (*it == n) return false;
			return true;
		};

		T _t;

		while (1) {
			_t = prime_b(randomf() % lim);
			if (validate(_t)) return _t;
		}
		return 0;
	}

	template<typename T>
	inline void RSA_custom<T>::generate(const uint64_t& seed)
	{
		std::mt19937_64 gen(seed);
		std::uniform_int_distribution<T> dis;

		constexpr T maxx = std::numeric_limits<T>::max() >> (sizeof(T) * 4); // limit for operations. 32 bit number * 32 bit number = 64 bit number, fits uint64_t.
		constexpr T less = std::numeric_limits<T>::max() >> (sizeof(T) * 7); // minimum value trying for primes. Lowest prime possible should be bigger than this.
		constexpr T expc = std::numeric_limits<T>::max() >> (sizeof(T) * 6); // primes must fit into 16 unfortunately, so n fits in 32 and operations fit in 64.


		T primes[3]{ 0 };
		while ((primes[0] * primes[1]) < expc) { // force 16 bit minimum for N!
			for (auto& i : primes) { i = find_prime_different_max([&] {return less + (dis(gen) % (expc - less - 1)); }, expc, primes, std::size(primes)); }
		}

		// has primes from here. Random primes, probably.

		n = (primes[0] * primes[1]); // there's no DOUBT this is > than 16 bit and < than 32. This is A MUST because numbers later are % this, so this > 16 bit for functional purposes.
		if (n < expc) throw std::runtime_error("N must be more than 1/4 of the bits of T, but it isn't somehow. Please call for help!"); // I did this anyway (read line above kekw)
		e = (primes[2]) & maxx;

		const T phi = ((primes[0] - 1) * (primes[1] - 1));

		{
			T k = 1;
			T tmpp = 0;
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

	template<typename T>
	inline uint64_t RSA_custom<T>::generate()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());
		const uint64_t gn = gen();
		generate(gn);
		return gn;
	}

	template<typename T>
	inline T RSA_custom<T>::get_key() const
	{
		return p;
	}

	template<typename T>
	inline T RSA_custom<T>::get_mod() const
	{
		return n;
	}

	template<typename T>
	inline RSA_keys<T> RSA_custom<T>::get_combo() const
	{
		return RSA_keys<T>{ p, n };
	}

	template<typename T>
	inline RSA_device_custom<T> RSA_custom<T>::get_encrypt() const
	{
		return RSA_device_custom<T>(e, n, true);
	}

	template<typename T>
	inline RSA_device_custom<T> RSA_custom<T>::get_decrypt() const
	{
		return RSA_device_custom<T>(p, n, false);
	}


	inline Lunaris::RSA_plus::RSA_plus()
		: form_64(0) // This is not random because I don't want people thinking this is broken without any proper config
	{
	}

	inline void RSA_plus::as_decoder(const uint64_t& pubkey, const uint64_t& modkey)
	{
		m_is_enc = false;
		m_pub_cpy_p = pubkey;
		m_pub_cpy_m = modkey;
		crypt = std::make_unique<RSA_device>(pubkey, modkey, false); // decrypt
		this->form_64::operator=(form_64(m_pub_cpy_p));
	}

	inline void RSA_plus::as_decoder(const RSA_keys<uint64_t>& keys)
	{
		as_decoder(keys.key, keys.mod);
	}

	inline void RSA_plus::as_encoder(const uint64_t& seed)
	{
		m_is_enc = true;
		RSA fun;
		fun.generate(seed);
		crypt = std::make_unique<RSA_device>(fun.get_encrypt());
		m_pub_cpy_p = fun.get_key();
		m_pub_cpy_m = fun.get_mod();
		this->form_64::operator=(form_64(m_pub_cpy_p)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	inline void RSA_plus::as_encoder()
	{
		m_is_enc = true;
		RSA fun;
		fun.generate();
		crypt = std::make_unique<RSA_device>(fun.get_encrypt());
		m_pub_cpy_p = fun.get_key();
		m_pub_cpy_m = fun.get_mod();
		this->form_64::operator=(form_64(m_pub_cpy_p)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	inline uint64_t RSA_plus::get_key() const
	{
		return m_pub_cpy_p;
	}

	inline uint64_t RSA_plus::get_mod() const
	{
		return m_pub_cpy_m;
	}

	inline RSA_keys<uint64_t> RSA_plus::get_combo() const
	{
		return RSA_keys<uint64_t>{ m_pub_cpy_p, m_pub_cpy_m };
	}

	inline bool RSA_plus::is_encoder() const
	{
		return m_is_enc;
	}

	inline bool RSA_plus::transform(const uint8_t* data, const size_t len, std::vector<uint8_t>& push, const bool exceptions) const
	{
		try {
			if (!crypt) throw std::runtime_error("You must init as encoder or decoder using as_encoder() or as_decoder()");

			push.clear();

			if (is_encoder()) {
				auto venc = this->form_64::encode(data, len);
				push.insert(push.end(), std::make_move_iterator(venc.begin()), std::make_move_iterator(venc.end()));
				crypt->transform_in(push);
			}
			else { // inverse order
				push = std::vector<uint8_t>(data, data + len);
				crypt->transform_in(push);
				push = this->form_64::decode(push.data(), push.size());
			}
		}
		catch (...) {
			std::exception_ptr eptr = std::current_exception();
			if (exceptions) throw eptr;
			else return false;
		}
		return true;
	}

	inline bool RSA_plus::transform(std::vector<uint8_t>& vec, const bool exceptions) const
	{
		std::vector<uint8_t> targ;
		const bool gud = transform(vec.data(), vec.size(), targ, exceptions);
		vec = std::move(targ);
		return gud;
	}

	inline RSA_plus::operator RSA_keys<uint64_t>() const
	{
		return get_combo();
	}

	inline RSA_plus make_encrypt_auto()
	{
		RSA_plus set;
		set.as_encoder();
		return set;
	}

	inline RSA_plus make_decrypt_auto(const RSA_keys<uint64_t>& keys)
	{
		RSA_plus set;
		set.as_decoder(keys);
		return set;
	}

}