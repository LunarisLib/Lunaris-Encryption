#pragma once

#include "encryption.h"

namespace Lunaris {

#ifdef LUNARIS_ENABLE_TABLEMATCH_ENCRYPTION

	template<typename T>
	inline const T& TableMatch<T>::encode(const T& key) const
	{
		auto it = mm_enc.find(key);
		if (it != mm_enc.end()) return *(it->second);
		throw std::runtime_error("TableMatch map not generated properly!");
		return {};
	}

	template<typename T>
	inline const T& TableMatch<T>::decode(const T& key) const
	{
		auto it = mm_dec.find(key);
		if (it != mm_dec.end()) return *(it->second);
		throw std::runtime_error("TableMatch map not generated properly!");
		return {};
	}

	template<typename T>
	inline void TableMatch<T>::generate(const uint64_t seed)
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
	inline uint64_t TableMatch<T>::generate()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());
		const T gn = gen();
		generate(gn);
		return gn;
	}

	template<typename T>
	inline std::vector<uint8_t> TableMatch<T>::encrypt(const uint8_t* data, const size_t len) const
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
	inline std::vector<uint8_t> TableMatch<T>::decrypt(const uint8_t* data, const size_t len) const
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
	inline void TableMatch<T>::encrypt_in(T* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");
		for (size_t p = 0; p < len; ++p) data[p] = encode(data[p]);
	}

	template<typename T>
	inline void TableMatch<T>::decrypt_in(T* data, const size_t len) const
	{
		if (mm_dec.empty() || mm_dec.size() != mm_enc.size()) throw std::runtime_error("Invalid map or not generated!");
		for (size_t p = 0; p < len; ++p) data[p] = decode(data[p]);
	}

	template<typename T>
	inline void TableMatch<T>::encrypt_in(std::vector<T>& vec) const
	{
		encrypt_in(vec.data(), vec.size());
	}

	template<typename T>
	inline void TableMatch<T>::decrypt_in(std::vector<T>& vec) const
	{
		decrypt_in(vec.data(), vec.size());
	}

#endif

	inline Lunaris::Form64::Form64(const uint64_t& seed)
		: m_seed(seed)
	{
	}
	
	inline void Form64::reseed(const uint64_t& seed)
	{
		m_seed = seed;
	}

	inline std::vector<uint8_t> Form64::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	inline std::vector<uint8_t> Form64::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	inline void Form64::encode_in(uint8_t* data, const size_t len) const
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

	inline void Form64::decode_in(uint8_t* data, const size_t len) const
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

	inline void Form64::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	inline void Form64::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}


	inline Lunaris::Form32::Form32(const uint32_t& seed)
		: m_seed(seed)
	{
	}

	inline void Form32::reseed(const uint32_t& seed)
	{
		m_seed = seed;
	}

	inline std::vector<uint8_t> Form32::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	inline std::vector<uint8_t> Form32::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	inline void Form32::encode_in(uint8_t* data, const size_t len) const
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

	inline void Form32::decode_in(uint8_t* data, const size_t len) const
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

	inline void Form32::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	inline void Form32::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}


	inline bool RSA::is_prime(const uint64_t& test) const
	{
		if (test == 2 || test == 3)
			return true;
		if (test <= 1 || test % 2 == 0 || test % 3 == 0)
			return false;
		for (uint64_t i = 5; i * i <= test; i += 6) {
			if (test % i == 0 || test % (i + 2) == 0)
				return false;
		}
		return true;
	}

	inline uint64_t RSA::prime_b(uint64_t p, const bool noexc) const
	{
		while (!is_prime(--p) && p > 2);
		if (p <= 2) {
			if (noexc) return 0;
			throw std::runtime_error("Somehow primeb got invalid prime lesser than expected prime limit");
		}
		return p;
	}

	inline uint64_t RSA::find_prime_different_max(const std::function<uint64_t(void)> randomf, const uint64_t& lim, const uint64_t* arr, const size_t len)
	{
		const auto validate = [&](const uint64_t& n) {
			if (n < 2) return false;
			if (!arr) return true;
			for (const uint64_t* it = arr; it != (arr + len); ++it) if (*it == n) return false;
			return true;
		};

		uint64_t _t;

		while (1) {
			_t = prime_b(randomf() % lim);
			if (validate(_t)) return _t;
		}
		return 0;
	}

	inline void RSA::generate(const uint64_t& seed)
	{
		std::mt19937_64 gen(seed);
		std::uniform_int_distribution<uint64_t> dis;

		constexpr uint64_t maxx = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()); // limit for operations. 32 bit number * 32 bit number = 64 bit number, fits uint64_t.
		constexpr uint64_t less = static_cast<uint64_t>(std::numeric_limits<uint8_t>::max());  // minimum value trying for primes. Lowest prime possible should be bigger than this.
		constexpr uint64_t expc = static_cast<uint64_t>(std::numeric_limits<uint16_t>::max()); // primes must fit into 16 unfortunately, so n fits in 32 and operations fit in 64.


		uint64_t primes[3]{ 0 };
		while ((primes[0] * primes[1]) < expc) { // force 16 bit minimum for N!
			for (auto& i : primes) { i = find_prime_different_max([&] {return less + (dis(gen) % (expc - less - 1)); }, expc, primes, std::size(primes)); }
		}

		// has primes from here. Random primes, probably.

		n = static_cast<uint32_t>(primes[0] * primes[1]); // there's no DOUBT this is > than 16 bit and < than 32. This is A MUST because numbers later are % this, so this > 16 bit for functional purposes.
		if (n < expc) throw std::runtime_error("N must be more than 16 bit, but it isn't somehow. Please call for help!"); // I did this anyway (read line above kekw)
		e = static_cast<uint32_t>(primes[2]);

		const uint64_t phi = ((primes[0] - 1) * (primes[1] - 1));

		{
			uint64_t k = 1;
			uint64_t tmpp = 0;
			while (1) {
				if (((k * phi + 1) % e) == 0) {
					if (((tmpp = (k * phi + 1) / e) % phi) == 0) continue;

					if (tmpp > maxx) throw std::runtime_error("P value must not be bigger than 32 bits. Math failed internally :("); // the numbers * numbers % this should be <= 32 bit so next (this * this) won't overflow 64 bit
					p = static_cast<uint32_t>(tmpp);
					break;
				}
				if (++k == 0) throw std::runtime_error("Fatal error generating internal RSA");
			}
		}
	}

	inline uint64_t RSA::generate()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());
		const uint64_t gn = gen();
		generate(gn);
		return gn;
	}

	inline uint64_t RSA::get_public() const
	{
		return static_cast<uint64_t>(p) | (static_cast<uint64_t>(n) << static_cast<uint64_t>(32)); // combining two 32 into a 64 single number. That's a lot of fun!
	}

	inline RSA_device RSA::get_encrypt() const
	{
		return RSA_device(static_cast<uint64_t>(e) | (static_cast<uint64_t>(n) << static_cast<uint64_t>(32)), true);
	}

	inline RSA_device RSA::get_decrypt() const
	{
		return RSA_device(static_cast<uint64_t>(p) | (static_cast<uint64_t>(n) << static_cast<uint64_t>(32)), false);
	}

	inline uint32_t RSA_device::enc(const uint32_t& num) const
	{
		uint64_t fin = 1;
		uint64_t count = 0;
		uint64_t pw = static_cast<uint64_t>(key);
		const uint64_t rm = static_cast<uint64_t>(n);

		while (pw) {
			uint64_t currpw = (pw & (static_cast<uint64_t>(0b1) << count++));
			if (!currpw) continue;
			pw &= ~currpw;

			uint64_t numc = static_cast<uint64_t>(num);
			while (currpw >>= 1) {
				numc *= numc; // numc ^ 2
				numc %= rm; // result = (numc ^ 2) % rm;
			}
			fin *= numc;
			fin %= rm;
		}

		return static_cast<uint32_t>(fin);
	}

	inline RSA_device::RSA_device(const RSA_device& device)
		: n(device.n), key(device.key), m_16to32(device.m_16to32)
	{
	}

	inline RSA_device::RSA_device(const uint64_t& i, const bool enc)
		: key(static_cast<uint32_t>(i)), n(static_cast<uint32_t>(i >> static_cast<uint64_t>(32))), m_16to32(enc)
	{
	}

	inline std::vector<uint8_t> RSA_device::transform(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> end;

		if (m_16to32) {
			for (size_t p = 0; p < (len / sizeof(uint16_t)); ++p) {
				const uint16_t _n = (static_cast<uint32_t>(data[p*2]) | (static_cast<uint32_t>(data[p*2 + 1]) << 8)); // sequential order
				const uint32_t _f = enc(static_cast<uint32_t>(_n)); // use 16 bit number instead of 32 because n is no doubt > 16 bit, so no breaking here

				for (size_t k = 0; k < 4; ++k) end.push_back((_f >> (8 * k))); // sequential order
			}
			if (len % 2) { // last bit hanging
				const uint32_t _f = enc(static_cast<uint32_t>(data[len-1]));
				for (size_t k = 0; k < 4; ++k) end.push_back((_f >> (8 * k))); // sequential order
				end.push_back({}); // keeps % 2 == 1
			}
		}
		else {
			if ((len % 4) > 1) throw std::runtime_error("For decoding, it is expected multiple of 4 or that +1!");

			for (size_t p = 0; p < (len / sizeof(uint32_t)); ++p) {
				const uint32_t _n = (static_cast<uint32_t>(data[p*4]) | (static_cast<uint32_t>(data[p*4 + 1]) << 8) | (static_cast<uint32_t>(data[p*4 + 2]) << 16) | (static_cast<uint32_t>(data[p*4 + 3]) << 24)); // combine 4 (8 * 4 = 32 bit)
				const uint16_t _f = static_cast<uint16_t>(enc(_n)); // expects 16 bit number here because source MUST be that.
				end.push_back(static_cast<uint8_t>(_f));
				end.push_back(static_cast<uint8_t>(_f >> 8));
			}
			if (len % 4) end.pop_back();
		}

		return end;
	}

	inline std::vector<uint8_t> RSA_device::transform(const std::vector<uint8_t>& vec) const
	{
		return transform(vec.data(), vec.size());
	}

	inline void RSA_device::transform_in(std::vector<uint8_t>& vec) const
	{
		vec = transform(vec);
	}

	inline uint64_t RSA_device::code() const
	{
		return static_cast<uint64_t>(key) | (static_cast<uint64_t>(n) << static_cast<uint64_t>(32));
	}

	inline Lunaris::RSA_plus::RSA_plus()
		: Form64(0) // This is not random because I don't want people thinking this is broken without any proper config
	{
	}

	inline void RSA_plus::as_decoder(const uint64_t& pubseed)
	{
		m_is_enc = false;
		m_pub_cpy = pubseed;
		crypt = std::make_unique<RSA_device>(pubseed, false); // decrypt
		this->Form64::operator=(Form64(pubseed));
	}

	inline void RSA_plus::as_encoder(const uint64_t& seed)
	{
		m_is_enc = true;
		RSA fun;
		fun.generate(seed);
		crypt = std::make_unique<RSA_device>(fun.get_encrypt());
		m_pub_cpy = fun.get_public();
		this->Form64::operator=(Form64(m_pub_cpy)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	inline void RSA_plus::as_encoder()
	{
		m_is_enc = true;
		RSA fun;
		fun.generate();
		crypt = std::make_unique<RSA_device>(fun.get_encrypt());
		m_pub_cpy = fun.get_public();
		this->Form64::operator=(Form64(m_pub_cpy)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	inline uint64_t RSA_plus::get_public() const
	{
		return m_pub_cpy;
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
				auto venc = this->Form64::encode(data, len);
				push.insert(push.end(), std::make_move_iterator(venc.begin()), std::make_move_iterator(venc.end()));
				crypt->transform_in(push);
			}
			else { // inverse order
				push = std::vector<uint8_t>(data, data + len);
				crypt->transform_in(push);
				push = this->Form64::decode(push.data(), push.size());
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

	inline RSA_plus make_encrypt_auto()
	{
		RSA_plus set;
		set.as_encoder();
		return set;
	}

	inline RSA_plus make_decrypt_auto(const uint64_t& public_key)
	{
		RSA_plus set;
		set.as_decoder(public_key);
		return set;
	}
}