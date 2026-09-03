#include <Lunaris/Encryption/form.h>

#include <random>

namespace Lunaris {
namespace Encryption {

	Form32::Form32(const uint32_t& seed)
		: m_seed(seed)
	{
	}

	void Form32::reseed(const uint32_t& seed)
	{
		m_seed = seed;
	}

	std::vector<uint8_t> Form32::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	std::vector<uint8_t> Form32::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	void Form32::encode_in(uint8_t* data, const size_t len) const
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

	void Form32::decode_in(uint8_t* data, const size_t len) const
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

	void Form32::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	void Form32::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}


	Form64::Form64(const uint64_t& seed)
		: m_seed(seed)
	{
	}
	
	void Form64::reseed(const uint64_t& seed)
	{
		m_seed = seed;
	}

	std::vector<uint8_t> Form64::encode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		encode_in(vec.data(), vec.size());
		return vec;
	}

	std::vector<uint8_t> Form64::decode(const uint8_t* data, const size_t len) const
	{
		std::vector<uint8_t> vec(data, data + len);
		decode_in(vec.data(), vec.size());
		return vec;
	}

	void Form64::encode_in(uint8_t* data, const size_t len) const
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

	void Form64::decode_in(uint8_t* data, const size_t len) const
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

	void Form64::encode_in(std::vector<uint8_t>& vec) const
	{
		encode_in(vec.data(), vec.size());
	}

	void Form64::decode_in(std::vector<uint8_t>& vec) const
	{
		decode_in(vec.data(), vec.size());
	}

} // Encryption
} // Lunaris