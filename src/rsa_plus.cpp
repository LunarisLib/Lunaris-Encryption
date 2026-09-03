#include <Lunaris/Encryption/rsa_plus.h>

namespace Lunaris {
namespace Encryption {

	RSAPlus::RSAPlus()
		: Form64(0) // This is not random because I don't want people thinking this is broken without any proper config
	{
	}

	void RSAPlus::as_decoder(const uint64_t& pubkey, const uint64_t& modkey)
	{
		m_is_enc = false;
		m_pub_cpy_p = pubkey;
		m_pub_cpy_m = modkey;
		crypt = std::make_unique<RSADevice>(pubkey, modkey, false); // decrypt
		this->Form64::operator=(Form64(m_pub_cpy_p));
	}

	void RSAPlus::as_decoder(const RSA_keys<uint64_t>& keys)
	{
		as_decoder(keys.key, keys.mod);
	}

	void RSAPlus::as_encoder(const uint64_t& seed)
	{
		m_is_enc = true;
		RSA fun;
		fun.generate(seed);
		crypt = std::make_unique<RSADevice>(fun.get_encrypt());
		m_pub_cpy_p = fun.get_key();
		m_pub_cpy_m = fun.get_mod();
		this->Form64::operator=(Form64(m_pub_cpy_p)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	void RSAPlus::as_encoder()
	{
		m_is_enc = true;
		RSA fun;
		fun.generate();
		crypt = std::make_unique<RSADevice>(fun.get_encrypt());
		m_pub_cpy_p = fun.get_key();
		m_pub_cpy_m = fun.get_mod();
		this->Form64::operator=(Form64(m_pub_cpy_p)); // same as fun.get_decrypt().code(), same as get_public() current value.
	}

	uint64_t RSAPlus::get_key() const
	{
		return m_pub_cpy_p;
	}

	uint64_t RSAPlus::get_mod() const
	{
		return m_pub_cpy_m;
	}

	RSA_keys<uint64_t> RSAPlus::get_combo() const
	{
		return RSA_keys<uint64_t>{ m_pub_cpy_p, m_pub_cpy_m };
	}

	bool RSAPlus::is_encoder() const
	{
		return m_is_enc;
	}

	bool RSAPlus::transform(const uint8_t* data, const size_t len, std::vector<uint8_t>& push, const bool exceptions) const
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

	bool RSAPlus::transform(std::vector<uint8_t>& vec, const bool exceptions) const
	{
		std::vector<uint8_t> targ;
		const bool gud = transform(vec.data(), vec.size(), targ, exceptions);
		vec = std::move(targ);
		return gud;
	}

	RSAPlus::operator RSA_keys<uint64_t>() const
	{
		return get_combo();
	}

	RSAPlus make_encrypt_auto()
	{
		RSAPlus set;
		set.as_encoder();
		return set;
	}

	RSAPlus make_decrypt_auto(const RSA_keys<uint64_t>& keys)
	{
		RSAPlus set;
		set.as_decoder(keys);
		return set;
	}

} // Encryption
} // Lunaris