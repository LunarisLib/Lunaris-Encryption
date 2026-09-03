#include <iostream>

#include <Lunaris/encryption.h>

#include "common.h"

using namespace Lunaris::Encryption;

int main() {
    const uint64_t fixed_seed = 123456;
    RSA rsa;
    rsa.generate(fixed_seed);

    RSADevice enc_device = rsa.get_encrypt();
    RSADevice dec_device = rsa.get_decrypt();

    const std::vector<uint8_t> random_strings[] = {
        generate_random_data(20),
        generate_random_data(50),
        generate_random_data(200)
    };

    std::vector<std::vector<uint8_t>> encoded, decoded;

    for(const auto& i : random_strings) {
        auto enc = enc_device.transform(i.data(), i.size());
        encoded.push_back(std::move(enc));
    }

    for(const auto& i : encoded) {
        auto dec = dec_device.transform(i.data(), i.size());
        decoded.push_back(std::move(dec));
    }

    for(size_t p = 0; p < std::size(random_strings); ++p) {
        if (random_strings[p] != decoded[p]) {
            std::cout << "Failed on data #" << p << std::endl;
            std::cout << "IN: ";
            for(const auto& ch : random_strings[p]) std::putchar(ch);
            std::cout << "\nOUT: ";
            for(const auto& ch : decoded[p]) std::putchar(ch);
            std::cout << "\n";

            return 1;
        }
    }

    return 0;
}