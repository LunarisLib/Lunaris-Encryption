#pragma once

#include <vector>
#include <cstdint>
#include <random>

inline std::vector<uint8_t> generate_random_data(size_t size)
{
    std::vector<uint8_t> str(size, 0);
    std::random_device rd; 
    std::mt19937 gen(rd());

    std::uniform_int_distribution<> distrib(0, 127);

    for(auto& ch : str) {
        ch = distrib(gen);
    }

    return str;
}