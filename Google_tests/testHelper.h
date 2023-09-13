#pragma once
#include <string>
#include <vector>

std::string vectorToHexString(const std::vector<uint8_t>& vector);
std::vector<uint8_t> hexStringToByteVector(const std::string& hex);
std::vector<uint8_t> getRandomBytes(int length);
std::vector<uint8_t> getRandomMessage(int minLength, int maxLength);
std::array<uint8_t, 16> getRandomKey();
std::array<uint8_t, 8> getRandomIV();