#pragma once
#include <string>
#include <vector>

//Converts a standard string to a vector of bytes (uint8_t)
std::vector<uint8_t> stringToByteVector(const std::string& str);
//Converts a vector of bytes (uint8_t) to a standard string
std::string byteVectorToString(const std::vector<uint8_t>& vector);
//Converts a vector of bytes (uint8_t) to a hexadecimal string representation
std::string vectorToHexString(const std::vector<uint8_t>& vector);
