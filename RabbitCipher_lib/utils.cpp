#include <iomanip>
#include <sstream>
#include "utils.h"

/**
 * Converts a standard string to a vector of bytes (uint8_t).
 *
 * @param str The input string to be converted.
 * @return A vector of bytes representing the input string.
 */
std::vector<uint8_t> stringToByteVector(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

/**
 * Converts a vector of bytes (uint8_t) to a standard string.
 *
 * @param vector The input vector of bytes to be converted.
 * @return A string representing the byte vector.
 */
std::string byteVectorToString(const std::vector<uint8_t>& vector) {
    return std::string(vector.begin(), vector.end());
}

/**
 * Converts a vector of bytes (uint8_t) to a hexadecimal string representation.
 * Each byte will be represented by its 2-character hexadecimal representation
 * followed by a space.
 *
 * @param vector The input vector of bytes to be converted.
 * @return A string with the hexadecimal representation of the byte vector.
 */
std::string vectorToHexString(const std::vector<uint8_t>& vector){
    std::ostringstream output;
    for(const auto& byte : vector) {
        output << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(byte) << " ";
    }
    return output.str();
}
