#include "testHelper.h"
#include <iomanip>
#include <sstream>
#include <__random/random_device.h>
#include <random>

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

// Creates a random device for seeding the random number generator.
std::random_device rd;

// Mersenne Twister random number generator, seeded with the random device.
std::mt19937 randomValue(rd());

/**
 * Generates a random byte vector of a given length.
 *
 * @param length The desired length of the byte vector.
 * @return A vector of random bytes of the specified length.
 */
std::vector<uint8_t> getRandomBytes(int length) {
    std::vector<uint8_t> data(length);
    std::generate(data.begin(), data.end(), []() { return static_cast<uint8_t>(rand()); });
    return data;
}

/**
 * Generates a random message as a byte vector with a length between the specified minimum and maximum lengths.
 *
 * @param minLength The minimum possible length of the random message.
 * @param maxLength The maximum possible length of the random message.
 * @return A random byte vector message.
 */
std::vector<uint8_t> getRandomMessage(int minLength, int maxLength) {
    std::uniform_int_distribution<int> dist(minLength, maxLength);
    int length = dist(randomValue);
    return getRandomBytes(length);
}

/**
 * Generates a random 16-byte key.
 *
 * @return A 16-byte array filled with random data.
 */
std::array<uint8_t, 16> getRandomKey() {
    std::array<uint8_t, 16> data{};
    std::generate(data.begin(), data.end(), []() { return static_cast<uint8_t>(rand()); });
    return data;
}

/**
 * Generates a random 8-byte Initialization Vector (IV).
 *
 * @return An 8-byte array filled with random data.
 */
std::array<uint8_t, 8> getRandomIV() {
    std::array<uint8_t, 8> data{};
    std::generate(data.begin(), data.end(), []() { return static_cast<uint8_t>(rand()); });
    return data;
}

/**
 * Converts a space-separated hex string to a vector of bytes.
 * 
 * @param hex The input hex string.
 * @return A vector of bytes representing the hex string.
 */
std::vector<uint8_t> hexStringToByteVector(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 3) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}
