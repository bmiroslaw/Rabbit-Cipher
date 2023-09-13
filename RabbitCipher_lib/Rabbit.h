#ifndef RABBITCIPHER_RABBIT_H
#define RABBITCIPHER_RABBIT_H

#include <cstdint>
#include <string>
#include <array>
#include <sstream>
#include <iomanip>

//Documentation https://www.rfc-editor.org/rfc/rfc4503

class Rabbit {
private:
    static const uint64_t WORD_SIZE = 0x100000000L;
    static const uint32_t A[8];
    static const int subKeyArrayLength = 8;
    std::array<uint32_t, 8> X = {}, C = {}, G = {};
    std::array<uint8_t, 16> key{}, S{};
    std::optional<std::array<uint8_t, 8>> prevIV;  // Starts uninitialized
    uint64_t b{};

    //Function g implementation per the point 2.6 Next-State Function
    static uint32_t g(uint32_t u, uint32_t v);
    //Left bit rotation
    static uint32_t leftRotation(uint32_t x, uint32_t n);
    //Extraction scheme per the point 2.7 Extraction Scheme
    void extraction();


public:
    // Constructor
    Rabbit() = default;

    //Initialising the Cipher per the 2.3 Key Setup Scheme
    void initialiseCipher(const std::array<uint8_t, 16>& newKey);
    //Initialising the IV per the 2.4 IV Setup Scheme
    void initialiseIV(const std::array<uint8_t, 8>& IV);
    //Updating the counter system per the 2.5 Counter System
    void counterUpdate();
    //Next-State function per the point 2.6 Next-State Function
    void nextState();
    //Encryption per point 2.8 Encryption/Decryption
    void encrypt(std::vector<uint8_t>& block);
    //Decryption per point 2.8 Encryption/Decryption
    void decrypt(std::vector<uint8_t>& block);
    //Message encryption
    void encryptMessage(const std::array<uint8_t, 8>& iv, std::vector<uint8_t>& message);
    //Message decryption
    void decryptMessage(const std::array<uint8_t, 8>& iv, std::vector<uint8_t>& message);
    //Returns the state of the cipher in hexadecimal
    std::string getStateString();
};


#endif //RABBITCIPHER_RABBIT_H
