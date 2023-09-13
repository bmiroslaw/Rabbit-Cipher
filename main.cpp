#include <iostream>
#include "RabbitCipher_lib/Rabbit.h"
#include "RabbitCipher_lib/utils.h"

//Documentation https://www.rfc-editor.org/rfc/rfc4503

int main() {
    Rabbit rabbit;

    std::array<uint8_t, 16> key{0x01, 0x03, 0x05, 0x07, 0x09, 0x11, 0x13, 0x15, 0x17, 0x19, 0x21, 0x23, 0x25, 0x27, 0x29, 0x31};
    std::array<uint8_t, 8> iv{0xA1, 0xB2, 0xA3, 0xC4, 0xA5, 0xD6, 0xA7, 0xE8};
    rabbit.initialiseCipher(key); //initialising the cipher

    std::string message = "Hello World!"; //message to be encrypted
    std::vector<uint8_t> toEncrypt = {stringToByteVector(message)}; //converting to a vector of bytes (unit_8)

    std::cout << message << std::endl; //printing the original message
    rabbit.encryptMessage(iv,toEncrypt); //encrypting the message
    std::cout << byteVectorToString(toEncrypt) << std::endl; //printing the encrypted version of the message
    rabbit.decryptMessage(iv, toEncrypt); //decrypting the message
    std::cout << byteVectorToString(toEncrypt) << std::endl; //printing the decrypted version of the message

    return 0;
}
