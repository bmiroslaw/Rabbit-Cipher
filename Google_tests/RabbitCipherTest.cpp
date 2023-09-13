#include "gtest/gtest.h"
#include "Rabbit.h"
#include "testHelper.h"

Rabbit rabbit;

// Test case to check initialization with a zero key
TEST(InitialisationTests, ZeroKeyInitTest){
    // Initialize the cipher with an all-zero key
    rabbit.initialiseCipher(std::array<uint8_t, 16>{});
    // Check if the cipher's state matches the expected state for the zero key
    EXPECT_EQ(rabbit.getStateString(), "6E9E1D18 F5A54E5C F8FD49C6 9B94253F DCD14A79 1F32FA20 D2055921 53F371D0 E802074F 5206296D 01486DF2 67203CE4 23AACE55 26E87A8F CC2E04F2 D6A0F672 1");
}

// Test case to check initialization with multiple predefined keys
TEST(InitialisationTests, ExtendedInitTest){
    // Define and test a specific key
    std::array<uint8_t, 16> key{0xAC,0xC3,0x51,0xDC,0xF1,0x62,0xFC,0x3B,0xFE,0x36,0x3D, 0x2E, 0x29, 0x13, 0x28,0x91};
    rabbit.initialiseCipher(key);
    EXPECT_EQ(
            rabbit.getStateString(),
            "1D059312 BDDC3E45 F440927D 50CBB553 36709423 0B6F0711 3ADA3A7B EB9800C8 5DA1EF57 22E9312F DCACFF87 9B5784FA 0DE43C8C BC5679B8 63841B4C 8E9623AA 0"
    );

    // Redefine the key and test again
    key = {0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
           0x78, 0x69,0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};
    rabbit.initialiseCipher(key);
    EXPECT_EQ(
            rabbit.getStateString(),
            "BD37DC44 416F631E D917BCF9 F37D7FDC D9E41C4F 46BA596C 5D0B7468 58EBBE16 47AF84DF 57BD206D 5D82379A E48208BB 92124B5B 5FC8010E 03906832 AF2ECAE1 1"
    );

    // Redefine the key and test again
    key = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    rabbit.initialiseCipher(key);

    EXPECT_EQ(
            rabbit.getStateString(),
            "854CDD00 DB30DFAD 516CEDC8 E7848FA2 A6F6C0C6 0C8B08D2 5156270D 5E47E0F9 9C2C91FD 55CAD58A 840613D9 629BB3C2 DE0F025A 0C62E97B 6FB2B8F5 AAB16EFE 1"
    );
}

// Test case to check initialization with a zero key and a zero IV
TEST(InitialisationTests, SingleIVInitTest) {
    // Initialize cipher with zero key and IV
    rabbit.initialiseCipher(std::array<uint8_t, 16> {});
    rabbit.initialiseIV(std::array<uint8_t, 8>{});

    // Check if cipher state matches expected state for zero key and IV
    EXPECT_EQ(
            rabbit.getStateString(),
            "825CE07B 12633711 A0FE547B 75CF0E64 92EF9246 89E633C7 2C7442FF 2C6B4782 1CD55487 9F3AFCBB D495A2C5 9BF38A18 70DFA1A2 FA35AF62 01015226 23D5C9C0 1"
    );
}

// Test case to check re-initialization with different IV values
TEST(InitialisationTests, IVReInitTest) {
    // Initialize cipher with zero key
    rabbit.initialiseCipher(std::array<uint8_t, 16>{});

    std::array<uint8_t, 8> t1{0xFA, 0x3E, 0x32, 0xCD, 0xA4, 0x02, 0xFE, 0x01};
    std::array<uint8_t, 8> t2{0xAF, 0xB7, 0xCB, 0x00, 0xA0, 0x4C, 0xDA, 0x19};
    std::string ivOneState = "143DAB82 15D8A3E8 4C6E3CA4 C8505533 CE271207 6946D0BF C5D4A680 AC7D4B95 5A0386ED A12DB7AC D403A429 9A574F52 3BCDC3FC FA63EC91 02A3538A 21399BD6 1";
    std::string ivTwoState = "4D551582 C95BFC66 51D4DFF1 AEB269D5 9AB5B427 C4A273F8 98ED98CC 825B40F2 1D9CFE18 9910FCF4 EBDF5625 6053D87F 70964D47 127FAF17 0AC79587 E735152B 0";

    // Initialize with one IV and check its state
    rabbit.initialiseIV(t1);
    EXPECT_EQ(
            rabbit.getStateString(),
            ivOneState
    );

    // Initialize with another IV and check its state
    rabbit.initialiseIV(t2);
    EXPECT_EQ(
            rabbit.getStateString(),
            ivTwoState
    );

    // Reinitialize with the first IV and check its state again
    rabbit.initialiseIV(t1);
    EXPECT_EQ(
            rabbit.getStateString(),
            ivOneState
    );
}

// Test case to check initialization using multiple keys and IVs
TEST(InitialisationTests, MultiKeyInitTest) {
    // Predefine multiple test keys and IVs
    std::array<std::array<uint8_t, 16>, 3> testKeys = {{
                                                               { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
                                                               { 0xAC, 0xC3, 0x51, 0xDC, 0xF1, 0x62, 0xFC, 0x3B, 0xFE, 0x36, 0x3D, 0x2E, 0x29, 0x13, 0x28, 0x91 },
                                                               { 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F }
                                                       }};

    std::array<std::array<uint8_t, 8>, 2> testIVs = {{
                                                             std::array<uint8_t, 8>{ 1, 0, 0, 0, 0, 0, 0, 0 },
                                                             std::array<uint8_t, 8>{ 0x0E, 0xB0, 0x04, 0xD0, 0x01, 0x09, 0xA0, 0xF0 }
                                                     }};

    std::array<std::string, 6> expectedOutputs =  {
            "541B47F9 FA068DEC BEE22902 1A246E1F 253BB501 8081C9CD 4A792514 E370E49D D0FFDF34 A2FFA8D7 575348AC 976F00F8 2B43D5A8 DFB01E4F A4860629 F7E6424C 0",
            "C4417724 B34450D3 E69110F5 38C5D75F FE252E28 9DCC0944 97B88C69 77BAD4E8 92753C8D 701E047C AFFA345A D02AD230 5B190FDA 8FA3AE8B 98576881 DBCAF6F8 0",
            "3533BD4F 1DA4A544 E17051C9 E05E5F0A 5B348A16 A2EC7854 97D83BCF 87F90CD5 7C82D216 A4F1F3BA 30CF6C6D 195555EF DF471EA8 331535E1 3863B567 FC639E2D 0",
            "C6D53C0A 4B6DF2FE A4F7768C BD045176 00479F86 D9385DDF D39D63D3 672C6FBC 80FB6F2B F29ED8DB 47F34FAB A06D5101 5B4085A1 D00F6E52 D3E5FF29 F0E5B23D 0",
            "CF5A605A C70909B4 3FAB8C42 C2322BE2 13DF34DF E04C7AE1 B4619B55 1276945D C278AC90 1F7EB478 FF5A2B5A C7298228 2B155FCF 2043DE90 C7F75F82 D4CC66F1 0",
            "6AC4A03D 84040A14 F3024C5F C074BC67 77B24909 0839C0C7 37E53052 6F4D3A68 CC7E8209 F452C3B6 806F736E 225705EA 8F4BCEA3 82B605DD 2803AE68 F3644E3D 0",
    };

    rabbit.initialiseCipher(std::array<uint8_t, 16>{});

    // Loop through all key and IV combinations, testing each one
    for (int i = 0; i < 3 * 2; i++) {
        int ki = i % 3;
        int ivi = i / 3;
        rabbit.initialiseCipher(testKeys[ki]);
        rabbit.initialiseIV(testIVs[ivi]);

        EXPECT_EQ(
                rabbit.getStateString(),
                expectedOutputs[i]
        );
    }
}

// Testing the encryption of a single block.
TEST(EncryptionTests, EncryptSingleBlockTest) {
    // Initialise the cipher with a 16-byte key.
    rabbit.initialiseCipher(std::array<uint8_t, 16>  { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
    // Initialise the IV (Initialization Vector) with an 8-byte value.
    rabbit.initialiseIV(std::array<uint8_t, 8> { 0xFF, 0xFE,0xFD,0xFC,0xFB,0xFA,0xEF,0xEE });

    // The plaintext to be encrypted.
    std::vector<uint8_t> plaintext = { static_cast<uint8_t>(-93), 1, static_cast<uint8_t>(-26), static_cast<uint8_t>(-4),
                                       static_cast<uint8_t>(-64), 2, static_cast<uint8_t>(-23), 122,
                                       static_cast<uint8_t>(-44), static_cast<uint8_t>(-72), 8, 9, 31, 100,
                                       static_cast<uint8_t>(-80), 115 };

    // Expected output after the plaintext is encrypted.
    std::vector<uint8_t> expectedBlock = { 65, static_cast<uint8_t>(-60), 51, static_cast<uint8_t>(-40),
                                           static_cast<uint8_t>(-15), static_cast<uint8_t>(-72), static_cast<uint8_t>(-66), 55,
                                           static_cast<uint8_t>(-75), static_cast<uint8_t>(-62), static_cast<uint8_t>(-12),
                                           static_cast<uint8_t>(-40), 102, 19, 63, static_cast<uint8_t>(-58) };

    // Create a copy of the plaintext, which will be encrypted.
    std::vector<uint8_t> encryptedBlock = plaintext;
    // Encrypt the block.
    rabbit.encrypt(encryptedBlock);
    // Assert that the encrypted block matches the expected output.
    EXPECT_EQ(
            encryptedBlock,
            expectedBlock
    );
}

// Testing the encryption of multiple blocks.
TEST(EncryptionTests, EncryptMultipleBlockTest) {
    // Initialise the cipher and IV.
    rabbit.initialiseCipher(std::array<uint8_t, 16> { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
    rabbit.initialiseIV(std::array<uint8_t, 8>{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xEF, 0xEE });

    // The plaintext to be encrypted.
    std::vector<uint8_t> plaintext = { static_cast<uint8_t>(-93), 1, static_cast<uint8_t>(-26), static_cast<uint8_t>(-4),
                                         static_cast<uint8_t>(-64), 2, static_cast<uint8_t>(-23), 122,
                                         static_cast<uint8_t>(-44), static_cast<uint8_t>(-72), 8, 9, 31, 100,
                                         static_cast<uint8_t>(-80), 115 };

    // Expected output after the plaintext is encrypted.
    std::vector<uint8_t> expectedBlock = { static_cast<uint8_t>(-118), 44, static_cast<uint8_t>(-13), 62,
                                              static_cast<uint8_t>(-14), 101, 39, static_cast<uint8_t>(-5),
                                              static_cast<uint8_t>(-50), static_cast<uint8_t>(-39), static_cast<uint8_t>(-19),
                                              68, 40, static_cast<uint8_t>(-50), static_cast<uint8_t>(-34), 88 };

    // Create a copy of the plaintext, which will be encrypted.
    std::vector<uint8_t> encryptedBlock(plaintext);

    // Encrypt the block multiple times.
    for (int i = 0; i < 10; i++) {
        rabbit.encrypt(encryptedBlock);
    }

    // Assert that the final encrypted block matches the expected output.
    EXPECT_EQ(
            encryptedBlock,
            expectedBlock
    );
}

// Testing the decryption of a single block.
TEST(DecryptionTests, DecryptSingleBlockTest) {
    // Initialise the cipher and IV.
    std::array<uint8_t, 16> key = { 1, 5, 8, 2, 0, 9, 3, 6, 3, 7, 8, 2, 6, 2, 9, 0 };
    std::array<uint8_t, 8> iv = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xEF, 0xEE };

    rabbit.initialiseCipher(key);
    rabbit.initialiseIV(iv);

    // The ciphertext to be decrypted.
    std::vector<uint8_t> ciphertext = { 65, static_cast<uint8_t>(-60), 51, static_cast<uint8_t>(-40),
                                           static_cast<uint8_t>(-15), static_cast<uint8_t>(-72), static_cast<uint8_t>(-66), 55,
                                           static_cast<uint8_t>(-75), static_cast<uint8_t>(-62), static_cast<uint8_t>(-12),
                                           static_cast<uint8_t>(-40), 102, 19, 63, static_cast<uint8_t>(-58) };

    // Expected output after the ciphertext is decrypted.
    std::vector<uint8_t> expectedBlock = { 55, static_cast<uint8_t>(-7), 125, static_cast<uint8_t>(-12),
                                              static_cast<uint8_t>(-88), static_cast<uint8_t>(-117), 1, static_cast<uint8_t>(-15),
                                              static_cast<uint8_t>(-95), static_cast<uint8_t>(-34), 95, 84,
                                              static_cast<uint8_t>(-60), static_cast<uint8_t>(-8), static_cast<uint8_t>(-97),
                                              static_cast<uint8_t>(-44) };

    std::vector<uint8_t> decryptedBlock = ciphertext;

    // Decrypt the block.
    rabbit.decrypt(decryptedBlock);

    // Assert that the decrypted block matches the expected output.
    EXPECT_EQ(
            decryptedBlock,
            expectedBlock
    );
}

// Testing the decryption of multiple blocks.
TEST(DecryptionTests, DecryptMultipleBlockTest) {
    // Initialise the cipher and IV.
    std::array<uint8_t, 16> key = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    rabbit.initialiseCipher(key);
    std::array<uint8_t, 8> iv = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xEF, 0xEE };
    rabbit.initialiseIV(iv);

    // The ciphertext to be decrypted.
    std::vector<uint8_t> ciphertext = { 0xA0, 31, 0xF6, 61, 7, 0xD9, 0xAA, 65, 0xAE, 0xEC, 0xE5, 113, 61, 0xC8, 108, 0xC3 };
    // Expected output after the ciphertext is decrypted.
    std::vector<uint8_t> expectedBlock = { 0x89, 50, 0xE3, 0xFF, 53, 0xBE, 100, 0xC0, 0xB4, 0x8D, 0x00, 60, 10, 98, 2, 0xE8 };
    std::vector<uint8_t> decryptedBlock = ciphertext;

    // Decrypt the block multiple times.
    for (int i = 0; i < 10; i++) {
        rabbit.encrypt(decryptedBlock);
    }

    // Assert that the final decrypted block matches the expected output.
    EXPECT_EQ(
            decryptedBlock,
            expectedBlock
    );
}

// Testing the encryption of a single message block.
TEST(MessageEncryptionTests, SingleBlockSingleMessageTest) {
    // Define key and iv
    std::array<uint8_t, 16> key = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    std::array<uint8_t, 8> iv = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xEF, 0xEE};

    // Initialise the cipher.
    rabbit.initialiseCipher(key);

    // The plaintext message to be encrypted.
    std::vector<uint8_t> plaintext = { static_cast<uint8_t>(-93), 1,
                                       static_cast<uint8_t>(-26),  static_cast<uint8_t>(-4),
                                       static_cast<uint8_t>(-64), 2,  static_cast<uint8_t>(-23),
                                       122,  static_cast<uint8_t>(-44), static_cast<uint8_t>(-72), 8,
                                       9, 31, 100,  static_cast<uint8_t>(-80), 115};

    // Expected output after the message is encrypted.
    std::vector<uint8_t> expectedBlock = {65,  static_cast<uint8_t>(-60), 51,
                                             static_cast<uint8_t>(-40),  static_cast<uint8_t>(-15),
                                             static_cast<uint8_t>(-72), static_cast<uint8_t>(-66),
                                             55, static_cast<uint8_t>(-75), static_cast<uint8_t>(-62),
                                             static_cast<uint8_t>(-12), static_cast<uint8_t>(-40),
                                             102, 19, 63, static_cast<uint8_t>(-58)};

    std::vector<uint8_t> encryptedBlock = plaintext;

    // Encrypt the message with the IV.
    rabbit.encryptMessage(iv, encryptedBlock);

    // Assert that the encrypted message matches the expected output.
    EXPECT_EQ(
            encryptedBlock,
            expectedBlock
    );
}

// Testing the encryption of single block messages with multiple IVs.
TEST(MessageEncryptionTests, SingleBlockMultiMessageTest) {
    // Initialise the cipher.
    std::array<uint8_t, 16> key = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    rabbit.initialiseCipher(key);

    // Define ivs
    std::array<uint8_t, 8> ivM1 = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xEF, 0xEE};
    std::array<uint8_t, 8> ivM2 = {4, 3, 2, 1, 9, 8, 7, 6};

    // The plaintext message to be encrypted.
    std::vector<uint8_t> plaintext = {static_cast<uint8_t>(-93), 1, static_cast<uint8_t>(-26), static_cast<uint8_t>(-4),
                                         static_cast<uint8_t>(-64), 2, static_cast<uint8_t>(-23), 122,
                                         static_cast<uint8_t>(-44), static_cast<uint8_t>(-72), 8, 9, 31, 100,
                                         static_cast<uint8_t>(-80), 115};

    // Expected output for each encrypted message.
    std::vector<uint8_t> expectedBlockM1 = {65, static_cast<uint8_t>(-60), 51, static_cast<uint8_t>(-40),
                                               static_cast<uint8_t>(-15), static_cast<uint8_t>(-72), static_cast<uint8_t>(-66),
                                               55, static_cast<uint8_t>(-75), static_cast<uint8_t>(-62),
                                               static_cast<uint8_t>(-12), static_cast<uint8_t>(-40), 102, 19, 63,
                                               static_cast<uint8_t>(-58)};

    std::vector<uint8_t> expectedBlockM2 = {18, 47, 82, static_cast<uint8_t>(-6), 71, static_cast<uint8_t>(-49),
                                               static_cast<uint8_t>(-7), static_cast<uint8_t>(-13), 61, 69,
                                               static_cast<uint8_t>(-22), 43, static_cast<uint8_t>(-86),
                                               static_cast<uint8_t>(-118), 63, static_cast<uint8_t>(-10)};

    std::vector<uint8_t> encryptedBlockM1 = plaintext;
    std::vector<uint8_t> encryptedBlockM2 = plaintext;

    // Encrypt the messages with different IVs.
    rabbit.encryptMessage(ivM1, encryptedBlockM1);
    rabbit.encryptMessage(ivM2, encryptedBlockM2);


    // Assert that the encrypted messages match their respective expected outputs.
    EXPECT_EQ(
            encryptedBlockM1,
            expectedBlockM1
    );
    EXPECT_EQ(
            encryptedBlockM2,
            expectedBlockM2
    );
}

// Testing the encryption of multiple message blocks.
TEST(MessageEncryptionTests, MultiBlockSingleMessageTest){
    std::array<uint8_t, 16> key{0x01, 0x03, 0x05, 0x07, 0x09, 0x11, 0x13, 0x15, 0x17, 0x19, 0x21, 0x23, 0x25, 0x27, 0x29, 0x31};
    std::array<uint8_t, 8> iv{0xA1, 0xB2, 0xA3, 0xC4, 0xA5, 0xD6, 0xA7, 0xE8};

    // Initialise the cipher.
    rabbit.initialiseCipher(key);
    rabbit.initialiseIV(iv);

    // Convert the input and expected output messages from hex string to byte vector format
    std::vector<uint8_t> message = hexStringToByteVector("7D 03 B5 70 37 49 64 C4 7D 14 D7 02 22 91 38 B9 81 98 53 ED B5 13 15 AF 7D 86 52 A5 1A 97 78 40 63 AA 3A 6E 2C 39 52 54 74 7E AB CE A7 66 55 21 A1 A7 10 02 38 53 7E E1 9B AA F7 7C E2 9A 63 C2");
    std::vector<uint8_t> expectedMessage = hexStringToByteVector("70 9E 64 77 B1 ED A3 9D 8D CF 44 5B B6 6E A8 9F 19 6C EA 50 11 1F 89 F5 64 7A 5B 60 C5 EF 9C F4 56 2F 57 62 43 BC 45 D8 C3 77 A7 BC 60 56 D4 98 1D 8F D4 08 C0 2D 29 6A 6C C4 EB 9D F8 CD 34 69");

    std::vector<uint8_t> encryptedBlock = message;

    // Encrypt the message
    rabbit.encryptMessage(iv, encryptedBlock);

    // Assert that the encrypted message matches the expected output.
    EXPECT_EQ(
            encryptedBlock,
            expectedMessage
  );
}

// Testing the encryption of multiple messages on multiple blocks.
TEST(MessageEncryptionTests, MultiBlockMultiMessageTest) {
    // Initialise the key and ivs
    std::array<uint8_t, 16> key{0x01, 0x03, 0x05, 0x07, 0x09, 0x11, 0x13, 0x15, 0x17, 0x19, 0x21, 0x23, 0x25, 0x27, 0x29, 0x31};
    std::array<std::array<uint8_t, 8>, 3> ivs = {{
            {0xA1, 0xB2, 0xA3, 0xC4, 0xA5, 0xD6, 0xA7, 0xE8},
            {0xFA, 0x3D, 0xDE, 0x9B, 0xCA, 0x8A, 0xE4, 0x12},
    }};

    // Initialise the messages to be encrypted and their expected output
    std::array<std::vector<uint8_t>, 2> messages = {{
            hexStringToByteVector("A9 10 E1 3E 1F F7 9C 21 48 A5 08 BB 87 D7 F1 F4 61 11 DF 7C 85 73 90 FF 75 D1 62 45 20 D5 F7 6D"),
            hexStringToByteVector("FC 06 E4 E8 A0 9A EA 7A 70 71 4A 0B A6 25 D9 39 9F 5B 5F 48 8D FC F1 7E 57 EE A0 7A 18 7C 33 CC DD E1 C5 1E B3 7A 0A 9A D3 E9 AB 3E D2 D3 0F 0A"),
    }};

    std::array<std::vector<uint8_t>, 2> expectedMessages = {{
            hexStringToByteVector("A4 8D 30 39 99 53 5B 78 B8 7E 9B E2 13 28 61 D2 F9 E5 66 C1 21 7F 0C A5 6C 2D 6B 80 FF AD 13 D9"),
            hexStringToByteVector("61 8C 84 8A CB 5C D1 39 3F 9E 2A 6C EF 58 AC 0E 23 17 05 7A 5B 43 DA 69 19 0A 67 64 30 23 E3 F1 DF E6 DA 9C B0 E5 30 74 FE 07 92 9B 87 B6 10 DB"),
    }};

    // Initialise the cipher.
    rabbit.initialiseCipher(key);

    // Loop through each message and its corresponding IV to encrypt
    // and assert that the encrypted message matches the expected output.
    for (int i = 0; i < messages.size(); i++) {
        std::vector<uint8_t> encryptedBlock = messages[i];
        rabbit.encryptMessage(ivs[i], encryptedBlock);
        EXPECT_EQ(
                expectedMessages[i],
                encryptedBlock
        );
    }
}

// Testing the encryption of random.
TEST(MessageEncryptionTests, RandomMessageTest) {
    // Loop to generate random keys and validate encryption/decryption with them
    for (int k = 0; k < 10; k++) {
        std::array<uint8_t, 16> key = getRandomKey();
        rabbit.initialiseCipher(key);

        // Inner loop for each key to test with multiple random IVs and messages
        for (int i = 0; i < 10; i++) {
            std::array<uint8_t, 8> iv = getRandomIV();
            std::vector<uint8_t> message = getRandomMessage(10, 1024);
            std::vector<uint8_t> encryptedBlock = message;  // This copies the message

            // Encrypting the message
            rabbit.encryptMessage(iv, encryptedBlock);

            // Asserting that the message has been encrypted
            EXPECT_NE(
                    message,
                    encryptedBlock
            );

            // Decrypting the message
            rabbit.decryptMessage(iv, encryptedBlock);

            // Asserting that the message has been decrypted
            EXPECT_EQ(
                    message,
                    encryptedBlock
            );
        }
    }
}