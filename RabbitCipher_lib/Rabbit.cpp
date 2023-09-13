#include <iostream>
#include "Rabbit.h"

//Documentation https://www.rfc-editor.org/rfc/rfc4503

const uint32_t Rabbit::A[8] = {0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3};

//Initialising the Cipher per the 2.3 Key Setup Scheme
void Rabbit::initialiseCipher(const std::array<uint8_t, 16>& newKey) {
    //key is saved in case the cipher needs to be reinitialised later
    key = newKey;

    //carry bit is initialised
    b=0;

    //dividing the key into subkeys
    int subK[subKeyArrayLength] = {};
    for (int i = 0; i < subKeyArrayLength; i++) {
        subK[i] = (key[2*i+1] << 8 | (key[2*i] & 0xFF)) & 0xFFFF;
    }

    //initialising the initial state
    for(int i=0; i<subKeyArrayLength; i++){
        if(i%2==0){
            X[i] = (subK[(i+1) % 8] << 16) | (subK[i]);
            C[i] = (subK[(i+4) % 8] << 16) | (subK[(i+5) % 8]);
        }else{
            X[i] = (subK[(i+5) % 8] << 16) | (subK[(i+4) % 8]);
            C[i] = (subK[i]         << 16) | (subK[(i+1) % 8]);
        }
    }

    //iterating counter update and next-state function 4 times
    for(int i=0; i<4; i++){
        counterUpdate();
        nextState();
    }

    //reinitialising the counter variables
    for(int i=0; i<C.size(); i++){
        C[i]=C[i]^X[(i+4) % 8];
    }

}

//Initialising the IV per the 2.4 IV Setup Scheme
void Rabbit::initialiseIV(const std::array<uint8_t, 8>& IV) {
    if (!IV.empty()){
        //To handle reinitialisation
        if(prevIV.has_value()){
            initialiseCipher(key);
        }
        prevIV=IV;

        //C0 = C0 ^ IV[31..0]
        C[0] ^= (IV[3] << 24) | ((IV[2] & 0xFF) << 16) | ((IV[1] & 0xFF) << 8) | (IV[0] & 0xFF);
        //C1 = C1 ^ (IV[63..48] || IV[31..16])
        C[1] ^= (IV[7] << 24) | ((IV[6] & 0xFF) << 16) | ((IV[3] & 0xFF) << 8) | (IV[2] & 0xFF);
        //C2 = C2 ^ IV[63..32]
        C[2] ^= (IV[7] << 24) | ((IV[6] & 0xFF) << 16) | ((IV[5] & 0xFF) << 8) | (IV[4] & 0xFF);
        //C3 = C3 ^ (IV[47..32] || IV[15..0])
        C[3] ^= (IV[5] << 24) | ((IV[4] & 0xFF) << 16) | ((IV[1] & 0xFF) << 8) | (IV[0] & 0xFF);
        //C4 = C4 ^ IV[31..0]
        C[4] ^= (IV[3] << 24) | ((IV[2] & 0xFF) << 16) | ((IV[1] & 0xFF) << 8) | (IV[0] & 0xFF);
        //C5 = C5 ^ (IV[63..48] || IV[31..16])
        C[5] ^= (IV[7] << 24) | ((IV[6] & 0xFF) << 16) | ((IV[3] & 0xFF) << 8) | (IV[2] & 0xFF);
        //C6 = C6 ^ IV[63..32]
        C[6] ^= (IV[7] << 24) | ((IV[6] & 0xFF) << 16) | ((IV[5] & 0xFF) << 8) | (IV[4] & 0xFF);
        //C7 = C7 ^ (IV[47..32] || IV[15..0])
        C[7] ^= (IV[5] << 24) | ((IV[4] & 0xFF) << 16) | ((IV[1] & 0xFF) << 8) | (IV[0] & 0xFF);

        //iterating counter update and next-state function 4 times
        for(int i=0; i<4; i++){
            counterUpdate();
            nextState();
        }
    }
}

//Updating the counter system per the 2.5 Counter System
void Rabbit::counterUpdate() {
    //using the carry bit to update the counter system
    for (int j = 0; j < 8; j++) {
        uint64_t s1 =  (C[j] % WORD_SIZE);
        uint64_t temp = s1 + A[j] + b;
        b = temp / WORD_SIZE;
        C[j] = temp % WORD_SIZE;
    }
}

//Next-State function per the point 2.6 Next-State Function
void Rabbit::nextState() {
    for(int i=0; i<G.size(); i++){
        G[i]=g(X[i], C[i]);
    }

    //X0 =          G0 + (G7 <<< 16) + (G6 <<< 16) mod WORDSIZE
    X[0] = ((G[0] + leftRotation(G[7],16) + leftRotation(G[6],16)) % WORD_SIZE);
    //X1 =          G1 + (G0 <<<  8) + G7 mod WORDSIZE
    X[1] = ((G[1] + leftRotation(G[0],8) + G[7]) % WORD_SIZE);
    //X2 =          G2 + (G1 <<< 16) + (G0 <<< 16) mod WORDSIZE
    X[2] = ((G[2] + leftRotation(G[1],16) + leftRotation(G[0],16)) % WORD_SIZE);
    //X3 =          G3 + (G2 <<<  8) + G1 mod WORDSIZE
    X[3] = ((G[3] + leftRotation(G[2],8) + G[1]) % WORD_SIZE);
    //X4 =          G4 + (G3 <<< 16) + (G2 <<< 16) mod WORDSIZE
    X[4] = ((G[4] + leftRotation(G[3],16) + leftRotation(G[2],16)) % WORD_SIZE);
    //X5 =          G5 + (G4 <<<  8) + G3 mod WORDSIZE
    X[5] = ((G[5] + leftRotation(G[4],8) + G[3]) % WORD_SIZE);
    //X6 =          G6 + (G5 <<< 16) + (G4 <<< 16) mod WORDSIZE
    X[6] = ((G[6] + leftRotation(G[5],16) + leftRotation(G[4],16)) % WORD_SIZE);
    //X7 =          G7 + (G6 <<<  8) + G5 mod WORDSIZE
    X[7] = ((G[7] + leftRotation(G[6],8) + G[5]) % WORD_SIZE);
}

//Function g implementation per the point 2.6 Next-State Function
uint32_t Rabbit::g(uint32_t u, uint32_t v) {
    /*
    g(u,v) = LSW(square(u+v)) ^ MSW(square(u+v))
    where square(u+v) = ((u+v mod WORDSIZE) * (u+v mod WORDSIZE)).
     */
    uint64_t square = (u + v) % WORD_SIZE;
    square *= square;
    return (square & 0xFFFFFFFFULL) ^ square >> 32;
}

//Left bit rotation
uint32_t Rabbit::leftRotation(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

//Extraction scheme per the point 2.7 Extraction Scheme
void Rabbit::extraction() {
    counterUpdate();
    nextState();

    //output S initialisation
    S={};

    //S[15..0] = X0[15..0]  ^ X5[31..16]
    uint32_t s = X[0] ^ X[5] >> 16;
    S[0] = s;
    S[1] = (s >> 8);
    //S[31..16] = X0[31..16] ^ X3[15..0]
    s = X[0] >> 16 ^ X[3];
    S[2] = s;
    S[3] = (s >> 8);
    //S[47..32] = X2[15..0]  ^ X7[31..16]
    s = X[2] ^ X[7] >> 16;
    S[4] = s;
    S[5] = (s >> 8);
    //S[63..48] = X2[31..16] ^ X5[15..0]
    s = X[2] >> 16 ^ X[5];
    S[6] = s;
    S[7] = (s >> 8);
    //S[79..64] = X4[15..0]  ^ X1[31..16]
    s = X[4] ^ X[1] >> 16;
    S[8] = s;
    S[9] = (s >> 8);
    //S[95..80] = X4[31..16] ^ X7[15..0]
    s = X[4] >> 16 ^ X[7];
    S[10] = s;
    S[11] = (s >> 8);
    //S[111..96]  = X6[15..0]  ^ X3[31..16]
    s = X[6] ^ X[3] >> 16;
    S[12] = s;
    S[13] = (s >> 8);
    //S[127..112] = X6[31..16] ^ X1[15..0]
    s = X[6] >> 16 ^ X[1];
    S[14] = s;
    S[15] = (s >> 8);
}

//Encryption per point 2.8 Encryption/Decryption
void Rabbit::encrypt(std::vector<uint8_t>& block) {
    for(int i=0; i<block.size(); i++){
        if(i%16==0)
            extraction(); //to generate new S values
        //E  = M ^ S
        block[i] ^= S[i%16];
    }
}

//Decryption per point 2.8 Encryption/Decryption
void Rabbit::decrypt(std::vector<uint8_t>& block) {
    /*
        E  = M ^ S
        M' = E ^ S.
        If S is the same in both operations (as it should be if the same key
        and IV are used), then M = M'.
        */
    encrypt(block); //same computation is used as in encryption
}

//Message encryption, vector is used since messages are not limited in length
void Rabbit::encryptMessage(const std::array<uint8_t, 8>& iv, std::vector<uint8_t>& message) {
    if(!message.empty()){
        initialiseIV(iv);
        encrypt(message);
    }
}

//Message decryption, vector is used since messages are not limited in length
void Rabbit::decryptMessage(const std::array<uint8_t, 8>& iv, std::vector<uint8_t>& message) {
    if(!message.empty()){
        initialiseIV(iv);
        encrypt(message); //since its a stream cipher encryption = decryption
    }
}

//Returns string of the state arrays in hexadecimal form
std::string Rabbit::getStateString() {
    std::ostringstream output;
    for(int i = 0; i < 8; i++) {
        // Adding X values in hexadecimal
        output << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << X[i] << " ";
    }
    for(int i = 0; i < 8; i++) {
        // Adding C values in hexadecimal
        output << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << C[i] << " ";
    }
    // Adding carry bit b value and returning
    output << std::dec << b;  // Switching back to decimal for b, if you want its decimal representation.
    return output.str();
}

