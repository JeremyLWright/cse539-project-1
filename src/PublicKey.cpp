#include "PublicKey.hpp"
#include "base64.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/err.h"
#include <fstream>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <string.h>
#include <iostream>

public_key::public_key(std::string key):
    rsa_pkey(NULL)
{
    FILE* f = fopen(key.c_str(), "r");
    if(!PEM_read_RSA_PUBKEY(f, &rsa_pkey, NULL, NULL))
        throw std::runtime_error("Unable to decode key.");
    
}

public_key::~public_key()
{
}

std::string public_key::encrypt(std::string msg)
{
    EVP_CIPHER_CTX ctx;
    EVP_PKEY *pkey = EVP_PKEY_new();

    uint8_t buffer_out[4096 + EVP_MAX_IV_LENGTH];

    int len_out;
    int eklen;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if(!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        throw std::runtime_error("Unable to assign key.");

    EVP_CIPHER_CTX_init(&ctx);
    uint8_t* ek = new uint8_t[EVP_PKEY_size(pkey)];

    if(!EVP_SealInit(&ctx, EVP_aes_256_cbc(), &ek, &eklen, iv, &pkey, 1))
        throw std::runtime_error("Unable to init seal.");


     EVP_SealUpdate(&ctx, buffer_out, &len_out, (uint8_t const *)(msg.c_str()), msg.size());

     int flen_out;
     EVP_SealFinal(&ctx, buffer_out+len_out, &flen_out);

     std::stringstream ss;
     ss << eklen; //Write key length
     ss << base64_encode(&ek[0], eklen); //Write the session ket encrypted with the public ket
     ss << base64_encode(&iv[0], EVP_CIPHER_iv_length(EVP_aes_256_cbc())); //Write the aes initialization vector
     ss << base64_encode(&buffer_out[0], len_out+flen_out); //Write the encrypted data.
     return ss.str();
}
