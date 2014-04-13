
#include "PrivateKey.hpp"
#include <iostream>
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

private_key::private_key(std::string key):
    rsa_pkey(NULL)
{
    FILE* f = fopen(key.c_str(), "r");
    if(!PEM_read_RSAPrivateKey(f, &rsa_pkey, NULL, NULL))
        throw std::runtime_error("Unable to decode key.");
    
}

private_key::~private_key()
{
}

std::string private_key::decrypt(std::istream & emsg)
{
    std::stringstream ss;
    int retval = 0;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;

    //uint8_t buffer[4096];
    uint8_t buffer_out[4096 + EVP_MAX_IV_LENGTH];

    size_t len;
    int len_out;
    int eklen;
    uint32_t eklen_n;
    //unsigned char iv[EVP_MAX_IV_LENGTH];
    if(!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        throw std::runtime_error("Unable to assign key.");

    EVP_CIPHER_CTX_init(&ctx);
    //uint8_t* ek = new uint8_t[EVP_PKEY_size(pkey)];

    emsg >> eklen;
    if(eklen > EVP_PKEY_size(pkey))
        throw std::runtime_error("Incorrect key size. Read: "+std::to_string(eklen));

    char s[172];
    emsg.read(s, 172);
    auto ek = base64_decode(s);

    char i[24];
    emsg.read(i, 24);
    auto iv = base64_decode(i);
    
    if(!EVP_OpenInit(&ctx, EVP_aes_256_cbc(), &ek[0], eklen, &iv[0], pkey))
        throw std::runtime_error("Unable to read key from file.");

    std::string es;
    emsg >> es;
    auto buffer = base64_decode(es);
    std::cout << "Unpacked Data Size: " << buffer.size() << '\n';

    //emsg.read((char*)buffer, 4096);

    if(!EVP_OpenUpdate(&ctx, buffer_out, &len_out, &buffer[0], buffer.size()))
        throw std::runtime_error("Unable to decrypt.");

    int flen_out;
    
    if(!EVP_OpenFinal(&ctx, buffer_out+len_out, &flen_out))
        throw std::runtime_error("Unable to unpack final block.");

    for(int i = 0; i < len_out+flen_out; ++i)
        ss << buffer_out[i];
    
    return ss.str();
}


