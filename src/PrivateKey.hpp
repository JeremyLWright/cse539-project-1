#pragma once

#include <string>
#include <iostream>
#include <sstream>
#include "openssl/rsa.h"


class private_key
{
    RSA* rsa_pkey;
    int const BASE64_ENCODED_KEY_SIZE;
    int const BASE64_ENCODED_IV_SIZE;
public:
    explicit private_key(std::string key);
    private_key();
    ~private_key();
    std::string decrypt(std::istream& emsg);

void print(std::ostream& stream);

};
