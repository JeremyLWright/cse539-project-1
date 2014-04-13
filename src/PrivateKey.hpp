#pragma once

#include <string>
#include <sstream>
#include "openssl/rsa.h"


class private_key
{
    RSA* rsa_pkey;
    int const BASE64_ENCODED_KEY_SIZE = 172;
    int const BASE64_ENCODED_IV_SIZE = 24;
public:
    explicit private_key(std::string key);
    ~private_key();
    std::string decrypt(std::istream& emsg);

};
