#pragma once

#include <string>
#include "openssl/rsa.h"


class public_key
{
 RSA* rsa_pkey;
public:
    explicit public_key(std::string key);
    ~public_key();

    std::string encrypt(std::string msg);

};
