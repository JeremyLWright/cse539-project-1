#pragma once

#include <string>
#include <sstream>
#include "openssl/rsa.h"


class private_key
{
 RSA* rsa_pkey;
public:
    explicit private_key(std::string key);
    ~private_key();
    std::string decrypt(std::istream& emsg);

};
