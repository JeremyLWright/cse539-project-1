
#include "PrivateKey.hpp"
#include <iostream>
#include <iterator>
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

#include "base64.h"

using namespace std;

namespace {
string printBignum(BIGNUM* bn)
{
	// This is really F**KING DUMB.
	// Yet again, we have to write to a temporary file first...
	FILE* f = tmpfile();

	char ch;
	string result;

	BN_print_fp(f, bn);

	rewind(f);
	
	while( !feof(f) ) {
		ch = fgetc(f);
		if(ch > 0) {
			result.append((char*) &ch, 1);
		}
	}

	// Close the temporary file to delete it.
	fclose(f);
	return result;
}

}

private_key::private_key():
    rsa_pkey(NULL),
    BASE64_ENCODED_KEY_SIZE(172),
    BASE64_ENCODED_IV_SIZE(24)
{
}

private_key::private_key(std::string key):
    rsa_pkey(NULL),
    BASE64_ENCODED_KEY_SIZE(172),
    BASE64_ENCODED_IV_SIZE(24)
{
    FILE* f = fopen(key.c_str(), "r");
    if(!PEM_read_RSAPrivateKey(f, &rsa_pkey, NULL, NULL))
        throw std::runtime_error("Unable to decode key.");
    fclose(f);
    
}

private_key::~private_key()
{
}

void private_key::print(std::ostream& stream)
{
	stream << "Modulus: " << printBignum(rsa_pkey->n)
		<< "\nd: " << printBignum(rsa_pkey->d) << "\n";
}

std::string private_key::decrypt(std::istream & emsg)
{
    std::stringstream ss;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;

    uint8_t buffer_out[4096 + EVP_MAX_IV_LENGTH];

    int len_out;
    int eklen;
    if(!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        throw std::runtime_error("Unable to assign key.");

    EVP_CIPHER_CTX_init(&ctx);

    emsg >> eklen;
    if(eklen > EVP_PKEY_size(pkey))
        throw std::runtime_error("Incorrect key size. Read: "+std::to_string(eklen));

    char s[BASE64_ENCODED_KEY_SIZE];
    emsg.read(s, BASE64_ENCODED_KEY_SIZE);
    auto ek = base64_decode(s);

    char i[BASE64_ENCODED_IV_SIZE];
    emsg.read(i, BASE64_ENCODED_IV_SIZE);
    auto iv = base64_decode(i);
    
    if(!EVP_OpenInit(&ctx, EVP_aes_256_cbc(), &ek[0], eklen, &iv[0], pkey))
        throw std::runtime_error("Unable to read key from file.");

    std::string es;
    emsg >> es;
    auto buffer = base64_decode(es);

    if(!EVP_OpenUpdate(&ctx, buffer_out, &len_out, &buffer[0], buffer.size()))
        throw std::runtime_error("Unable to decrypt.");

    int flen_out;
    
    if(!EVP_OpenFinal(&ctx, buffer_out+len_out, &flen_out))
        throw std::runtime_error("Unable to unpack final block.");

    std::copy_n(buffer_out, len_out+flen_out, std::ostream_iterator<char>(ss));

    return ss.str();
}


