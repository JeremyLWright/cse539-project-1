#include "PublicKey.hpp"

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

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

namespace {
    using namespace boost::archive::iterators;
    ///
    /// Convert up to len bytes of binary data in src to base64 and store it in dest
    ///
    /// \param dest Destination buffer to hold the base64 data.
    /// \param src Source binary data.
    /// \param len The number of bytes of src to convert.
    ///
    /// \return The number of characters written to dest.
    /// \remarks Does not store a terminating null in dest.
    ///
    uint base64_encode(char* dest, const char* src, uint len)
    {
        char tail[3] = {0,0,0};
        typedef base64_from_binary<transform_width<const char *, 6, 8> > base64_enc;

        uint one_third_len = len/3;
        uint len_rounded_down = one_third_len*3;
        uint j = len_rounded_down + one_third_len;

        std::copy(base64_enc(src), base64_enc(src + len_rounded_down), dest);

        if (len_rounded_down != len)
        {
            uint i=0;
            for(; i < len - len_rounded_down; ++i)
            {
                tail[i] = src[len_rounded_down+i];
            }

            std::copy(base64_enc(tail), base64_enc(tail + 3), dest + j);

            for(i=len + one_third_len + 1; i < j+4; ++i)
            {
                dest[i] = '=';
            }

            return i;
        }

        return j;
    }

    ///
    /// Convert null-terminated string src from base64 to binary and store it in dest.
    ///
    /// \param dest Destination buffer
    /// \param src Source base64 string
    /// \param len Pointer to unsigned int representing size of dest buffer. After function returns this is set to the number of character written to dest.
    ///
    /// \return Pointer to first character in source that could not be converted (the terminating null on success)
    ///
    const char* base64_decode(char* dest, const char* src, uint* len)
    {
        uint output_len = *len;

        typedef transform_width<binary_from_base64<const char*>, 8, 6> base64_dec;

        uint i=0;
        try
        {
            base64_dec src_it(src);
            for(; i < output_len; ++i)
            {
                *dest++ = *src_it;
                ++src_it;
            }
        }
        catch(dataflow_exception&)
        {
        }

        *len = i;
        return src + (i+2)/3*4; // bytes in = bytes out / 3 rounded up * 4
    }
}

public_key::public_key(std::string key)
{
    FILE* f = fopen(key.c_str(), "r");
    rsa_pkey = NULL;
    //std::ifstream fpub_key(key);
    //std::string pub_key(static_cast<std::stringstream const &>(std::stringstream() << fpub_key.rdbuf()).str());
    //BIO* k = BIO_new_mem_buf((void*)(pub_key.c_str()), pub_key.size());
    if(!PEM_read_RSA_PUBKEY(f, &rsa_pkey, NULL, NULL))
        throw std::runtime_error("Unable to decode key.");
    
}

public_key::~public_key()
{
}

std::string public_key::encrypt(std::string msg)
{
    int retval = 0;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;

    uint8_t buffer[4096];
    uint8_t buffer_out[4096 + EVP_MAX_IV_LENGTH];

    size_t len;
    int len_out;
    int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if(!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        throw std::runtime_error("Unable to assign key.");

    EVP_CIPHER_CTX_init(&ctx);
    uint8_t* ek = new uint8_t[EVP_PKEY_size(pkey)];

    if(!EVP_SealInit(&ctx, EVP_aes_256_cbc(), &ek, &eklen, iv, &pkey, 1))
        throw std::runtime_error("Unable to init seal.");

    eklen_n = htonl(eklen);

     std::stringstream ss;
     ss << eklen_n;
     char* d = new char[4096];
     len = base64_encode((char*)(ek), d, eklen);
     std::copy_n(d, len, std::ostream_iterator<char>(ss));
     //len = base64_encode(iv, d, EVP_CIPHER_iv_length(EVP_aes_256_cbc())
     //std::copy(base64_text(ek.get()), eklen, ostream_iterator<char>(ss));
     //std::copy_n(base64_text(iv), EVP_CIPHER_iv_length(EVP_aes_256_cbc()), std::ostream_iterator<char>(ss));

     EVP_SealUpdate(&ctx, buffer_out, &len_out, (uint8_t const *)(msg.c_str()), msg.size());
     //std::copy(base64_text(buffer_out), len_out, ostream_iteator<char>(ss));
     return ss.str();
}

