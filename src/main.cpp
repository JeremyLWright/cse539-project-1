/*
 * Demonstration program for hashing and MACs
 */
#include <ostream>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include "openssl/bio.h"
#include "openssl/asn1.h"
#include "openssl/err.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/objects.h"
#include "openssl/pem.h"
#include "apps/apps.h"

#include <stdexcept>

#include "boost/program_options.hpp"
#include "boost/filesystem.hpp"

struct x509_extensions 
{
    std::string basic_constraints;
    std::string key_usage;
    std::string ca_policy;
    std::string cert_type;
    std::string revocation_url;
};

class certificate
{

    BIO* cert;
    X509* x;
    std::fstream file;
    public:
    certificate(std::string filename)
    {
        cert=BIO_new(BIO_s_file());
        if(BIO_read_filename(cert,filename.c_str()) <= 0)
        {
            throw std::runtime_error("Cannot open file: "+filename);
        }
        x=d2i_X509_bio(cert,NULL);

        if (x == NULL)
        {
            throw std::runtime_error("cannot decode certificate");
        }
    }

    ~certificate()
    {
        BIO_free(cert);
    }
    int version;
    std::string serial_number;
    std::string signature_algorithm;
    std::string issuer;
    std::string validity_not_before;
    std::string validity_not_after;

    std::string subject;

    std::string public_key_algorithm;

    size_t public_key_length;
    std::string public_key_modulus;
    size_t public_key_exponent;

    //std::string signature_algorithm;
    std::string signature;

    



};
#if 0

using namespace std;

    static void
printDigest(unsigned char *digest, unsigned int len)
{
    int i;

    cout << "length: " << len << endl;
    for(i = 0;i < len;i++) printf("%02x ", digest[i]);
    cout << endl;
}



void print_key(std::ostream& s, std::string data)
{
    auto data_base64 = BTOA_DataToAscii(reinterpret_cast<unsigned char const *>(data.c_str()), data.size());
    for(auto i = 0; i < data.size(); ++i) //TODO I'm pretty sure this length is wrong
        s << data_base64[i];
    s << '\n';
}
#endif
/*
 * main
 */
    int
main(int argc, const char *argv[])
{

    namespace po = boost::program_options;
    namespace fs = boost::filesystem;

    std::string const magic_string("Our names are Jeremy Wright and Aaron Gibson. We are enrolled in CSE 539");

    po::options_description desc("CSE539 Project 1 by Jeremy Wright and Aaron Gibson");
    desc.add_options()
        ("help", "Produce this help message.")
        ("publicKey", po::value<std::string>(), "Public Key.")
        ("privateKey", po::value<std::string>(), "Private Key.")
        ("cert", po::value<std::string>(), "DER format Certificate")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if(vm.count("help"))
    {
        std::cout << desc << '\n';
        return 1;
    }

    int const cert_format = FORMAT_ASN1;

    int e;
    certificate c(vm["cert"].as<std::string>());

#if 0
    std::ifstream fpub_key(vm["publicKey"].as<string>());
    std::string   pub_key(static_cast<std::stringstream const &>(std::stringstream() << fpub_key.rdbuf()).str());
    std::ifstream fpriv_key(vm["privateKey"].as<string>());
    std::string   priv_key(static_cast<std::stringstream const &>(std::stringstream() << fpriv_key.rdbuf()).str());
    std::ifstream fcert(vm["cert"].as<string>());
    std::string   cert(static_cast<std::stringstream const &>(std::stringstream() << fcert.rdbuf()).str());

    std::cout << "Print Public Key" << '\n';
    print_key(cout, pub_key);

    std::cout << "Print Certificate" << '\n';
    print_key(cout, cert);

    std::cout << "Print Private Key" << '\n';
    print_key(cout, priv_key);

    int status = 0;
    PK11SlotInfo *slot = 0;
    PK11SymKey *key = 0;
    PK11Context *context = 0;
    unsigned char data[80];
    unsigned char digest[20]; /*Is there a way to tell how large the output is?*/
    unsigned int len;
    SECStatus s;

    /* Initialize NSS
     * If your application code has already initialized NSS, you can skip it
     * here.
     * This code uses the simplest of the Init functions, which does not
     * require a NSS database to exist
     */
    NSS_NoDB_Init(".");

    /* Get a slot to use for the crypto operations */
    slot = PK11_GetInternalKeySlot();
    if (!slot)
    {
        cout << "GetInternalKeySlot failed" << endl;
        status = 1;
        goto done;
    }

    /*
     *  Part 1 - Simple hashing
     */
    cout << "Part 1 -- Simple hashing" << endl;

    /* Initialize data */
    memset(data, 0xbc, sizeof data);

    /* Create a context for hashing (digesting) */
    context = PK11_CreateDigestContext(SEC_OID_MD5);
    if (!context) { cout << "CreateDigestContext failed" << endl; goto done; }

    s = PK11_DigestBegin(context);
    if (s != SECSuccess) { cout << "DigestBegin failed" << endl; goto done; }

    s = PK11_DigestOp(context, data, sizeof data);
    if (s != SECSuccess) { cout << "DigestUpdate failed" << endl; goto done; }

    s = PK11_DigestFinal(context, digest, &len, sizeof digest);
    if (s != SECSuccess) { cout << "DigestFinal failed" << endl; goto done; }

    /* Print digest */
    printDigest(digest, len);

    PK11_DestroyContext(context, PR_TRUE);
    context = 0;

    /*
     *  Part 2 - Hashing with included secret key
     */
    cout << "Part 2 -- Hashing with included secret key" << endl;

    /* Initialize data */
    memset(data, 0xbc, sizeof data);

    /* Create a Key */
    key = PK11_KeyGen(slot, CKM_GENERIC_SECRET_KEY_GEN, 0, 128, 0);
    if (!key) { cout << "Create key failed" << endl; goto done; }

    cout << (void *)key << endl;

    /* Create parameters for crypto context */
    /* NOTE: params must be provided, but may be empty */
    SECItem noParams;
    noParams.type = siBuffer;
    noParams.data = 0;
    noParams.len = 0;

    /* Create context using the same slot as the key */
//  context = PK11_CreateDigestContext(SEC_OID_MD5);
  context = PK11_CreateContextBySymKey(CKM_MD5, CKA_DIGEST, key, &noParams);
  if (!context) { cout << "CreateDigestContext failed" << endl; goto done; }

  s = PK11_DigestBegin(context);
  if (s != SECSuccess) { cout << "DigestBegin failed" << endl; goto done; }

  s = PK11_DigestKey(context, key);
  if (s != SECSuccess) { cout << "DigestKey failed" << endl; goto done; }

  s = PK11_DigestOp(context, data, sizeof data);
  if (s != SECSuccess) { cout << "DigestUpdate failed" << endl; goto done; }

  s = PK11_DigestFinal(context, digest, &len, sizeof digest);
  if (s != SECSuccess) { cout << "DigestFinal failed" << endl; goto done; }

  /* Print digest */
  printDigest(digest, len);

  PK11_DestroyContext(context, PR_TRUE);
  context = 0;

  /*
   *  Part 3 - MAC (with secret key)
   */
  cout << "Part 3 -- MAC (with secret key)" << endl;

  /* Initialize data */
  memset(data, 0xbc, sizeof data);

  context = PK11_CreateContextBySymKey(CKM_MD5_HMAC, CKA_SIGN, key, &noParams);
  if (!context) { cout << "CreateContextBySymKey failed" << endl; goto done; }

  s = PK11_DigestBegin(context);
  if (s != SECSuccess) { cout << "DigestBegin failed" << endl; goto done; }

  s = PK11_DigestOp(context, data, sizeof data);
  if (s != SECSuccess) { cout << "DigestOp failed" << endl; goto done; }

  s = PK11_DigestFinal(context, digest, &len, sizeof digest);
  if (s != SECSuccess) { cout << "DigestFinal failed" << endl; goto done; }

  /* Print digest */
  printDigest(digest, len);

  PK11_DestroyContext(context, PR_TRUE);
  context = 0;

done:
  if (context) PK11_DestroyContext(context, PR_TRUE);  /* freeit ?? */
  if (key) PK11_FreeSymKey(key);
  if (slot) PK11_FreeSlot(slot);

  return status;
#endif
}
