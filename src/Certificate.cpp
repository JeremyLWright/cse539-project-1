//
// Certificate.cpp
//
// Author: Aaron Gibson
//
// This file implements the Certificate class using OpenSSL.
//
// I wanted to use Crypto++, but it output the X509 parameters
// in a very cumbersome way...

#include <cstdio>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <openssl/x509_vfy.h>

#include "Certificate.hpp"
#include "base64.h"
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <ctime>

using namespace std;
using namespace boost::posix_time;

// Note that this template is a handy "toString()" equivalent for C++
// Of course, you should specialize this template as appropriate for 
// custom types that do not have a friend '<<' operator implemented.
//
template< typename T >
string as_string(const T& t) {
	stringstream stream;
	stream << t;
	return stream.str();
}

// This template attempts to extract a type from the given string.
// Mainly used for numeric types, though this template will work for
// any type where you overload '>>' and is default-constructible.
template< typename T >
T from_string(const string& str) {
	stringstream stream(str);
	T result;
	stream >> result;
	return result;
}

//=========================================================
// Helper functions for converting between OpenSSL structs
//=========================================================
//
// Functions are defined in anonymous namespace because that is
// the recommended way of function-hiding (as opposed to the 
// dreaded 'static' function way).
//
namespace {
time_t to_time_t(boost::posix_time::ptime t)
{
    using namespace boost::posix_time;
    ptime epoch(boost::gregorian::date(1970,1,1));
    time_duration::sec_type x = (t - epoch).total_seconds();

    // ... check overflow here ...

    return time_t(x);
} 
std::string convert(X509_NAME* name) {
	// This is really F**KING DUMB.
	// Basically, OpenSSL doesn't offer a way to write X509
	// String to a buffer (its deprecated, and will only return
	// a string that is the size of the passed in buffer, which
	// is inherently finite), so instead, we write it to a
	// temporary file, and then read the file back into the
	// string.
	std::string result;
	int ch;
	
	FILE* f = tmpfile();
	X509_NAME_print_ex_fp(f, name, 0, XN_FLAG_RFC2253);
	
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

ptime convert_time(const ASN1_TIME* time) {
	struct tm t;
	const char* str = (const char*) time->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) /* two digit year */
	{
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70)
			t.tm_year += 100;
	}
	else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
	{
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year += (str[i++] - '0') * 100;
		t.tm_year += (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		t.tm_year -= 1900;
	}
	t.tm_mon = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.

	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday += (str[i++] - '0');

	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour += (str[i++] - '0');

	t.tm_min = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');

	t.tm_sec = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	return from_time_t(mktime(&t));ASN1_STRFLGS_RFC2253
}

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

int convertHexStrToInt(const string& num)
{
	// We assume that "str" is a properly encoded hexadecimal string...
	int exp = 1;
	int result = 0;
	string str = boost::algorithm::to_lower_copy(num);

	string::const_reverse_iterator itr, end;
	for(itr = str.rbegin(), end = str.rend(); itr != end; ++itr) {
		if ((*itr >= '0')&&(*itr <= '9')) {
			result += (exp * static_cast<int>(*itr - '0'));
		}
		// Handle the hexadecimal characters
		else if ((*itr >= 'a')&&(*itr <= 'f')) {
			result += (exp * (static_cast<int>(*itr - 'a') + 10));
		}
		// Error
		else {
		
		}
		exp *= 16;
	}
	return result;
}

std::string convert(ASN1_INTEGER* i) {
	std::string result;
	BIGNUM *bnser = ASN1_INTEGER_to_BN(i, NULL);

	result = printBignum(bnser);
	
	// Remember to free the created BIGNUM instance.
	BN_free(bnser);

	return result;
}

std::string convertASNString(ASN1_STRING* p)
{
	// This is really F**KING DUMB.
	// Yet again, we have to write to a temporary file first...
	FILE* f = tmpfile();
	char ch;
	string result;

	ASN1_STRING_print_ex_fp(f, p, ASN1_STRFLGS_RFC2253);

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
//=========================================================
// Constructor/Destructor
//=========================================================

X509Certificate::X509Certificate(const string& filename)
:cert(NULL), x(NULL), version(-1), serial_number(), signature_algorithm(),
notBefore(), notAfter(), subject(), issuer(), pkey(NULL),
public_key_algorithm(), public_key_length(0), public_key_modulus(),
public_key_exponent(0), signature()
{
	int retval;
	cert = BIO_new( BIO_s_file() );
	
	// I separate the function call from the comparison for convenience.
	retval = BIO_read_filename(cert, filename.c_str());
	if(retval <= 0) {
		throw std::runtime_error("Cannot open file: " + filename);
	}
	
	// Load the X509 Certificate in for comparison.
	x = d2i_X509_bio( cert, NULL );
	if(!x) {
		throw std::runtime_error("Cannot decode the certificate!");
	}
	
	// Okay, now get each field individually. Each field has a corresponding
	// OpenSSL X509 call (which is really just a preprocessor macro for accessing
	// the correct field in the X509 struct, but whatever).
	
	version = X509_get_version(x) + 1;
	// Subject
	subject = convert(X509_get_subject_name(x));
	serial_number = convert(X509_get_serialNumber(x));
	issuer = convert(X509_get_issuer_name(x));
	
	notBefore = convert_time(X509_get_notBefore(x));
	notAfter = convert_time(X509_get_notAfter(x));
	
	// Extract the public key...
	pkey = X509_get_pubkey(x);
	if(!pkey) {
		throw runtime_error("Could not acquire public key from certificate!");
	}
	// Get various parameters from the public key for convenience.
	public_key_length = EVP_PKEY_bits(pkey);
	string bits = as_string(public_key_length);
	switch(pkey->type) {
	case EVP_PKEY_RSA:
		public_key_algorithm = bits + " bit RSA Public Key";
		public_key_modulus = printBignum(pkey->pkey.rsa->n);

		// Note that this number is currently stored in hexadecimal...
		public_key_exponent = convertHexStrToInt(printBignum(pkey->pkey.rsa->e));
		break;
	case EVP_PKEY_DSA:
		public_key_algorithm = bits + " bit DSA Public Key";
		break;
	default:
		public_key_algorithm = bits + " bit Public Key of unknown type.";
		break; 
	}
	int pkey_nid = OBJ_obj2nid(x->sig_alg->algorithm);
	if (pkey_nid == NID_undef) {
		throw std::runtime_error("Unknown Signature algorithm name!");
	}

	signature_algorithm = OBJ_nid2ln(pkey_nid);

	// Get the actual signature now..
	signature = convertASNString(x->signature);
}

X509Certificate::~X509Certificate()
{
	// Free 'x' first ?
	
	// Free the BIO instance.
	if(pkey) {
		EVP_PKEY_free(pkey);
	}
	if(x) {
		X509_free(x);
	}
	if(cert) {
		BIO_free(cert);
	}
}

string X509Certificate::encrypt_message(const string& msg)
{
    //EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;

    uint8_t buffer_out[4096 + EVP_MAX_IV_LENGTH];

    int len_out;
    int eklen;
    unsigned char iv[EVP_MAX_IV_LENGTH];

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

//=========================================================
// X509CertStore Functions
//=========================================================
X509CertStore::X509CertStore(const string& file)
:rootCAfile(file)
{	
}

X509CertStore::~X509CertStore()
{
}

bool X509CertStore::verifyCertificate(X509Certificate& cert, string& msg, int flags)
{
	X509_LOOKUP* lookup = NULL;
	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;
	bool result = false;

	// Allocate the store.
	store = X509_STORE_new();
	if(!store) {
		throw runtime_error("Could not allocate X509_STORE for verification.");
	}
	
	// Create the lookup table by loading the root certificate.
	lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
	if(!lookup) {
		throw runtime_error("X509_LOOKUP was not added to the store.");
	}
	if(!X509_LOOKUP_load_file(lookup, rootCAfile.c_str(), X509_FILETYPE_ASN1)) {
		throw runtime_error("Error loading root certificate: " + rootCAfile);
	}
	X509_STORE_set_flags(store, 0);

	ctx = X509_STORE_CTX_new();
	if(!ctx) {
		throw runtime_error("Could not allocate X509_STORE_CTX for verification.");
	}
	X509_STORE_CTX_init(ctx, store, cert.x, 0);
	X509_STORE_CTX_set_flags(ctx, flags);
	
	int rc = X509_verify_cert(ctx);
	if(rc == 1) {
		result = true;
	} else {
		msg = X509_verify_cert_error_string(ctx->error);
		result = false;
	}
	X509_STORE_CTX_free(ctx);
	
	return result;
}

bool X509CertStore::verifyCertificateAtTime(X509Certificate& cert, std::string& msg,
	const boost::posix_time::ptime& p, int flags)
{
	X509_LOOKUP* lookup = NULL;
	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;
	bool result = false;

	// Allocate the store.
	store = X509_STORE_new();
	if(!store) {
		throw runtime_error("Could not allocate X509_STORE for verification.");
	}
	
	// Create the lookup table by loading the root certificate.
	lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
	if(!lookup) {
		throw runtime_error("X509_LOOKUP was not added to the store.");
	}
	if(!X509_LOOKUP_load_file(lookup, rootCAfile.c_str(), X509_FILETYPE_ASN1)) {
		throw runtime_error("Error loading root certificate: " + rootCAfile);
	}
	X509_STORE_set_flags(store, 0);
	
	ctx = X509_STORE_CTX_new();
	if(!ctx) {
		throw runtime_error("Could not allocate X509_STORE_CTX for verification.");
	}
	X509_STORE_CTX_init(ctx, store, cert.x, 0);
	X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_USE_CHECK_TIME | flags);
	
	// For this variant of the call, we set the verification time to what
	// was passed in.
	X509_STORE_CTX_set_time(ctx, 0, to_time_t(p));
	
	int rc = X509_verify_cert(ctx);
	if(rc == 1) {
		result = true;
	} else {
		msg = X509_verify_cert_error_string(ctx->error);
		result = false;
	}
	X509_STORE_CTX_free(ctx);
	
	return result;}


bool X509CertStore::verifyCertificate(X509Certificate& cert, string& msg)
{
	return verifyCertificate(cert, msg, X509_V_FLAG_CB_ISSUER_CHECK );
}

bool X509CertStore::isIssuedByTrustedSource(X509Certificate& cert)
{
	return false;
}

//=========================================================
// Printing Functions
//=========================================================
void X509Certificate::printCertificate(ostream& stm) const
{
	stm << "Version: " << version
		<< "\nSubject: " << subject
		<< "\nIssuer: " << issuer
		<< "\nSerial #: " << serial_number
		<< "\nNot Valid Before: " << to_simple_string(notBefore)
		<< "\nNot Valid After: " << to_simple_string(notAfter)
		<< "\n\nPublic Key Algorithm: " << public_key_algorithm
		<< "\nPublic Key Length: " << public_key_length
		<< "\nPublic Key Modulus: " << public_key_modulus
		<< "\nPublic Key Exponent: " << public_key_exponent
		<< "\n\nSignature Algorithm: " << signature_algorithm
		<< "\nSignature: " << signature << "\n";
}


