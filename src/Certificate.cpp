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

#include "Certificate.hpp"

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
		t.tm_year += (str[++i] - '0');if (t.tm_year < 70)
		t.tm_year += 100;
	}
	else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
	{
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year += (str[++i] - '0') * 100;
		t.tm_year += (str[++i] - '0') * 10;
		t.tm_year += (str[++i] - '0');
		t.tm_year -= 1900;
	}
	t.tm_mon = (str[i++] - '0') * 10;
	t.tm_mon += (str[++i] - '0') - 1; // -1 since January is 0 not 1.

	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday += (str[++i] - '0');

	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour += (str[++i] - '0');

	t.tm_min = (str[i++] - '0') * 10;
	t.tm_min += (str[++i] - '0');

	t.tm_sec = (str[i++] - '0') * 10;
	t.tm_sec += (str[++i] - '0');

	return from_time_t(mktime(&t));
}

std::string convert(ASN1_INTEGER* i) {
	std::string result;
	int ch;
	BIGNUM *bnser = ASN1_INTEGER_to_BN(i, NULL);
	
	// This is really F**KING DUMB.
	// Yet again, we have to write to a temporary file first...
	FILE* f = tmpfile();
	
	BN_print_fp(f, bnser);

	rewind(f);
	
	while( !feof(f) ) {
		ch = fgetc(f);
		if(ch > 0) {
			result.append((char*) &ch, 1);
		}
	}
	
	// Remember to free the created BIGNUM instance.
	BN_free(bnser);
	
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
	
	version = X509_get_version(x);
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
		break;
	case EVP_PKEY_DSA:
		public_key_algorithm = bits + " bit DSA Public Key";
		break;
	default:
		public_key_algorithm = bits + " bit Public Key of unknown type.";
		break; 
	}
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


