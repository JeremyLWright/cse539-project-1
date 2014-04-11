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
#include <stdexcept>

#include "Certificate.hpp"

using namespace std;

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
	// String to a buffer (its deprecated), so instead, we
	// write it to a temporary file, and then read the file 
	// back into the string.
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
issuer(), validity_not_before(), validity_not_after(), subject(),
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
}

X509Certificate::~X509Certificate()
{
	// Free 'x' first ?
	
	// Free the BIO instance.
	BIO_free(cert);
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
		<< "\nValid Not Before: " << validity_not_before
		<< "\nValid Not After: " << validity_not_after
		<< "\n\nPublic Key Algorithm: " << public_key_algorithm
		<< "\nPublic Key Length: " << public_key_length
		<< "\nPublic Key Modulus: " << public_key_modulus
		<< "\nPublic Key Exponent: " << public_key_exponent
		<< "\n\nSignature Algorithm: " << signature_algorithm
		<< "\nSignature: " << signature << "\n";
}

