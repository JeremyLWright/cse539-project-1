#ifndef CERTIFICATE_HPP
#define CERTIFICATE_HPP
//
// Certificate.hpp
//
// Author: Aaron Gibson and Jeremy Wright
//
// This file implements a wrapper class around certificates. It will use
// the Crypto++ library to implement the various functions.

#include "openssl/bio.h"
#include "openssl/asn1.h"
#include "openssl/err.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/objects.h"
#include "openssl/pem.h"

#include <boost/date_time/posix_time/posix_time_types.hpp>


class X509Certificate {
public:
	// Instance variables.
	BIO* cert;
	X509* x;
	
	int version;
	std::string serial_number;
	std::string signature_algorithm;
	boost::posix_time::ptime notBefore;
	boost::posix_time::ptime notAfter;
	
	std::string subject;
	std::string issuer;
	
	EVP_PKEY *pkey;
	std::string public_key_algorithm;
	size_t public_key_length;
	std::string public_key_modulus;
	size_t public_key_exponent;
	
	std::string signature;

	// Instance Variables
	X509Certificate(const X509Certificate& other);
	X509Certificate& operator=(const X509Certificate& other);
		
	// Makes implementing '<<' operator easier.
	void printCertificate(std::ostream& stm) const;
	
	X509Certificate(const std::string& filename);
	~X509Certificate();
#ifdef HAS_MOVE_SEMANTICS
	X509Certificate( X509Certificate&& other);
	X509Certificate& operator=( X509Certificate&& other);
#endif
	static X509Certificate parseFromFile(const std::string& filepath);
}; // class X509Certificate

// Declare the streaming operator. We define it inline to avoid linker errors,
// since this is really just a proxy call to "printCertificate()".
inline std::ostream& operator<<(std::ostream& stm, const X509Certificate& cert) {
	cert.printCertificate(stm);
	return stm;
}

#endif

