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

#include <stdexcept>

#include "Certificate.hpp"

//#include "boost/program_options.hpp"
//#include "boost/filesystem.hpp"

int main(int argc, char** argv)
{
	if(argc < 2) {
		std::cout << "Filename required as an argument.\n";
		return 1;
	}
	X509Certificate cert(argv[1]);
	
	std::cout << cert << std::endl;
	return 0;
}

