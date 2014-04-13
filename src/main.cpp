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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>

#include "Certificate.hpp"
#include "PrivateKey.hpp"

//#include "boost/program_options.hpp"
//#include "boost/filesystem.hpp"

using namespace std;
using namespace boost::posix_time;

namespace po = boost::program_options;

void printSectionHeader(std::ostream& stream, const string& name) {
	stream << "\n================================================\n"
		<< name
		<< "\n================================================"
		<< endl;
}

int main(int argc, const char* argv[])
{
	try {
		string rootCAfile = "../certificate/Trustcenter.cer";
		string certsToVerify;
		string privKeyfile = "../certificate/private_key.pem";
		
		po::options_description desc("Configuration Options");
		desc.add_options()
			("help,h,?", "Display help")
			("root-ca,r", po::value<string>()->default_value(rootCAfile),
			"Set the root CA certificate to use in verification.")
			("priv-key,p", po::value<string>()->default_value(privKeyfile),
				"Set the private key for the given certificate.")
			("cert", po::value<string>(),
				"Set the certificate to actually verify.")
		; // Don't forget this...
		
		// Set any parameters passed (that aren't options) to be the same
		po::positional_options_description p;
			p.add("cert", -1);
		
		// Parse the commandline options.
		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
		po::notify(vm);
		
		// Now, process based on the options.
		if(vm.count("help")) {
			cout << desc << "\n";
			return 1;
		}
		if(!vm.count("cert"))	{
			cout << "A certificate is required to run the tests!\n";
			return 2;	
		}
		
		//=========================================
		// First, construct the certificate store, with the root certificate.		
		printSectionHeader(cout, "Creating Certificate Store");
		cout << "Loading Root certificate at: " << rootCAfile << "\n";
		X509CertStore store(rootCAfile);

		//=========================================
		// Print the root certificate (?)
		{
			X509Certificate root(rootCAfile);
			cout << root << "\n";
		}
		
		certsToVerify = vm["cert"].as< string >();
		//=========================================
		// Print Certificate
		printSectionHeader(cout, "Printing Certificate at: " + certsToVerify);
		X509Certificate cert(certsToVerify);	
		cout << cert << "\n";
		//=========================================
		// Verify Certificate
		printSectionHeader(cout, "Verifying Certificate at: " + certsToVerify);
		string msg;
		if(!store.verifyCertificate(cert, msg)) {
			cout << "Verification failed: " << msg << "\n";
			//=========================================
			// Re-verify Certificate with older date.
			ptime oldDate(boost::gregorian::date(2007, boost::gregorian::Jan, 1),
				hours(1));
			cout << "Trying verification again with an older date: "<<
				to_simple_string(oldDate) << "\n";
			if(!store.verifyCertificateAtTime(cert, msg, oldDate, 0)) {
				cout << "Verification failed: " << msg << "\n";
			} else {
				cout << "Verification successful.\n";
			}
		} else {
			cout << "Verification successful.\n";
		}

		//=========================================
		// Encrypt the text with the public key of the loaded certificate.
		printSectionHeader(cout, "Encrypting String with Public Key");
		
		if(!vm.count("priv-key")) {
			cout << "No priv key specified... (Error: default should be used.)\n";
			return 1;
		}
		
		msg = "Our names are Jeremy Wright and Aaron Gibson. We are enrolled in CSE 539.";
		
		cout << "Original Text: " << msg << "\n";
		
		std::string encrypted = cert.encrypt_message(msg);
		cout << "Encrypted Text: " << encrypted << "\n";
		
		std::stringstream ss;
		ss << encrypted;
		
		private_key pvt(vm["priv-key"].as<string>());
		std::string decrypted = pvt.decrypt(ss);
		
		cout << "Decrypted Text: " << decrypted << "\n";
		
		return 0;
	} catch (const exception& e) {
		cerr << e.what() << "\n";
	} catch (...) {
		cerr << "Unknown Exception!\n";
	}
	return 3;
}

