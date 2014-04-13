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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>

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
		vector<string> certsToVerify;
			string privKeyfile;
		
		po::options_description desc("Configuration Options");
		desc.add_options()
			("help,h,?", "Display help")
			("root-ca,r", po::value<string>()->default_value(rootCAfile),
			"Set the root CA certificate to use in verification.")
			("priv-key,p", po::value<string>()->default_value(privKeyfile),
				"Set the private key for the given certificate.")
			("cert", po::value<vector<string>>(),
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
		
		certsToVerify = vm["cert"].as< vector< string > >();
		vector< string >::const_iterator itr, end;
		for(itr = certsToVerify.begin(), end = certsToVerify.end(); itr != end; ++itr) {
			//=========================================
			// Print Certificate
			printSectionHeader(cout, "Printing Certificate at: " + *itr);
			X509Certificate cert(*itr);	
			cout << cert << "\n";
			//=========================================
			// Verify Certificate
			printSectionHeader(cout, "Verifying Certificate at: " + *itr);
			string msg;
			if(!store.verifyCertificate(cert, msg)) {
				cout << "Verification failed: " << msg << "\n";
			} else {
				cout << "Verification successful.\n";
				continue;
			}
			//=========================================
			// Re-verify Certificate with older date.
			ptime oldDate(boost::gregorian::date(2006, boost::gregorian::Apr, 1), hours(1));

			cout << "Trying verification again with an older date: "<<
				to_simple_string(oldDate) << "\n";
			if(!store.verifyCertificateAtTime(cert, msg, oldDate, 0)) {
				cout << "Verification failed: " << msg << "\n";
			} else {
				cout << "Verification successful.\n";
				continue;
			}
		}
		return 0;
	} catch (const exception& e) {
		cerr << e.what() << "\n";
	} catch (...) {
		cerr << "Unknown Exception!\n";
	}
	return 3;
}

