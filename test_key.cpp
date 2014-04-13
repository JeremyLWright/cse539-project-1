#include "PublicKey.hpp"
#include "PrivateKey.hpp"
#include <iostream>
#include <string>
#include <sstream>



int main(int argc, const char *argv[])
{
    
    public_key pk = public_key(std::string(argv[1]));
    std::string msg("Our names are Jeremy Wright and Aaron Gibson. We are enrolled in CSE 539.");
    
    std::cout << "Cleartext Data:\n" << msg << '\n';
    std::string emsg = pk.encrypt(msg);

    std::cout << "Encrypted Data: \n" << emsg << '\n';
    std::stringstream ss;
    ss << emsg;

    private_key pvt = private_key(std::string(argv[2]));
    msg = pvt.decrypt(ss);
    std::cout << "Decrypted Data: \n" << msg << '\n';

    

    return 0;
}
