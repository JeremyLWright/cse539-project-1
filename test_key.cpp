#include "PublicKey.hpp"
#include <iostream>
#include <string>



int main(int argc, const char *argv[])
{
    
    public_key pk = public_key(std::string(argv[1]));
    std::string msg("Our names are Jeremy Wright and Aaron Gibson. We are enrolled in CSE 539.");
    std::string emsg = pk.encrypt(msg);
    std::cout << emsg << '\n';

    return 0;
}
