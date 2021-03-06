#!/bin/bash
sudo apt-get install cmake make g++ gcc libboost-dev libssl-dev libboost-program-options-dev libboost-date-time-dev
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
echo -en '\e[92m'
#"\033[1mE\033[0m"   # Blue
echo "####################################"
echo "## Aaron Gibson, and Jeremy Wright #"
echo "##         CSE 539 Project 1       #"
echo "####################################"
./proj1 -r ../certificate/Trustcenter.cer -p ../certificate/private_key.pem --cert ../certificate/Raghupub.cer
echo "###############"
echo "## Completed ##"
echo "###############"
tput sgr0                               # Reset colors to "normal."

