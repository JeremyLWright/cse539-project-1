#!/bin/bash
sudo apt-get install cmake make g++ gcc libboost-dev libssl-dev libboost-program-options-dev libboost-datetime-dev
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
./test_encrypt ../certificate/public_key.pem ../certificate/private_key.pem
