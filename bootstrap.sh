#!/bin/bash
mkdir build
cd build
cmake ..
make
./test_encrypt ../certificate/public_key.pem ../certificate/private_key.pem
