openssl pkcs12 -in Raghupri.pfx -nocerts -nodes -passin pass:raghu | openssl rsa -out private_key.pem
openssl rsa -in private_key.pem -pubout > public_key.pem
