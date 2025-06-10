# Create a private key for the root CA
openssl genpkey -algorithm RSA -out root_ca.key -pkeyopt rsa_keygen_bits:2048

# Create a self-signed root CA certificate (100 years validity)
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 36525 -out root_ca.crt -subj "/C=US/ST=State/L=City/O=tlsnotary/OU=IT/CN=tlsnotary.org"

# Create a private key for the end entity certificate
openssl genpkey -algorithm RSA -out test_server.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for the end entity certificate
openssl req -new -key test_server.key -out test_server.csr -subj "/C=US/ST=State/L=City/O=tlsnotary/OU=IT/CN=test-server.io"

# Sign the CSR with the root CA to create the end entity certificate (100 years validity)
openssl x509 -req -in test_server.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out test_server.crt -days 36525 -sha256 -extfile openssl.cnf -extensions v3_req

# Convert the root CA certificate to DER format
openssl x509 -in root_ca.crt -outform der -out root_ca_cert.der

# Convert the end entity certificate to DER format
openssl x509 -in test_server.crt -outform der -out test_server_cert.der

# Convert the end entity certificate private key to DER format
openssl pkcs8 -topk8 -inform PEM -outform DER -in test_server.key -out test_server_private_key.der -nocrypt

# ------------------------CLIENT AUTHENTICATION-------------------------

# Create a private key for the client certificate in PEM format
openssl genpkey -algorithm RSA -out client_cert.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for the client certificate
openssl req -new -key client_cert.key -out client_cert.csr -subj "/C=US/ST=State/L=City/O=tlsnotary/OU=IT/CN=client-authentication.io"

# Sign the CSR with the root CA to create the end entity certificate (100 years validity)
openssl x509 -req -in client_cert.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out client_cert.crt -days 36525 -sha256 -extfile openssl.cnf -extensions v3_req

# Convert the end entity certificate to PEM format
openssl x509 -in client_cert.crt -outform pem -out client_cert.pem
