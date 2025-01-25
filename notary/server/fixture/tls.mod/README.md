# Create a private key for the root CA
openssl genpkey -algorithm RSA -out rootCA.key -pkeyopt rsa_keygen_bits:2048

# Create a self-signed root CA certificate (100 years validity)
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 36525 -out rootCA.crt -subj "/C=US/ST=State/L=City/O=tlsnotary/OU=IT/CN=tlsnotary.org"

# Create a private key for the end entity certificate
openssl genpkey -algorithm RSA -out notary.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for the end entity certificate
openssl req -new -key notary.key -out notary.csr -subj "/C=US/ST=State/L=City/O=tlsnotary/OU=IT/CN=tlsnotaryserver.io"

# Sign the CSR with the root CA to create the end entity certificate (100 years validity)
openssl x509 -req -in notary.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out notary.crt -days 36525 -sha256 -extfile openssl.cnf -extensions v3_req
